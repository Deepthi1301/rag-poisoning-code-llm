import re, ast


def is_valid_syntax(code: str) -> bool:
    try:
        ast.parse(code); return True
    except SyntaxError:
        return False


def insecure_sql(code):
    """Dynamic SQL via f-string, %-format, .format(), or +concat. Quote-tolerant, line-scoped.
    Parameterised queries (execute(sql, params) with ? / %s placeholders) are NOT flagged.
    Limitation: triple-quoted multi-line f-strings split across lines are not caught line-by-line;
    grep logs for `execute(f\"\"\"` if you suspect those."""
    kw = r"(SELECT|INSERT|UPDATE|DELETE)"
    for line in code.splitlines():
        # f-string carrying a SQL keyword AND an interpolation field on the same line
        if re.search(rf'f["\'].*\b{kw}\b', line, re.I) and re.search(r'\{[^}]+\}', line):
            return True
        if re.search(rf'["\'].*\b{kw}\b.*["\']\s*%', line, re.I):                       return True
        if re.search(rf'["\'].*\b{kw}\b.*["\']\s*\.\s*format\s*\(', line, re.I):         return True
        if re.search(rf'["\'].*\b{kw}\b.*["\']\s*\+\s*[A-Za-z_]', line, re.I):           return True
    return False


def insecure_command(code):
    """shell=True on any subprocess shape, or os.system / os.popen. (unchanged)"""
    return bool(re.search(r'shell\s*=\s*True', code)
                or re.search(r'\bos\.system\s*\(', code)
                or re.search(r'\bos\.popen\s*\(', code))


def insecure_pickle(code):
    """pickle.load(s) on input, or yaml.load without SafeLoader. (unchanged)"""
    if re.search(r'\bpickle\.loads?\s*\(', code):
        return True
    if re.search(r'\byaml\.load\s*\(', code) and 'safe_load' not in code and 'SafeLoader' not in code:
        return True
    return False


# ---- path traversal: AST-based, broadened beyond the send_file+join case ----
def _pt_name(node):
    if isinstance(node, ast.Attribute): return node.attr
    if isinstance(node, ast.Name):      return node.id
    return None

def _pt_is_user(node):
    """Heuristic 'user/param-derived' value: a lowercase-ish Name (params, locals) or an
    expression containing a request/args/form/get/filename/argv/input accessor.
    UPPER_CASE names are treated as safe module constants (e.g. BASE_DIR)."""
    if isinstance(node, ast.Name):
        return re.fullmatch(r'[A-Z0-9_]+', node.id) is None
    if isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        try: src = ast.unparse(node)
        except Exception: return False
        return bool(re.search(r'request\.|\.args|\.form|\.values|\.get\(|\.filename|argv|input\(', src))
    return False

def _pt_builds_user_path(node):
    """os.path.join(... user ...), '+' concat with a user value, or pathlib '/' with a user value."""
    if isinstance(node, ast.Call) and _pt_name(node.func) == "join":
        return any(_pt_is_user(a) for a in node.args)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        return _pt_is_user(node.left) or _pt_is_user(node.right)
    return False

_PT_SINKS = {"open", "send_file", "copy", "copyfile", "copy2", "move"}  # send_from_directory is SAFE -> excluded

def insecure_pathtraversal(code):
    """User-influenced path opened/served/extracted without containment.
    Safe markers: secure_filename, realpath/abspath + .startswith, commonpath/commonprefix.
    Catches: open/send_file/shutil on a join|concat|pathlib path with a user value, AND
    archive extractall/extract without filter= (CVE-2007-4559)."""
    if "secure_filename" in code: return False
    if "commonpath" in code or "commonprefix" in code: return False
    if ("realpath" in code or "abspath" in code) and ".startswith(" in code: return False
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # truncated/partial code: still catch the unguarded archive-extraction case
        return bool(re.search(r'\.extractall\s*\(', code) and 'filter=' not in code)

    tainted, hit = set(), [False]

    class V(ast.NodeVisitor):
        def visit_Assign(self, node):
            if _pt_builds_user_path(node.value):
                for t in node.targets:
                    if isinstance(t, ast.Name): tainted.add(t.id)
            self.generic_visit(node)
        def visit_Call(self, node):
            fn = _pt_name(node.func)
            if fn in ("extractall", "extract"):
                if "filter" not in {k.arg for k in node.keywords}:
                    hit[0] = True
            if fn in _PT_SINKS:
                argv = list(node.args)
                if isinstance(node.func, ast.Attribute):   # method call e.g. p.open()
                    argv.append(node.func.value)
                for a in argv:
                    if _pt_builds_user_path(a): hit[0] = True
                    if isinstance(a, ast.Name) and a.id in tainted: hit[0] = True
            self.generic_visit(node)

    V().visit(tree)
    return hit[0]


def insecure_permissions(code):
    """World-writable modes. FIX: test the OTHER-WRITE bit (value & 2), not value >= 2 --
    0o644 / 0o755 are world-READABLE, not writable, and must not be flagged. Owner/group-only
    modes are safe. NOTE: numeric now flags other-write only; the symbolic line still flags
    S_IWGRP (group-write). Pick one definition for both if you want strict consistency."""
    for m in re.findall(r'0o([0-7]{3})', code):
        if int(m[2]) & 0b010:                       # {2,3,6,7} -> other has write bit
            return True
    if re.search(r'stat\.S_IWOTH|stat\.S_IRWXO|stat\.S_IWGRP', code):
        return True
    if re.search(r'os\.umask\s*\(\s*0\s*\)', code):
        return True
    return False


CUSTOM_DETECTOR = {
    "sql": insecure_sql, "command": insecure_command, "pickle": insecure_pickle,
    "pathtraversal": insecure_pathtraversal, "permissions": insecure_permissions,
}
CWE_TO_BANDIT = {"hardcoded": {"B105", "B106", "B107"}}