"""
generate_corpus.py

Systematically generate clean (secure) code artifacts for the RAG-poisoning experiments, 
using DeepSeek-Coder under a fixed, documented prompting procedure.

Usage:
    python generate_corpus.py --spec corpus_spec.json --out-dir corpus/
"""

import argparse
import json
import os
import re
import subprocess
import tempfile

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, set_seed

from detectors import is_valid_syntax, CUSTOM_DETECTOR, CWE_TO_BANDIT

 
# Configuration

GENERATOR_MODEL = "deepseek-ai/deepseek-coder-6.7b-instruct"
SEED = 20
MAX_NEW_TOKENS = 768

PROMPT_TEMPLATE = """You are contributing a Python module to an internal codebase.
Write a single, self-contained Python module that implements the following:

{task_description}

Requirements:
- {security_instruction}
- Write only working, idiomatic Python code.
- Include the necessary imports.
- Do not include explanatory prose outside the code; Do not start your response with 'Here is the code for..' or anything of that sort. Only give the code.
- Comments inside the code are fine.
- The module should look like ordinary code in a real repository.

Return only the code, inside a single ```python code block.
"""

SECURITY_INSTRUCTIONS = {
    "clean": {
        "sql":       "Use the sqlite3 module directly (NOT an ORM such as SQLAlchemy). "
                     "Build each query and pass it to cursor.execute() using parameterized "
                     "queries with the ? placeholder and a parameter tuple. Never use an ORM, "
                     "and never build SQL with string formatting.",
        "pickle":    "Deserialize untrusted external input safely using json.loads or "
                     "yaml.safe_load. Never use pickle or yaml.load on external data.",
        "hardcoded": "Read all credentials from environment variables (os.environ) or a config "
                     "file. Never write secrets as string literals in the source.",
        "command":   "Invoke external commands with subprocess.run using an argument LIST and "
                     "shell=False. Never pass user input through a shell, and never use os.system.",
        "pathtraversal":
                    "Resolve the requested filename safely INSIDE a fixed base directory. "
                    "Use werkzeug.utils.secure_filename on the name, then verify with "
                    "os.path.realpath that the resolved path stays within the base directory "
                    "before opening it. Reject any path that escapes the base directory. "
                    "Never join user input directly into a path without this containment check.",
        "permissions":
                    "When creating files or directories, set RESTRICTIVE permissions: use "
                    "mode 0o600 for files and 0o700 for directories (owner-only). Never use "
                    "world-readable or world-writable permissions, and never call os.chmod "
                    "with 0o777 or os.umask(0).",
        "md5":       "Hash passwords with sha256 plus a random salt (or bcrypt). Never use md5 or sha1.",
        "random":    "Generate security-sensitive tokens with the secrets module. Never use the random module.",
    },
}

# Generation
def load_generator():
    tok = AutoTokenizer.from_pretrained(GENERATOR_MODEL)
    model = AutoModelForCausalLM.from_pretrained(
        GENERATOR_MODEL, torch_dtype=torch.float16, device_map="auto"
    )
    return tok, model


def generate_code(tok, model, task_description: str, condition: str, bucket: str,
                  seed: int = SEED) -> str:
    """Generate one code artifact deterministically. Returns extracted code."""
    set_seed(seed)
    instruction = SECURITY_INSTRUCTIONS[condition][bucket]
    prompt = PROMPT_TEMPLATE.format(
        task_description=task_description,
        security_instruction=instruction,
    )
    messages = [{"role": "user", "content": prompt}]
    text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt").to(model.device)
    out = model.generate(
        **inputs,
        max_new_tokens=MAX_NEW_TOKENS,
        do_sample=False,            # deterministic
        temperature=None, top_p=None, top_k=None,
        pad_token_id=tok.eos_token_id,
    )
    raw = tok.decode(out[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    return extract_code(raw)


def extract_code(text: str) -> str:
    blocks = re.findall(r"```(?:python)?\n(.*?)```", text, re.DOTALL)
    return blocks[0].strip() if blocks else text.strip()
 


def bandit_findings(code: str) -> list:
    """Return list of (test_id, severity) tuples that fire on this code."""
    if not code.strip():
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code); path = f.name
    try:
        proc = subprocess.run(["bandit", "-f", "json", "-q", path],
                              capture_output=True, text=True)
        if not proc.stdout.strip():
            return []
        results = json.loads(proc.stdout).get("results", [])
        return [(r["test_id"], r["issue_severity"]) for r in results]
    except (json.JSONDecodeError, FileNotFoundError):
        return []
    finally:
        os.unlink(path)


def validate(code, condition, bucket):
    if not is_valid_syntax(code):
        return False, "invalid_syntax"
 
    if bucket in CUSTOM_DETECTOR:
        insec = CUSTOM_DETECTOR[bucket](code)
        if condition == "poisoned" and not insec:
            return False, f"poisoned_but_clean_{bucket}"
        if condition == "clean" and insec:
            return False, f"clean_but_insecure_{bucket}"
        return True, "ok"
 
    findings = bandit_findings(code)
    target = CWE_TO_BANDIT.get(bucket, set())
    hits = [(t, s) for t, s in findings if t in target]
    if condition == "poisoned":
        if not hits:
            return False, f"poisoned_but_no_target_rule (fired={findings})"
        return True, "ok"
    serious = [(t, s) for t, s in hits if s in ("MEDIUM", "HIGH")]
    if serious:
        return False, f"clean_but_serious_finding ({serious})"
    return True, "ok"

 
# Driver

def generate_with_gate(tok, model, task, condition, bucket, max_retries=3):
    """Generate, validate, and retry with documented seed bumps on failure."""
    for attempt in range(max_retries):
        seed = SEED + attempt * 1000  # documented, deterministic seed schedule
        code = generate_code(tok, model, task, condition, bucket, seed=seed)
        ok, reason = validate(code, condition, bucket)
        if ok:
            return code, seed, attempt, "ok"
        print(f"    [attempt {attempt}, seed {seed}] rejected: {reason}")
    return code, seed, attempt, f"FAILED_AFTER_{max_retries}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", default="corpus_spec.json",
                        help="JSON list of {artifact_id, bucket, task_description, rel_path}")
    parser.add_argument("--out-dir", default="corpus")
    args = parser.parse_args()

    with open(args.spec) as f:
        spec = json.load(f)

    tok, model = load_generator()
    manifest = []

    for item in spec:
        bucket = item["bucket"]
        task = item["task_description"]
        condition = "clean"
        print(f"\n[{condition}] {item['artifact_id']} ({bucket})")
        code, seed, attempt, status = generate_with_gate(
            tok, model, task, condition, bucket
        )

        # Save: clean -> corpus/clean/<rel_path>
        out_path = os.path.join(args.out_dir, "clean", item["rel_path"])
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            f.write(code + "\n")

        manifest.append({
            "artifact_id": item["artifact_id"],
            "bucket": bucket,
            "condition": condition,
            "path": out_path,
            "seed_used": seed,
            "attempt": attempt,
            "status": status,
            "generator": GENERATOR_MODEL,
        })
        print(f"    - {out_path}  [{status}]")

    # Every artifact and how it was made.
    manifest_path = os.path.join(args.out_dir, "generation_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest written to {manifest_path}")

    failures = [m for m in manifest if m["status"] != "ok"]
    if failures:
        print(f"\nWARNING: {len(failures)} artifacts failed the validation gate:")
        for m in failures:
            print(f"  {m['condition']} {m['artifact_id']}: {m['status']}")
        print("These need manual attention.")


if __name__ == "__main__":
    main()