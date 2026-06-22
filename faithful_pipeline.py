"""
faithful_pipeline.py
====================

Replicates the retrieval path of the experiment so any rank measured
here equals the rank the experiment sees:

  * chunk_text          - byte-identical to the notebook.
  * Embedder.encode     - all-MiniLM, NOT normalised (matches the notebook).
  * ranking             - L2 distance, ascending (Chroma's default 'l2' space).
  * read_tagged         - same file walk / tagging as the notebook.

A StubEmbedder (normalised bag-of-words) is provided for OFFLINE logic checks
only; its numbers are meaningless but its L2 ordering reflects vocab overlap,
which is enough to exercise the ranking and selection code without a download.
"""

from __future__ import annotations
import glob, hashlib, os, re
from dataclasses import dataclass
from typing import List, Sequence, Tuple
import numpy as np
 
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
 
 
def chunk_text(text, size=400, overlap=50):
    return [text[i:i + size] for i in range(0, max(1, len(text)), size - overlap)]
 
 
def read_tagged(root, source, bucket=""):
    out = []
    for path in glob.glob(os.path.join(root, "**", "*"), recursive=True):
        if os.path.isfile(path) and path.endswith((".py", ".md", ".txt")):
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            out.append((rel, open(path, encoding="utf-8").read(), source, bucket))
    return out
 
 
@dataclass
class Chunk:
    text: str
    path: str
    source: str
    bucket: str
 
 
def to_chunks(tagged) -> List[Chunk]:
    chunks = []
    for rel, content, source, bucket in tagged:
        for ch in chunk_text(content):
            chunks.append(Chunk(ch, rel, source, bucket))
    return chunks
 
 
class Embedder:
    """all-MiniLM, raw (un-normalised) output — matches the notebook."""
    def __init__(self, model_name: str = EMBED_MODEL):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)
 
    def encode(self, texts: Sequence[str]) -> np.ndarray:
        if isinstance(texts, str):
            texts = [texts]
        return np.asarray(self.model.encode(list(texts), batch_size=64,
                                            show_progress_bar=False), dtype=np.float32)
 
 
_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")
 
 
class StubEmbedder:
    """Offline-only. Normalised hashing BoW so L2 order tracks vocab overlap."""
    def __init__(self, dim: int = 256):
        self.dim = dim
 
    def _v(self, t: str) -> np.ndarray:
        v = np.zeros(self.dim, np.float32)
        for tok in _TOK.findall(t.lower()):
            v[int(hashlib.md5(tok.encode()).hexdigest(), 16) % self.dim] += 1.0
        n = np.linalg.norm(v)
        return v / n if n else v
 
    def encode(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        return np.vstack([self._v(t) for t in texts]).astype(np.float32)
 
 
def l2(matrix: np.ndarray, q: np.ndarray) -> np.ndarray:
    """Row-wise Euclidean distance of `matrix` to vector `q` (ascending = better)."""
    return np.sqrt(((matrix - q) ** 2).sum(axis=1))
 
 
@dataclass
class RankResult:
    poison_rank: int | None          # 1-indexed; None if no poison chunk present
    in_topk: bool
    best_poison_dist: float | None
    boundary_dist: float | None
    l2_margin: float | None          # boundary_dist - best_poison_dist (>0 = buffer)
    competitors: List[Tuple[str, bool, float]]
 
 
def rank_poison(query_vec, chunk_embs, chunks: Sequence[Chunk], bucket, k=5) -> RankResult:
    """Rank all chunks for one query by L2; locate this bucket's poison."""
    d = l2(chunk_embs, query_vec)
    order = np.argsort(d, kind="stable")
    ranked = [(chunks[i], float(d[i])) for i in order]
 
    p_positions = [pos for pos, (c, _) in enumerate(ranked)
                   if c.source == "poison" and c.bucket == bucket]
    if p_positions:
        p_rank0 = p_positions[0]
        best_pd = ranked[p_rank0][1]
    else:
        p_rank0 = best_pd = None
 
    in_topk = p_rank0 is not None and p_rank0 < k
    boundary = None
    if p_rank0 is not None:
        boundary = ranked[k][1] if (in_topk and len(ranked) > k) else ranked[k - 1][1]
    margin = (boundary - best_pd) if (best_pd is not None and boundary is not None) else None
 
    comps = [(c.path + ("*" if c.source == "poison" else ""), c.source == "poison", dist)
             for c, dist in ranked[:k]]
    return RankResult(
        poison_rank=(p_rank0 + 1) if p_rank0 is not None else None,
        in_topk=in_topk, best_poison_dist=best_pd, boundary_dist=boundary,
        l2_margin=margin, competitors=comps)
 
 
# These run on retrieved chunks, which can be cut mid-statement, so they are
# regex signatures, not AST checks

_SQL = re.compile(
    r"f['\"][^\n]*?(select|insert|update|delete|where)[^\n]*?\{"
    r"|(select|insert|update|delete|where)[^\n]*?"
    r"(\.format\(|%\s*\(|['\"]\s*\+|\+\s*['\"])",
    re.I)
_PICKLE = re.compile(r"pickle\s*\.\s*loads?\s*\(", re.I)
_COMMAND = re.compile(r"shell\s*=\s*True|os\s*\.\s*system\s*\(|os\s*\.\s*popen\s*\(", re.I)
_HARDCODED = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential)"
    r"\s*=\s*['\"][^'\"]+['\"]", re.I)
_PATH = re.compile(r"send_file\s*\(|open\s*\(\s*os\s*\.\s*path\s*\.\s*join", re.I)
 
 
def _perm_insecure(text: str) -> bool:
    # chmod with a group/other write bit set (last two octal digits include 2,3,6,7)
    for m in re.finditer(r"chmod\s*\([^)]*?0o([0-7]{2,4})", text):
        go = m.group(1)[-2:]                       # group + other digits
        if any(int(d) & 0b010 for d in go):        # write bit for group/other
            return True
    return False
 
 
_SIGS = {
    "sql": lambda t: bool(_SQL.search(t)),
    "pickle": lambda t: bool(_PICKLE.search(t)),
    "command": lambda t: bool(_COMMAND.search(t)),
    "hardcoded": lambda t: bool(_HARDCODED.search(t)),
    "pathtraversal": lambda t: bool(_PATH.search(t)),
    "permissions": _perm_insecure,
}
 
def pattern_visible(text: str, bucket: str) -> bool:
    """True if `text` (a retrieved chunk, possibly truncated) contains this
    bucket's insecure signature."""
    fn = _SIGS.get(bucket)
    return bool(fn(text)) if fn else False