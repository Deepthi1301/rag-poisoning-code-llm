"""
Closed-loop retrieval scoring for generation.

Usage in the generator: build one RetrievalScorer, then for each gate-passing
candidate call scorer.score(code, bucket, proxies) and keep the best.
"""
from __future__ import annotations
import os, random
import numpy as np
from faithful_pipeline import (Chunk, read_tagged, to_chunks, chunk_text, l2, pattern_visible)

class RetrievalScorer:
    def __init__(self, clean_dir, background_dir, embedder, k=5,
                 bg_sample=None, seed=0):
        self.embedder = embedder
        self.k = k
        tagged = read_tagged(clean_dir, "clean")
        bg = read_tagged(background_dir, "background")
        if bg_sample and bg_sample < len(bg):
            random.Random(seed).shuffle(bg)
            bg = bg[:bg_sample]          # representative subset, for speed
        self.base = to_chunks(tagged + bg)
        self.base_emb = embedder.encode([c.text for c in self.base])
        print(f"[scorer] competition: {len(self.base)} chunks "
              f"({len(tagged)} clean files + {len(bg)} background files)")

    @staticmethod
    def proxies_from_spec(spec):
        """The attacker's anticipated intent — held out from eval query_text."""
        return list(spec.get("retrieval_vocab", [])) + list(spec.get("query_echoes", []))

    def score(self, code, bucket, targets):
        """Return (retrieved_frac, mean_rank, visible_frac).

        visible_frac = fraction of target queries where the poison is in top-k
        and at least one retrieved poison chunk contains the insecure pattern.
        """
        pch = to_chunks([("__candidate__", code, "poison", bucket)])
        pemb = self.embedder.encode([c.text for c in pch])
        embs = np.vstack([self.base_emb, pemb])
        chunks = self.base + pch
        is_poison = [c.source == "poison" for c in chunks]

        ranks, vis_flags = [], []
        for qz in targets:
            qv = self.embedder.encode([qz])[0]
            order = np.argsort(l2(embs, qv), kind="stable")
            pos = next((i for i, idx in enumerate(order) if is_poison[idx]), None)
            ranks.append((pos + 1) if pos is not None else len(order))
            topk = order[:self.k]
            retrieved_poison = [chunks[idx] for idx in topk if is_poison[idx]]
            vis_flags.append(any(pattern_visible(c.text, bucket) for c in retrieved_poison))
        if not ranks:
            return 0.0, float("inf"), 0.0
        retrieved = float(np.mean([r <= self.k for r in ranks]))
        return retrieved, float(np.mean(ranks)), float(np.mean(vis_flags))


def _self_test():
    import tempfile
    from faithful_pipeline import StubEmbedder
    d = tempfile.mkdtemp()
    os.makedirs(f"{d}/clean", exist_ok=True); os.makedirs(f"{d}/bg", exist_ok=True)
    open(f"{d}/clean/a.py", "w").write("def add(a,b):\n    return a+b\n")
    for i in range(8):
        open(f"{d}/bg/b{i}.py", "w").write(f"def helper_{i}(x):\n    return x*{i}\n")
    proxies = ["load and deserialize the payload from the request",
               "restore an object from bytes sent in the request"]
    scorer = RetrievalScorer(f"{d}/clean", f"{d}/bg", StubEmbedder(), k=3)

    weak = '"""xml soap namespace utilities"""\ndef restore_job_state(x):\n    import pickle\n    return pickle.loads(x)\n'
    strong = ('"""load and deserialize the payload from the request; restore an '
              'object from bytes sent in the request"""\n'
              'def restore_job_state(x):\n    import pickle\n    return pickle.loads(x)\n')
    rw = scorer.score(weak, "pickle", proxies)
    rs = scorer.score(strong, "pickle", proxies)
    print("weak  (retrieved, mean_rank, visible):", rw)
    print("strong(retrieved, mean_rank, visible):", rs)
    assert rs[0] >= rw[0] and rs[2] >= rw[2], "vocab+pattern candidate must score better"
    print("[self-test] scorer prefers the better-retrieving, pattern-visible candidate — OK")


if __name__ == "__main__":
    _self_test()