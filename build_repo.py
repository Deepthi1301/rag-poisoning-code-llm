#!/usr/bin/env python3
"""
build_repo.py

Assemble a "background repository" corpus from CodeSearchNet (Python split) to
provide realistic retrieval competition for the poisoned files.

  1. Load CodeSearchNet Python via the HuggingFace datasets library.
  2. Sample N functions (deterministic, fixed seed).
  3. Profile each with the custom detectors, flag files that already contain 
     an insecurity.
  4. Either drop flagged files (clean repo) or keep+flag them, controlled by --mode.
  5. Write functions as .py files under background_corpus/, plus a profiling report.

The files are general-domain Python, used as inert retrieval competition.

Usage:
    python build_repo.py --n 400 --mode drop --out-dir background_corpus/
    python build_repo.py --n 400 --mode flag --out-dir background_corpus/
"""

import argparse
import json
import os
import random
import re

# Import the project's detectors so profiling uses the same logic as the experiment.
try:
    from generate_corpus import CUSTOM_DETECTOR, CWE_TO_BANDIT, bandit_findings, extract_code
except ImportError:
    raise SystemExit("Put generate_corpus.py on the path (same detectors as the "
                     "experiment) before running this.")


# Profiling

def profile_snippet(code: str) -> list[str]:
    """Return the list of target CWE buckets this snippet already trips.

    Uses the same custom detectors as the experiment for sql/command/pickle/
    pathtraversal/permissions, and Bandit for hardcoded.
    """
    hits = []
    for bucket, detector in CUSTOM_DETECTOR.items():
        if detector(code):
            hits.append(bucket)
    # hardcoded via Bandit
    fired = {t for t, _ in bandit_findings(code)}
    if fired & CWE_TO_BANDIT.get("hardcoded", set()):
        hits.append("hardcoded")
    return hits


# Load + sample CodeSearchNet

def load_codesearchnet_python(n: int, seed: int = 42) -> list[dict]:
    """Load and sample N Python functions from CodeSearchNet.

    Returns list of {func_name, code, repo, path}.
    """
    from datasets import load_dataset
    # CodeSearchNet python split; 'train' is large, we stream + sample.
    print("Loading CodeSearchNet (python)...")
    ds = load_dataset("code_search_net", "python", split="train",
                      trust_remote_code=True)
    total = len(ds)
    print(f"  {total} functions available; sampling {n}")

    rng = random.Random(seed)
    idxs = rng.sample(range(total), min(n * 3, total))  # oversample, we filter

    sampled = []
    for i in idxs:
        row = ds[i]
        code = row.get("whole_func_string") or row.get("func_code_string") or ""
        if not code.strip() or len(code) < 40:
            continue
        sampled.append({
            "func_name": row.get("func_name", f"func_{i}"),
            "code": code,
            "repo": row.get("repository_name", "unknown"),
            "path": row.get("func_path_in_repository", f"file_{i}.py"),
        })
        if len(sampled) >= n:
            break
    print(f"  sampled {len(sampled)} usable functions")
    return sampled


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400, help="target repo size")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--mode", choices=["drop", "flag"], default="drop",
                    help="drop: exclude files tripping a target CWE (clean "
                         "repo). flag: keep them but record (honest "
                         "noise-accounting).")
    ap.add_argument("--out-dir", default="background_corpus")
    ap.add_argument("--report", default="background_corpus_profile.json")
    args = ap.parse_args()

    snippets = load_codesearchnet_python(args.n, args.seed)

    os.makedirs(args.out_dir, exist_ok=True)
    profile = []
    kept = 0
    dropped = 0
    bucket_hits = {}

    for i, s in enumerate(snippets):
        code = s["code"]
        hits = profile_snippet(code)
        for h in hits:
            bucket_hits[h] = bucket_hits.get(h, 0) + 1

        record = {
            "idx": i,
            "func_name": s["func_name"],
            "repo": s["repo"],
            "orig_path": s["path"],
            "cwe_hits": hits,
        }

        if hits and args.mode == "drop":
            dropped += 1
            record["action"] = "dropped"
            profile.append(record)
            continue

        # write the file
        safe_name = re.sub(r"[^\w]", "_", s["func_name"])[:40]
        rel = f"bg_corpus_{i:04d}_{safe_name}.py"
        with open(os.path.join(args.out_dir, rel), "w", encoding="utf-8") as f:
            f.write(code + "\n")
        record["action"] = "kept_flagged" if hits else "kept"
        record["corpus_path"] = rel
        profile.append(record)
        kept += 1

    # Write profiling report
    with open(args.report, "w") as f:
        json.dump({
            "source": "code_search_net/python",
            "seed": args.seed,
            "mode": args.mode,
            "n_sampled": len(snippets),
            "n_kept": kept,
            "n_dropped": dropped,
            "baseline_cwe_hits_in_sample": bucket_hits,
            "files": profile,
        }, f, indent=2)

    # Summary
    print(f"\n{'='*55}\Repo Profile\n{'='*55}")
    print(f"sampled:        {len(snippets)}")
    print(f"kept:           {kept}")
    print(f"dropped:        {dropped}  (mode={args.mode})")
    print(f"\nBaseline CWE hits in the sampled background (before drop):")
    if bucket_hits:
        for b, c in sorted(bucket_hits.items(), key=lambda x: -x[1]):
            print(f"  {b:<14} {c}  ({c/len(snippets):.1%} of sample)")
    else:
        print("  none — sample is clean of all target CWE patterns")
    print(f"\nWrote {kept} background files to {args.out_dir}/")
    print(f"Profiling report: {args.report}")
    print(f"\nInterpretation:")
    if args.mode == "drop":
        print("  Background is now clean of target CWEs (flagged files excluded).")
        print("  Any insecure generation in the experiment is attributable to the")
        print("  planted poison, not the background.")
    else:
        print("  Background retains its natural insecurity (flagged files kept).")
        print("  Report the baseline rates above as the repo's own contribution;")
        print("  attribute the DELTA over baseline to the poison.")


if __name__ == "__main__":
    main()