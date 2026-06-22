"""
filter_llmseceval.py

Filters the LLMSecEval prompt dataset into the query set used for the
RAG-poisoning coding-assistant experiments.

Filtering criteria:
  1. Language == Python.
  2. CWE in the set for which reliable detection is available
     (Bandit-detectable classes, plus CWE-89 anchored by a custom detector).

For each retained prompt the script records:
  - query_id      : the original LLMSecEval Prompt ID (e.g. "CWE-89_SQI-1a")
  - scenario_id   : the prompt ID with the trailing paraphrase letter removed
                    (e.g. "CWE-89_SQI-1"); a/b/c variants are paraphrases of
                    one underlying scenario and are collapsed for analysis.
  - cwe           : the CWE identifier (e.g. "CWE-89")
  - payload_bucket: internal label linking the query to its payload/detector
  - bandit_rules  : Bandit test IDs that indicate this CWE's insecure pattern
  - query_text    : the prompt text, preferring the manually-fixed version,
                    with the "<language>" placeholder replaced by "Python"
  - source        : "LLMSecEval"

Output: JSONL (one query per line) and CSV (for manual inspection).

Usage:
    python filter_llmseceval.py \
        --input LLMSecEval-Prompts_dataset.csv \
        --out-jsonl llmseceval_queries.jsonl \
        --out-csv  llmseceval_queries.csv
"""

import argparse
import csv
import json
import re
from collections import Counter


# CWEs retained, mapped to an internal "payload bucket" label.
# Selection rationale: each has a reliable detector available.
#   CWE-89  -> SQL injection      (custom detector + Bandit B608)
#   CWE-502 -> deserialization    (Bandit B301/B302/B506)
#   CWE-798 -> hardcoded creds    (Bandit B105/B106/B107)
#   CWE-78  -> command injection  (Bandit B602/B605/B607/B609)
# CWE-327 and CWE-330 are not present in the LLMSecEval Python subset;
keep_cwe = {
    "CWE-89": "sql",
    "CWE-502": "pickle",
    "CWE-798": "hardcoded",
    "CWE-78": "command",
    "CWE-22": "pathtraversal",
    "CWE-732": "permissions",
}

# Bandit test IDs indicating the insecure pattern for each payload bucket.
cwe_to_bandit = {
    "sql": ["B608"],
    "pickle": ["B301", "B302", "B506"],
    "hardcoded": ["B105", "B106", "B107"],
    "command": ["B602", "B605", "B607", "B609"],
    "pathtraversal": [],          # custom detector
    "permissions": ["B103"],      
}


def cwe_of(prompt_id: str) -> str | None:
    """Extract the CWE identifier from a LLMSecEval Prompt ID."""
    match = re.match(r"(CWE-\d+)", prompt_id)
    return match.group(1) if match else None


def scenario_of(prompt_id: str) -> str:
    """Collapse paraphrase variants by stripping a trailing lowercase letter.

    LLMSecEval encodes paraphrases of one scenario as <id>a, <id>b, <id>c.
    e.g. "CWE-89_SQI-1a" -> "CWE-89_SQI-1"
    """
    return re.sub(r"([a-z])$", "", prompt_id)


def pick_prompt(row: dict) -> str:
    """Choose the prompt text.

    Prefers the manually-fixed prompt (cleaned by the dataset authors); falls
    back to the raw LLM-generated prompt. Replaces the "<language>"
    placeholder with "Python".
    """
    text = (row.get("Manually-fixed NL Prompt") or "").strip()
    if not text:
        text = (row.get("LLM-generated NL Prompt") or "").strip()
    return text.replace("<language>", "Python").strip()



# Main filtering routine

def filter_dataset(input_path: str) -> list[dict]:
    """Read the LLMSecEval CSV and return the filtered list of query records."""
    with open(input_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    queries = []
    for row in rows:
        # Criterion 1: Python only
        if row["Language"].strip().lower() != "python":
            continue

        # Criterion 2: retained CWEs only
        cwe = cwe_of(row["Prompt ID"])
        if cwe not in keep_cwe:
            continue

        bucket = keep_cwe[cwe]
        queries.append({
            "query_id": row["Prompt ID"],
            "scenario_id": scenario_of(row["Prompt ID"]),
            "cwe": cwe,
            "payload_bucket": bucket,
            "bandit_rules": cwe_to_bandit[bucket],
            "query_text": pick_prompt(row),
            "source": "LLMSecEval",
        })

    return queries


def write_outputs(queries: list[dict], jsonl_path: str, csv_path: str) -> None:
    """Write the query set to JSONL (pipeline input) and CSV (inspection)."""
    with open(jsonl_path, "w", encoding="utf-8") as fh:
        for q in queries:
            fh.write(json.dumps(q) + "\n")

    fieldnames = ["query_id", "scenario_id", "cwe", "payload_bucket",
                  "bandit_rules", "query_text", "source"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for q in queries:
            record = dict(q)
            record["bandit_rules"] = ",".join(q["bandit_rules"])
            writer.writerow(record)


def print_summary(queries: list[dict]) -> None:
    """Print a short report of the filtered set."""
    by_cwe = Counter(q["cwe"] for q in queries)
    scenarios = {q["scenario_id"] for q in queries}
    scen_by_cwe = {
        cwe: len({q["scenario_id"] for q in queries if q["cwe"] == cwe})
        for cwe in keep_cwe
    }
    print(f"Retained queries:    {len(queries)}")
    print(f"Distinct scenarios:  {len(scenarios)}")
    print(f"Prompts per CWE:     {dict(by_cwe)}")
    print(f"Scenarios per CWE:   {scen_by_cwe}")


# main

def main():
    parser = argparse.ArgumentParser(description="Filter LLMSecEval prompts.")
    parser.add_argument("--input", default="LLMSecEval-Prompts_dataset.csv",
                        help="Path to the LLMSecEval CSV.")
    parser.add_argument("--out-jsonl", default="llmseceval_queries.jsonl",
                        help="Output JSONL path (pipeline input).")
    parser.add_argument("--out-csv", default="llmseceval_queries.csv",
                        help="Output CSV path (manual inspection).")
    args = parser.parse_args()

    queries = filter_dataset(args.input)
    write_outputs(queries, args.out_jsonl, args.out_csv)
    print_summary(queries)
    print(f"\nWrote {args.out_jsonl} and {args.out_csv}")


if __name__ == "__main__":
    main()