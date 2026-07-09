# RAG Poisoning of Code LLMs

Measures whether poisoned files planted in a retrieval corpus can steer a 
retrieval-augmented code LLM into emitting insecure code. The experiment compares 
attack success rate (ASR) with the poison present (`poison_on`) against a clean 
baseline (`poison_off`) across multiple temperatures for 4 subject models.

## Requirements

- Python 3.10 or newer.

```bash
pip install torch transformers accelerate bitsandbytes chromadb \
    sentence-transformers numpy pandas matplotlib datasets bandit
```

## Quick start (run the experiment on the existing corpus)

The `corpus/` directory is already generated, so you only need to unpack the background
corpus and point the script at a model.

1. Unzip the background corpus:

   ```bash
   unzip background_corpus.zip
   ```

   This creates `background_corpus/`, which the experiment reads as retrieval
   competition.

2. Make sure the query set is present. The experiment reads `queries/llmseceval_queries.jsonl`.
Then choose the subject model, either by editing `DEFAULT_MODEL` near the top of
   `run_rag_poison.py`, or by passing `--model`. Accepted model Ids:

   - `Qwen/Qwen2.5-Coder-1.5B-Instruct`
   - `Qwen/Qwen2.5-Coder-7B-Instruct`
   - `google/codegemma-7b-it`
   - `codellama/CodeLlama-7b-Instruct-hf`

4. Run:

   ```bash
   python run_rag_poison.py [--model HF_ID]
   ```

### Outputs

| Path | Contents |
|---|---|
| `results/run_<ts>.jsonl` | Per-query log |
| `results/sweep_<ts>_<model>.jsonl` | Full temperature-sweep, one row per generation |
| `run_results/output_<ts>_<model>.txt` | captured console output (summary tables) |
| `run_results/asr_vs_temp_<ts>_<model>.png` | ASR given poison retrieved, vs temperature |
| `run_results/asr_delta_vs_<ts>_<model>.png` | ASR delta (on − off), vs temperature |

`<ts>` is the run timestamp and `<model>` is a short model tag.

## Rebuilding the corpus from scratch

To regenerate the background, clean, and poison layers that
the quick-start path uses. 

**1. Background corpus.** Sample general-domain Python functions from CodeSearchNet as
retrieval competition. `--mode drop` excludes files that already trip a target CWE
(clean background, so any insecurity in the experiment is attributable to the poison);
`--mode flag` keeps them:

```bash
python build_repo.py --n 400 --mode drop --out-dir background_corpus/
# OR
python build_repo.py --n 400 --mode flag --out-dir background_corpus/
```

**2. Clean files.** Generate the secure baseline modules under `corpus/clean/`. Each
generation must pass the detector gate (valid syntax and confirmed secure) before it is
accepted:

```bash
python generate_corpus.py --spec corpus_spec.json --out-dir corpus/
```

**3. Poison files.** Generate the poison modules under `corpus/poisoned/<bucket>/`.
Candidates are sampled, filtered through the same detector gate, then ranked by the
retrieval scorer; the best-retrieving, pattern-visible candidate is kept.
`--per-scenario` writes one poison file per query (each mirrors a single scenario), and
`--operation-policy matched` makes the poison mirror the queried task for stronger
retrieval:

```bash
python generate_poison_corpus.py --spec poison_corpus_spec.json --out corpus \
    --clean-dir corpus/clean --background-dir background_corpus --queries queries/queries.jsonl \
    --optimise-against queries --operation-policy matched --per-scenario --candidates 6 \
    --bg-sample 200 -k 5
```

After these three steps, follow the quick-start run command above.

## Supporting modules

- **`detectors.py`** — the ground-truth insecurity checks. It provides one detector per
  bucket (`insecure_sql`, `insecure_command`, `insecure_pickle`, `insecure_pathtraversal`,
  `insecure_permissions`, all AST- or regex-based) plus a syntax-validity check, exposed
  as `CUSTOM_DETECTOR` and `CWE_TO_BANDIT` (the `hardcoded` bucket defers to Bandit).
  

- **`faithful_pipeline.py`** — a replica of the experiment's retrieval path (identical
  chunking, un-normalised all-MiniLM embeddings, and L2 ranking over the same
  file walk). It lets poison generation measure the exact rank the live ChromaDB run
  will see, without the entire pipeline.

- **`retrieval_select.py`** — a scorer that selects poison candidates. It
  embeds the clean and background corpora, then scores candidate files on whether it
  reaches top-k for the target queries and whether the retrieved chunk exposes
  the insecure pattern. `generate_poison_corpus.py` uses it to keep the best
  candidate per file.


## Threat model

Six CWEs are covered, each mapped to an internal payload bucket and a detector

| Bucket | CWE |
|---|---|---|
| `sql` | CWE-89 |
| `pickle` | CWE-502 |
| `command` | CWE-78 |
| `pathtraversal` | CWE-22 |
| `permissions` | CWE-732 |
| `hardcoded` | CWE-798 |

## Repository layout

```
run_rag_poison.py            main experiment
build_repo.py                assemble the background corpus from CodeSearchNet
generate_corpus.py           generate the clean secure files
generate_poison_corpus.py    generate the retrieval-optimised poison files
detectors.py                 static insecurity detectors + syntax validity
faithful_pipeline.py         retrieval path replica used offline during poison generation
retrieval_select.py          retrieval scorer used to select poison candidates
corpus_spec.json             specification for the clean artifacts
poison_corpus_spec.json      specification for the poison artifacts
corpus/                      generated clean/ and poisoned/ artifacts (+ manifests)
background_corpus.zip        pre-built background corpus (unzip before running)
queries/                     LLMSecEval-derived query set and the filter script
result_notebooks/            saved runs
```

Some subject models (e.g. CodeGemma, CodeLlama) are gated on the Hugging Face Hub;
accept their licence and authenticate with `huggingface-cli login` before use.