# Corpus Poisoning of Retrieval-Augmented Code Generation

Measures whether poisoned files planted in a retrieval corpus can steer a 
retrieval-augmented code LLM into emitting insecure code. The experiment compares 
attack success rate (ASR) with the poison present (`poison_on`) against a clean 
baseline (`poison_off`) across multiple temperatures for 5 subject models.

## Requirements

- Python 3.10 or newer.

```bash
pip install torch transformers accelerate bitsandbytes chromadb \
    sentence-transformers numpy pandas matplotlib datasets bandit
```

## To run the experiment on the existing corpus

The `corpus/` directory is already generated. Unzip the background
corpus and point the script at a model.

1. Unzip the background corpus:

   ```bash
   unzip background_corpus.zip
   ```

   This creates `background_corpus/`, which the experiment reads as retrieval
   competition.

2. The query set should be present. The experiment reads `queries/queries.jsonl`.
Then set the subject model in the notebook. Accepted model Ids:

   - `Qwen/Qwen2.5-Coder-1.5B-Instruct`
   - `Qwen/Qwen2.5-Coder-7B-Instruct`
   - `google/codegemma-7b-it`
   - `codellama/CodeLlama-7b-Instruct-hf`

3. Run the notebook

### Running the Gemini subject

Gemini runs through a separate script because it uses the Google API.
The subject model is `gemini-3.1-flash-lite`.

1. Set your key:

   ```bash
   export GEMINI_API_KEY=your_key_here
   ```

2. Run:

   ```bash
   python run_rag_poison_gemini.py
   
### Outputs

| Path | Contents |
|---|---|
| `results/run_<ts>.jsonl` | Per-query log |
| `results/sweep_<ts>_<model>.jsonl` | Full temperature-sweep, one row per generation |
| `results/gemini/sweep_<model>.jsonl` | Gemini temperature-sweep, one row per generation |
| `results/gemini/gemini_run.jsonl` | Gemini per-query log |
| `results/gemini/gemini_console.txt` | Gemini console output |

`<ts>` is the run timestamp and `<model>` is a short model tag.

Some subject models (e.g. CodeGemma, CodeLlama) are gated on the Hugging Face Hub;
accept their licence and authenticate with `huggingface-cli login` before use.

## Rebuilding the corpus from scratch

To regenerate the background, clean, and poison layers(background from CodeSearchNet, 
then the secure clean files, then the retrieval-optimised poison files, each gated 
by the detectors):

```bash
python build_repo.py --n 400 --mode drop --out-dir background_corpus/
python generate_corpus.py --spec corpus_spec.json --out-dir corpus/
python generate_poison_corpus.py --spec poison_corpus_spec.json --out corpus \
    --clean-dir corpus/clean --background-dir background_corpus --queries queries/queries.jsonl \
    --optimise-against queries --operation-policy matched --per-scenario --candidates 6 \
    --bg-sample 200 -k 5
```
## Defence (activation steering)

A generation-side defence is included. It aims to steers the model towards secure code 
at inference time.

The defence files:

- `defence_code_pairs/code_pairs.jsonl` — the secure/insecure contrastive pairs.
- `rag_poison_defense_arm.ipynb` — derives the steering vectors and runs the defended arm.
- `defense_config_calibration.ipynb` — calibrates strength and layers per bucket, and
  runs the HumanEval utility check.

Run `defense_config_calibration.ipynb` first for the calibrated configurations for
each model and weakness class. Then run `rag_poison_defense_arm.ipynb` for the 
steering defence.
