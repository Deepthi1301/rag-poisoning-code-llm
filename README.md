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

### Outputs

| Path | Contents |
|---|---|
| `results/run_<ts>.jsonl` | Per-query log |
| `results/sweep_<ts>_<model>.jsonl` | Full temperature-sweep, one row per generation |

`<ts>` is the run timestamp and `<model>` is a short model tag.

Some subject models (e.g. CodeGemma, CodeLlama) are gated on the Hugging Face Hub;
accept their licence and authenticate with `huggingface-cli login` before use.
