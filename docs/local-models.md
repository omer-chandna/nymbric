# Local models

Nymbric's default configuration points at Ollama and `qwen3:8b`. That tag is a current tool-capable model in the Ollama library. At the default 4-bit quant, weights are about 5 GB. With `num_ctx` 8192, an 8 GB RTX 4060 can hold one copy. KV cache at long context will spill; do not raise `num_ctx` until a run fits.

This tree was tested with the mock provider only. A claim that a local model passed PKG-Risk is valid only after you run the commands below and keep the result file.

## Windows 11 and WSL2

1. Install the NVIDIA driver on Windows. WSL2 uses that driver; do not install a second Linux driver inside the distro.
2. Install Ollama inside WSL.
3. Keep a single model resident:

```bash
export OLLAMA_MAX_LOADED_MODELS=1
ollama pull qwen3:8b
nymbric models check --provider ollama --model qwen3:8b --probe
```

`--probe` sends one structured-output request. If it fails, the model is not usable for this benchmark yet. The process will not switch to another provider.

4. Run one model across all four conditions before changing models:

```bash
nymbric run pkg-risk \
  --provider ollama \
  --model qwen3:8b \
  --conditions all \
  --trials 4 \
  --personas 24 \
  --seed 42 \
  --defender model
```

The orchestrator runs agents one after another so two models are not loaded together. If VRAM is tight, use `qwen3:4b` for every role instead of mixing sizes. `llama3.1:8b` is an alternative tool-capable tag; validate it with `--probe` rather than assuming the mock policy's behavior.

## Hosted models

Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` and pass `--provider openai` or `--provider anthropic`. For other OpenAI-compatible servers, set `base_url` in the model config and `--provider openai_compatible`. Missing credentials produce a diagnostic and exit code 2.

Do not send a non-synthetic world to a hosted API. The built-in generator is fictional; keep it that way.

## Reproducibility

Temperature defaults to 0. That does not make GPU kernels bitwise reproducible. Record the provider, model tag, `num_ctx`, world hash, and seed from the run row. The mock provider is repeatable given the same code and seed. Documented in `docs/reproducibility.md`.
