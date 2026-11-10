# Setup

## 1. Python environment

See the Quick start in the [README](../README.md). Everything in steps 1 and 2 of the roadmap runs with Python alone; no LLM is needed.

## 2. Local LLM (needed from roadmap step 3)

You do not need this yet. It is documented here so the decision is recorded.

### Decision: run Ollama natively, not in Docker

On an Apple Silicon Mac, Docker containers run inside a Linux VM that **cannot use the Mac's GPU (Metal)**. Ollama in Docker would therefore run on CPU only and be several times slower. The native macOS app uses Metal directly.

Marlowe's Python code talks to Ollama over its local HTTP API (`http://localhost:11434`), so it does not need Open WebUI at all. Open WebUI is optional, for ad-hoc chatting with models.

### Install (macOS)

```bash
brew install ollama            # or download the app from https://ollama.com
ollama serve                   # start the server (the macOS app does this automatically)
ollama pull <model>            # download a model; we will choose and benchmark one in step 3
ollama list                    # show installed models
curl http://localhost:11434/api/tags   # check the API is reachable
```

**Model sizing on 16 GB RAM:** a model of about 7 to 8 billion parameters at 4-bit quantisation needs roughly 5 to 6 GB, which leaves room for the OS and our analysis code. Larger models will swap and become unusably slow. We will benchmark two or three candidates on real Marlowe prompts in step 3 instead of guessing.

### Optional: Open WebUI

If you want a chat UI, run it in Docker and point it at the native Ollama:

```bash
docker run -d -p 3000:8080 \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -v open-webui:/app/backend/data \
  --name open-webui ghcr.io/open-webui/open-webui:main
```

`host.docker.internal` is how a container reaches services running on the Mac itself. The UI is then at http://localhost:3000.

### Finding an old install

If you previously installed these and want to find or remove them:

```bash
which ollama; ollama list                   # native Ollama, if installed
docker ps -a                                # any Ollama / Open WebUI containers
docker volume ls                            # their data volumes
```
