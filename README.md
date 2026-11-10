# Marlowe-DFIR

Marlowe-DFIR is a locally hosted, AI-assisted digital forensics and cybersecurity data science platform. It combines statistical analysis, machine learning and a local LLM to help an investigator analyse digital evidence, detect anomalies and understand patterns in data, with a focus on privacy, explainability and reproducible analysis.

> **Status:** early development. The project foundation and evidence hashing/provenance module are in place. Log ingestion, anomaly detection and the LLM assistant are not built yet; see [docs/roadmap.md](docs/roadmap.md).

## Design principle

**The LLM explains; deterministic code extracts, calculates and verifies.**
Every finding Marlowe reports should trace back to a computed result and the source records behind it. The local model never invents artefacts, timestamps or tool output.

## What works today

| Component | Status |
|---|---|
| Evidence registration: SHA-256 hashing, append-only provenance manifest, tamper verification | Done, tested |
| Linux auth log parser and normalised event table | Planned (step 2) |
| EDA, rule baseline and Isolation Forest anomaly detection | Planned (step 2) |
| Local LLM analyst via Ollama | Planned (step 3) |

## Quick start

Requires Python 3.11+. From the repository root:

```bash
python3 -m venv .venv          # create an isolated environment for this project
source .venv/bin/activate      # activate it (run this in every new terminal)
pip install -e ".[dev]"        # install Marlowe in editable mode, plus test/lint tools
pytest                         # run the test suite
ruff check . && ruff format --check .   # lint and formatting checks (same as CI)
```

```python
from marlowe.forensics import register_evidence, verify_evidence

record = register_evidence("data/raw/auth.log", "data/processed/case.manifest.jsonl")
print(record.evidence_id, record.sha256)
assert verify_evidence(record)  # False if the file has changed since registration
```

## Project layout

```text
src/marlowe/          Python package (application code)
  forensics/          hashing, provenance, evidence manifest
tests/                pytest tests
notebooks/            exploratory analysis (not core logic)
data/raw/             local evidence, never committed
data/processed/       derived data, never committed
data/sample/          small, redistributable demo data only
docs/                 setup, architecture and roadmap
```

## Documentation

- [Setup, including local LLM install](docs/setup.md)
- [Architecture and design decisions](docs/architecture.md)
- [Roadmap](docs/roadmap.md)

## Responsible use

Marlowe-DFIR is a research and portfolio project, not a certified forensic tool. Anomalies it flags are leads for an investigator to review, not proof of malicious activity. Use synthetic or public datasets for demonstrations, and never commit real evidence.
