# Marlowe-DFIR

Marlowe-DFIR is a locally hosted, AI-assisted digital forensics and cybersecurity data science platform. It combines statistical analysis, machine learning and a local LLM to help an investigator analyse digital evidence, detect anomalies and understand patterns in data, with a focus on privacy, explainability and reproducible analysis.

> **Status:** early development. Evidence provenance and an end-to-end SSH `auth.log` anomaly-detection pipeline (parser, features, rule baseline, Isolation Forest, evaluation) are in place and tested. The LLM assistant is not built yet; see [docs/roadmap.md](docs/roadmap.md).

## Design principle

**The LLM explains; deterministic code extracts, calculates and verifies.**
Every finding Marlowe reports should trace back to a computed result and the source records behind it. The local model never invents artefacts, timestamps or tool output.

## What works today

| Component | Status |
|---|---|
| Evidence registration: SHA-256 hashing, append-only provenance manifest, tamper verification | Done, tested |
| Synthetic labelled `auth.log` generator (attacks + realistic benign hard negatives) | Done, tested |
| Linux auth log parser: normalised UTC table, every line kept, line-level provenance | Done, tested |
| Per-IP, per-window feature engineering | Done, tested |
| Rule baseline and Isolation Forest, with explanations | Done, tested |
| Time-split evaluation: precision/recall/F1, average precision, incident-level detection | Done, tested |
| EDA and evaluation notebook | Done |
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

### Run the analysis

```bash
marlowe generate --out data/sample          # (re)create the synthetic log + labels (seed 42)
marlowe analyse data/sample/auth.log --year 2026 --labels data/sample/auth_labels.csv
```

This registers the log as evidence, parses it, builds features, runs both detectors on the test period, prints the evaluation and writes every flagged window, with its source line numbers, to `data/processed/findings.csv`.

To open the notebook: `pip install -e ".[notebooks]"`, then `jupyter lab notebooks/`.

Headline result on the synthetic data: the rules catch 5 of 5 test-period incidents with 1 false positive, and the Isolation Forest reaches an average precision of 0.96 but is conservative at its pre-set threshold. See [docs/methodology.md](docs/methodology.md) for the full results, error analysis and limitations.

### Use the library

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
  synthetic/          labelled synthetic datasets
  parsers/            raw logs -> normalised tables
  features/           event -> window feature engineering
  detection/          rule baseline, Isolation Forest
  evaluation/         time split, metrics, incident detection
  pipeline.py         end-to-end analysis (used by CLI, notebooks, later the LLM)
  cli.py              `marlowe` command
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
- [Methodology, results and limitations](docs/methodology.md)
- [Roadmap](docs/roadmap.md)

## Responsible use

Marlowe-DFIR is a research and portfolio project, not a certified forensic tool. Anomalies it flags are leads for an investigator to review, not proof of malicious activity. Use synthetic or public datasets for demonstrations, and never commit real evidence.
