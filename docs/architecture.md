# Architecture

## Pipeline

```text
Evidence files (logs, CSV, JSON)
        |
        v
 1. Registration      hash + provenance manifest      (marlowe.forensics)   <- built
        |
        v
 2. Parsing           source-specific parsers          (marlowe.parsers)     <- step 2
        |
        v
 3. Normalisation     common event schema, UTC times   (marlowe.parsers)     <- step 2
        |
        v
 4. Analysis          EDA, baseline rules, ML models   (marlowe.detection)   <- step 2
        |
        v
 5. Assistant         local LLM calls approved         (marlowe.assistant)   <- step 3
                      analysis functions and explains
                      results with source references
```

Each stage only depends on the output of the stage before it, so a new log source means a new parser and nothing else changes.

## Key decisions

**Python package with a `src/` layout.** Code lives in `src/marlowe/` and is installed into the virtual environment with `pip install -e .`. This forces tests to import the package the same way a user would, which catches packaging mistakes early. It is the layout recommended by the Python Packaging Authority.

**Notebooks for exploration, the package for logic.** Notebooks are ideal for EDA and explaining results, but hard to test and review. Any function a notebook relies on moves into `src/marlowe/` with tests.

**Evidence is read-only and hashed on arrival.** `register_evidence` records SHA-256, size, path, UTC time and tool version in an append-only JSON Lines manifest. `verify_evidence` re-hashes to detect any change. Evidence IDs are derived from the hash, so they can be cited in findings and reports.

**Dependencies are added when they are needed.** The core package currently has no runtime dependencies. pandas and scikit-learn arrive in step 2 with the code that uses them.

**Native Ollama, not Docker.** See [setup.md](setup.md): Docker on Apple Silicon has no GPU access.

**CI on every push.** GitHub Actions runs ruff (lint and formatting) and pytest with coverage on Python 3.11 to 3.13.
