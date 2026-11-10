# Roadmap

Goal: a polished, demonstrable project for internship applications that shows sound software engineering and data-science practice applied to DFIR.

## Step 1: Project foundation (done)

- Python package skeleton, `.gitignore` that keeps evidence out of Git
- Evidence hashing and provenance manifest, with tests
- CI: lint and tests on every push
- Setup and architecture docs

## Step 2: Log anomaly detection, end to end, without the LLM (done)

- Generate a synthetic Linux `auth.log` dataset with known injected attacks (brute force, off-hours logins, new source IPs), so results can be measured against ground truth
- Parser to a normalised pandas table, keeping the evidence ID and line number of every event
- EDA notebook: event volumes, time-of-day distributions, per-user and per-IP behaviour
- Transparent rule baseline (e.g. failed logins per IP per time window)
- Isolation Forest on engineered features, compared with the baseline on precision, recall and false positives, using a time-based split
- Documented limitations

Follow-ups identified by the error analysis:
- Sliding windows, or a look-back feature ("failures from this IP in the last 30 min"), to fix attacks split across window boundaries
- Per-user (UEBA) features for stolen credentials used from familiar networks
- Validation on a public dataset with real behaviour

## Step 3: Marlowe as an AI analyst

- Benchmark local models that fit in 16 GB
- Python layer where the LLM can only call predefined, read-only analysis functions
- Explanations of flagged events that cite evidence IDs and line numbers

## Step 4: Portfolio presentation

- Methodology write-up, architecture diagram, screenshots, short demo
- Decide whether a second data source (network flows, e.g. CIC-IDS2017) is worth adding
