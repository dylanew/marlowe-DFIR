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

## Step 3: Marlowe as an AI analyst (done)

- Benchmark local models that fit in 16 GB
- Python layer where the LLM can only call predefined, read-only analysis functions
- Explanations of flagged events that cite evidence IDs and line numbers
- Deterministic grounding check and an append-only audit log
- Benchmarked llama3.1:8b: correct answers but it rarely checks the raw evidence (see `docs/assistant.md`)

## Step 3b: Safeguards in code (done)

- Sample raw evidence included in `get_finding` and `ip_activity`
- Verify-then-retry when the grounding check fails
- Result: no measurable improvement; error analysis showed the real cause

## Step 3c: Recoverable tool errors (done: final grounding 3/5 -> 5/5)

- Errors return real candidates and next-step hints; new `list_logins` tool
- An answer built only on failed tool calls fails grounding
- Prompt v2: discover identifiers, never guess them
- Re-ran the benchmark: both former failures now recover via retry

## Step 3d: Web app (done)

A Streamlit app (`marlowe web`) over the same pipeline and assistant: overview with evaluation metrics, findings table with drill-down to raw lines, timeline charts, and an Ask Marlowe chat that shows the tools used and the grounding check on every answer. Streamlit was chosen over Open WebUI so that findings, charts and chat sit in one interface and Marlowe's safeguards (tool loop, grounding check, audit log) stay in our code.

## Step 3e: Philip Marlowe persona (next)

An optional noir voice for the assistant, in tone only, with the evidence section kept plain. Versioned separately and benchmarked on and off, so the personality can be shown not to cost accuracy.

## Step 4: Portfolio presentation

- Methodology write-up, architecture diagram, screenshots, short demo
- Decide whether a second data source (network flows, e.g. CIC-IDS2017) is worth adding
