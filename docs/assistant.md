# Marlowe the AI analyst

Marlowe is a local LLM (via Ollama) that answers questions about an analysed `auth.log`. It **explains** results; deterministic code **computes** them.

```text
investigator question
        |
        v
  Analyst loop (marlowe/assistant/agent.py)
        |   sends: system prompt + conversation + tool definitions
        v
  local model (Ollama, on your Mac)  ──>  "call list_findings(limit=5)"
        |                                        |
        |   our code runs ONLY registered,       v
        |   read-only tools  <───────  AnalysisTools (tools.py)
        |                                        |
        |   JSON result goes back to the model   |
        v                                        |
  final answer with [line N] citations  <────────┘
        |
        v
  grounding check (deterministic)  ->  shown to user + appended to audit log
```

## Try it (on your Mac)

```bash
ollama pull llama3.1:8b                                   # ~5 GB, once
marlowe chat data/sample/auth.log --year 2026             # interactive
marlowe chat data/sample/auth.log --year 2026 -q "What is the most serious finding?"
marlowe chat ... --model qwen2.5:7b                      # any installed tool-capable model
```

Each answer is followed by the tools the model called and the result of the grounding check.

## The tools (`marlowe/assistant/tools.py`)

| Tool | Returns |
|---|---|
| `get_overview` | evidence hash, time range, event counts, detector descriptions, number of findings |
| `list_findings` | flagged windows (F1 = most anomalous) with rule and Isolation Forest reasons and line ranges |
| `get_finding` | every feature value for one finding, plus its line numbers |
| `get_log_lines` | raw lines by number (max 40), under `untrusted_log_lines` |
| `ip_activity` | everything one source IP did: counts, usernames tried, successful logins, findings |
| `user_activity` | one user's logins, source IPs, login hours and off-hours successes |

## Safety and trust design

| Risk | Mitigation |
|---|---|
| The model invents evidence (hallucination) | It can only learn about the evidence through tools. The system prompt requires `[line N]` citations, and a **deterministic grounding check** verifies that every cited line was actually returned by a tool, every IPv4 address exists in the evidence, and any SHA-256 matches the evidence hash. A failure is shown to the user, not hidden. |
| Prompt injection via log content (a username can be any string an attacker sends) | Raw text is only ever returned inside JSON tool results, under `untrusted_log_lines`. The system prompt tells the model that this is data and that instruction-like text should be reported as a finding. A test checks that such text never reaches the model as a system or user message. |
| The model takes harmful actions | It can't. Tools are read-only functions over an already-computed result. There is no shell, file or network access, and unknown tool names are refused. |
| Context overflow on a 16 GB machine | Every tool output is bounded (≤ 25 findings, ≤ 40 lines, ≤ 30 usernames). |
| Ground truth leaking into the answer | On synthetic data the labels exist, but no tool exposes them, and a test checks this. Marlowe reasons from the same information a real analyst would have. |
| Runaway tool loops | Capped at 8 steps per question. |
| Bugs disguised as "tool errors" | Only expected problems (`ToolError`, invalid arguments) go back to the model. Anything else raises, so it gets fixed. |
| Accountability | Every question, the tool calls and their arguments, the answer and the grounding result go to an append-only audit log (`data/processed/assistant_audit.jsonl`) with the model name and prompt version. |

**What the grounding check does not do:** it confirms that cited evidence *exists and was seen*, not that the model *interpreted* it correctly. An answer can cite real lines and still draw a wrong conclusion. That is why the investigator stays in the loop.

## Choosing a model

The default is `llama3.1:8b` (override with `--model` or `MARLOWE_MODEL`). On 16 GB of RAM, aim for roughly 7–8B parameter models at 4-bit quantisation. The model **must support tool calling**: check the "tools" tag on the model's page at ollama.com/library.

Don't guess; measure:

```bash
ollama pull llama3.1:8b && ollama pull qwen2.5:7b        # pick 2–3 candidates
python scripts/benchmark_models.py llama3.1:8b qwen2.5:7b
```

The script asks 5 fixed questions per model and records latency, tool calls, grounding pass rate and step-limit hits. The results table belongs in this document once it has been run.

| Model | Median s/answer | Grounded rate | Notes |
|---|---|---|---|
| *to be filled in from your benchmark run* | | | |

## Testing without a GPU

The test suite never needs a real model. `tests/test_agent.py` uses a scripted fake client to test the loop, the grounding check and the injection boundary. `tests/test_ollama_client.py` runs a fake Ollama HTTP server to test the real client and the `marlowe chat` command end to end.
