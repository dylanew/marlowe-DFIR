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
# ~5 GB, once
ollama pull llama3.1:8b
# interactive
marlowe chat data/sample/auth.log --year 2026
marlowe chat data/sample/auth.log --year 2026 -q "What is the most serious finding?"
# any installed tool-capable model
marlowe chat ... --model qwen2.5:7b
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
| `list_logins` | successful logins across all users, optionally only off-hours and/or only from a never-before-used source, with raw lines |
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
| The model doesn't look at the source evidence | `get_finding` and `ip_activity` include a few representative raw lines (`sample_evidence`): the first lines, any successful logins and the last line. The model sees the source without having to remember to ask for it. |
| The model guesses an identifier, the lookup fails, and it concludes "nothing happened" | Lookup errors are **recoverable**: an unknown IP returns the flagged IPs, an unknown user returns the known users, and invented parameters return the valid ones, each with a hint naming the right tool. An answer built only on failed tool calls **fails** the grounding check, and the retry message says that a failed call is not evidence of absence. |
| A sweeping citation such as `[lines 1-539]` passes because every line in it was seen somewhere (seen in the web app: "539 cited lines all verified") | A citation wider than 40 lines must sit inside one block a tool returned as a unit, such as a finding's own window. Otherwise it fails as "too wide", and the retry asks for the specific lines behind each claim. |
| The investigator asks about something that isn't there ("What did 10.9.9.9 do?"), and the correct answer, "it isn't in the evidence", has nothing to cite | A lookup that finds nothing returns `not_found`. If the investigator's own question named that value and the answer says plainly that it is absent, the check passes without citations. A value the *model* guessed never counts, so the original failure (guess an IP, find nothing, conclude no attack) still fails. |
| Invented times ("between 16:50 and 17:40" when the window starts at 16:50 and activity ends at 17:00) | Every ISO timestamp in an answer, to the minute, must have appeared in a tool result. |
| The answer misses that an attack succeeded (seen twice with llama3.1:8b: "the attackers haven't been very successful" about an IP that got root) | Every finding carries the IP's successful logins across the whole log and, when there are any, a plain-sentence `alert`. A deterministic **completeness check** then fails any answer that names a flagged IP which logged in without saying so, and the retry states exactly what was left out. The Findings tab shows the same fact in an "IP ever logged in as" column. |
| An ungrounded answer reaches the investigator | **Verify, then retry:** if the grounding check fails, the answer goes back to the model once with the specific problems. The note is labelled as coming from the automated checker, not the investigator. Both attempts are kept in the audit log, and the CLI says when a retry happened. |
| Bugs disguised as "tool errors" | Only expected problems (`ToolError`, invalid arguments) go back to the model. Anything else raises, so it gets fixed. |
| Accountability | Every question, the tool calls and their arguments, the answer and the grounding result go to an append-only audit log (`data/processed/assistant_audit.jsonl`) with the model name and prompt version. |

### Three outcomes, not two

Marlowe also answers general questions ("what is a password spray?", "how should I harden sshd?"), which have nothing to cite. So every answer gets one of three statuses:

| Status | When | Shown as |
|---|---|---|
| **verified** | Every cited line, IP and hash checks out, or the answer reports that something the investigator asked about isn't in the evidence, as a tool confirmed | green |
| **general** | The answer ends with "General guidance, not drawn from this evidence." **and** names nothing from the evidence: no citations, IPs, hashes or finding IDs | neutral |
| **failed** | Anything else, such as an uncited claim like "It was a brute force attack." | red; retried once |

The label is required on purpose. Without it, an evidence question answered from thin air would look exactly like a general answer. With it, an unlabelled, uncited claim still fails and goes back to the model. A model can still mislabel an answer, so the neutral badge says plainly that the answer was not checked against the evidence.

**What the grounding check does not do:** it confirms that cited evidence *exists and was seen*, not that the model *interpreted* it correctly. An answer can cite real lines and still draw a wrong conclusion. That is why the investigator stays in the loop.

## The personality slider

Marlowe is named after Raymond Chandler's detective, so it can talk like one, to a degree you choose. The **Personality** slider in the web app, or `--persona N` on `marlowe chat`, picks one of five voices (`PERSONA_LEVELS` in `prompts.py`):

| Level | Name | Voice |
|---|---|---|
| 0 | Plain | No persona: the rules prompt alone. The control. |
| 1 | Dry | Understated professional, at most one wry remark. |
| 2 | Marlowe | The original persona, word for word: laconic, world-weary, a simile or two. The web app's default; `--noir` is short for this. |
| 3 | Hard-boiled | First-person narration, short punchy sentences, a little period slang. |
| 4 | Full noir | Deliberately over the top: rain, smoke and a simile in nearly every sentence. The stress test. |

Design choices:

- **Tone only.** The persona may colour the short answer and the interpretation. The evidence section stays plain: citations, IPs, usernames, timestamps and counts are written exactly as the tools returned them.
- **Same rules at every level.** Each voice is appended after an identical rules prompt and repeats that the rules win. A test checks this, so a difference between levels can only come from the voice. A small model asked to play a character can otherwise decide the character "would" guess or embellish, and inventing a detail for atmosphere is exactly the failure the grounding check exists to catch.
- **Original voice.** The prompt asks for the style, not quotations from the novels.
- **Measured, not assumed.** The audit log records `persona_level` and `PERSONA_VERSION` (2 since the slider; level 2's wording is unchanged from version 1).

### Benchmarking the slider

The question is a dose-response one: **does grounding get worse as the character gets stronger, and from which level?** Run the same questions at every level:

```bash
python scripts/benchmark_models.py llama3.1:8b --levels 0 1 2 3 4 --out data/processed/bench_persona.csv
```

**It is slow.** On an M4 MacBook Air (16 GB) with llama3.1:8b, answers took 20 s to nearly 5 min each, around 2.5 min on average, so the full 40 answers take 1.5 to 2 hours. Each line it prints is one answer, so a long run of lines is progress, not a loop. To make that manageable:

- The results CSV is rewritten after every answer, so stopping early loses nothing. `--resume` carries on from it, skipping answers already done and asking again any that errored.
- `--questions 1 2 6 8` asks a subset (`--list-questions` shows the numbers). For example, `--levels 0 2 4 --questions 1 2 6 8` takes 12 answers, about 30 minutes.
- `--timeout` (default 600 s) is how long to wait for one model reply. The original 300 s cut off at least one slow answer.
- `--from-audit` rebuilds the CSV from `benchmark_audit.jsonl` without asking the model again, which rescues a run stopped before it saved anything. Add `--since 2026-11-12T21:00` (UTC) to leave out earlier runs. The audit log now records each answer's latency; answers logged before that show it blank.

It asks 8 questions per level (`QUESTIONS` in `marlowe/evaluation/persona.py`): the 5 from the model benchmark, plus "was root compromised?", one about an IP that isn't in the log (the right answer is that it isn't there), and one general question (the right answer keeps the "General guidance" label). For each answer it records:

- **Grounding**, first try and after the retry, using the same check as the app.
- **Correctness** on facts the synthetic ground truth gives us, such as naming the brute-force IP and that it got in as root. Questions with no known answer are left out of this rate rather than counted as right.
- **Voice**: similes, first person and period vocabulary per 100 words, outside the evidence section. If the voice score doesn't rise with the slider, the model ignored the persona and "no accuracy cost" means nothing.
- **Evidence leaks**: similes or period words *inside* the evidence section, which every level forbids.

Rates come with Wilson 95% intervals. With 8 questions, one answer is 12 percentage points, and 8 out of 8 is consistent with a true rate as low as 0.68, so only a large difference between levels is a real one. At temperature 0 the answers barely vary between runs, so for more data add questions rather than repeats; `--repeats N --temperature 0.7` measures run-to-run variation instead.

The voice measures are crude text statistics, not a judgement of the writing. That is deliberate: they are transparent, deterministic and unit tested, which an LLM judge would not be.

### Results: llama3.1:8b, first run

M4 MacBook Air, 16 GB, temperature 0, 1 retry. The run was stopped during level 4 and rebuilt with `--from-audit`, so level 1 has 7 answers (one timed out at the old 300 s limit) and level 4 has 4. Answers took about 2 to 4 minutes each. Medians from the printed log were 116 s at level 0 and 132 s at level 1; this run predates latency in the audit log, so the table has no latency column.

| Level | n | First-try grounded (95% CI) | Final grounded (95% CI) | Correct (95% CI) | Voice score | First person /100w | Similes /100w | Evidence leaks |
|---|---|---|---|---|---|---|---|---|
| 0 Plain | 8 | 0.62 (0.31–0.86) | 1.00 (0.68–1.00) | 1.0 (0.57–1.00) | 0.36 | 0.28 | 0.07 | 0 |
| 1 Dry | 7 | 0.57 (0.25–0.84) | 1.00 (0.65–1.00) | 0.8 (0.38–0.96) | 1.33 | 1.21 | 0.12 | 0 |
| 2 Marlowe | 8 | 0.38 (0.14–0.69) | 0.88 (0.53–0.98) | 0.8 (0.38–0.96) | 1.71 | 1.62 | 0.10 | 0 |
| 3 Hard-boiled | 8 | 0.38 (0.14–0.69) | 0.88 (0.53–0.98) | 0.8 (0.38–0.96) | 1.36 | 1.26 | 0.10 | 0 |
| 4 Full noir | 4 | 0.50 (0.15–0.85) | 1.00 (0.51–1.00) | 1.0 (0.34–1.00) | 2.28 | 2.28 | 0.00 | 0 |

What it shows:

- **No significant cost, but a weak experiment.** Final grounding stayed at 0.88 or above at every level, and no figurative language leaked into an evidence section. Every interval overlaps the others, though, so a cost of 20 to 30 points could still be hiding in this sample.
- **The dose was small.** The voice score rises with the slider, but almost all of that is first person ("I'd say..."). Similes stay near zero and level 3 scored *below* level 2. llama3.1:8b mostly ignored the stronger voices, so this tests "a bit of character", not "full noir". A model that follows style instructions more closely would be a fairer test of level 4.
- **First-try grounding dips from about 0.6 to 0.4 at levels 2 and 3.** The retry rescued most of those, which is the verify-then-retry safeguard doing its job. The dip is within noise for now.
- **The one recurring failure is a completeness failure, and only with a persona.** "Are there any successful logins at unusual hours from new addresses?" failed at levels 2 and 3 after the retry, both times for the same reason: it listed logins but left out that two attacking IPs got in (203.0.113.101 as frank, 203.0.113.88 as bob). The same question passed at levels 0 and 1. This is the most interesting lead: a voice may crowd out completeness rather than cause invention, and the completeness check is what caught it.

Next: finish level 4 and the timed-out level 1 answer (`--resume`), then read those two failed answers in the audit log and decide whether the completeness rule needs repeating in the persona's guardrails.

## Choosing a model

The default is `llama3.1:8b` (override with `--model` or `MARLOWE_MODEL`). On 16 GB of RAM, aim for roughly 7–8B parameter models at 4-bit quantisation. The model **must support tool calling**: check the "tools" tag on the model's page at ollama.com/library.

Don't guess; measure:

```bash
# pick 2–3 candidates
ollama pull llama3.1:8b && ollama pull qwen2.5:7b
python scripts/benchmark_models.py llama3.1:8b qwen2.5:7b
```

The script asks 5 fixed questions per model and records latency, tool calls, grounding pass rate and step-limit hits. The results table belongs in this document once it has been run.

| Model | Version | Median s/answer | Mean tool calls | Saw raw evidence | First-try grounded | Final grounded | Notes |
|---|---|---|---|---|---|---|---|
| llama3.1:8b | step 3 (prompt only) | 22.4 | 1.2 | 0.0 | 0.6 (3 of 5) | 0.6 (3 of 5) | M4 MacBook Air, 16 GB, temperature 0; 5.0–36.6 s per answer |
| llama3.1:8b | step 3b, sample evidence only (`--retries 0`) | 16.9 | 1.2 | 0.2 | 0.6 (3 of 5) | 0.6 (3 of 5) | |
| llama3.1:8b | step 3b, sample evidence + 1 retry | 25.0 | 1.2 | 0.2 | 0.6 (3 of 5) | 0.6 (3 of 5) | same 2 questions failed; retry did not fix them |
| llama3.1:8b | step 3c, recoverable errors + `list_logins` + prompt v2 | 34.5 | 1.6 | 0.4 | 0.6 (3 of 5) | **1.0 (5 of 5)** | both former failures recovered via retry; one answer took 120 s |

**Step 3c result:** final grounding went from 3 of 5 to **5 of 5**. Both questions that had failed in every earlier configuration now pass after one retry, because the retry message tells the model which call failed and which tool to use. The first-try rate didn't change (0.6), so the model still guesses at first. The improvement comes from the *system* catching and correcting it, which is the point of step 3b/3c. The cost is latency: the median rose from about 22 s to 34.5 s, and a retried answer can take up to 2 minutes. Caveats: 5 questions and a single run. Grounding also verifies that the evidence is *real*, not that the conclusion is *right*, so the recovered answers still need reading against the ground truth.

**Step 3b result: no measurable improvement.** The same two questions failed in every configuration. Two things the numbers show:
- **Sample evidence rarely reaches the model** (1 answer in 5). With about 1.2 tool calls per question, the model mostly stops after `get_overview` or `list_findings`, and neither of those returns raw lines. The evidence was added to the tools the model *doesn't* call.
- **The retry runs but doesn't fix the answer.** For the failing questions it took a few seconds longer with a retry than without, so the model was asked again and produced another ungrounded answer.

The benchmark now writes every answer, tool sequence and grounding failure to `data/processed/benchmark_audit.jsonl` and prints the failures, so the next change can be based on *why* those two questions fail rather than on a guess.

### Step 3c: error analysis of the two failures

The audit log showed that both failures had the same root cause. **The model skipped discovery and called a lookup tool with a guessed argument:**

| Question | What the model did | Result |
|---|---|---|
| Which IP looks most like a brute force? | `ip_activity(src_ip="192.168.1.100")`, an invented private IP | "not found" error → answered **"No source IP appears to be attempting a brute-force attack"**. This is a false negative on the most serious incident in the data. |
| Off-hours logins from new addresses? | `user_activity(user="all", off_hours="True", new_addresses="True")`, invented parameters | "bad arguments" error → "there are no successful logins…". On retry it added a made-up `[line 1]` citation. |

The first failure is the dangerous kind: **an absence-of-evidence claim built on a failed tool call.** The grounding check did catch both answers, but only as "no citations". It didn't recognise the actual problem, so the retry couldn't fix it.

The second also revealed a **capability gap**: no tool answered "logins across all users with filters", so the model invented one.

Changes:
1. **Recoverable errors:** see the safety table above. Errors return the real candidates and the next tool to call.
2. **`list_logins`:** a new tool for the question the model was trying to ask. It surfaces all three injected stolen-credential logins.
3. **Failed calls can't support an answer:** if no tool call succeeded, the answer fails grounding ("answered without any successful tool result"). The retry message lists the failed calls and says a failure is not evidence of absence.
4. **Prompt v2:** never guess identifiers; discover them first; a failed call is not evidence.

Both real failures are replayed as tests (`tests/test_agent.py::test_replay_*`).

Use `--retries 0` to measure the effect of sample evidence alone, without retries.

**Reading the llama3.1:8b result:** it never fetched raw lines (0 of 5) and averaged barely more than one tool call per question. The two fastest answers (5.0 s and 8.4 s) were the two that failed grounding, which suggests that when it does little tool work, it also fails to cite evidence. With only 5 questions this is indicative, not conclusive. Still, it shows that prompting alone did not make the model check the source.

`Saw raw evidence` is the share of answers where the model received actual log text from any tool, whether through `get_log_lines` or the `sample_evidence` that `get_finding` and `ip_activity` now include. (The step 3 run measured only `get_log_lines`, which was the only source of raw text then.) A careful analyst checks the source, so higher is better. `First-try grounded` is the grounding rate before any retry, and `Final grounded` is the rate after it.

### First real run (llama3.1:8b, M4 MacBook Air)

Asked "What is the most serious finding?", the model called `get_finding("F1")` once and answered correctly. It identified the brute force from `203.0.113.62`, and every number it quoted (130 failures, 109 invalid users, 239 events, score 0.757, lines 1309–1548) matched the analysis. Two lessons:

- It cited `(lines 1309-1548)` rather than the requested `[lines ...]`, so the first version of the grounding check wrongly reported "no citations". The checker now verifies every "line N" mention, whatever the brackets.
- It summarised from computed features **without fetching any raw lines**, despite the prompt asking it to check the source. The benchmark's raw-lines rate measures this across questions and models.

### Step 3b: safeguards in code, not just the prompt

The step 3 benchmark showed that the prompt alone doesn't make an 8B model careful: it never fetched raw lines, and 2 of 5 answers failed grounding. Rather than rewording the prompt again, step 3b moves the safeguards into code:

1. **Evidence comes with the finding.** `get_finding` and `ip_activity` now include up to 7 representative raw lines, so the model sees the source even if it never calls `get_log_lines`.
2. **Verify, then retry.** A failed grounding check sends the answer back once, with the specific problems (for example "no line citations", or "IPs not in the evidence: [...]"). The investigator sees the final answer and whether a retry happened. The audit log keeps both attempts.

The design principle is that **reliability comes from the system, not from the model's good behaviour**. That matters most with small local models.

## Testing without a GPU

The test suite never needs a real model. `tests/test_agent.py` uses a scripted fake client to test the loop, the grounding check and the injection boundary. `tests/test_ollama_client.py` runs a fake Ollama HTTP server to test the real client and the `marlowe chat` command end to end.
