# Marlowe-DFIR: a local AI analyst that has to show its evidence

*A project write-up. For setup and commands, see the [README](../README.md). For the detail behind every number here, see [methodology.md](methodology.md) and [assistant.md](assistant.md).*

## The short version

Marlowe-DFIR analyses a Linux SSH `auth.log` for attacks and lets an investigator ask questions about it in plain English. The answers come from a small language model running entirely on a laptop (llama3.1:8b through Ollama, on a 16 GB MacBook Air), so no evidence leaves the machine.

The design rests on one rule: **the LLM explains; deterministic code extracts, calculates and verifies.** Detection is done by tested rules and an Isolation Forest. The model can only see the evidence through read-only tools, must cite log lines, and every answer is checked by code before the investigator sees it.

The assistant is named after Raymond Chandler's detective and can talk like one. A five-level personality slider runs from a plain assistant to full 1930s noir. That started as character, and it became the project's most interesting experiment: **does a stronger persona make a small model less reliable?** It did, measurably, in one specific way, and a one-paragraph change to the prompt closed the gap.

## Why build it this way

Two constraints shaped everything.

**Evidence can't go to a cloud API.** In forensics, sending case data to a third party is often not an option. So the model has to run locally, which on a laptop means a model of about 8 billion parameters. Models that size are fluent but careless: they guess identifiers, skip steps and state things they never checked.

**An investigator has to be able to trust, or at least check, every claim.** "The model said so" is not evidence. Every finding has to trace back to specific lines in a file whose hash was recorded when it arrived.

Together these lead to the central choice: don't try to make the model trustworthy, make the *system* trustworthy around it. The model never sees a raw dump of the log. It calls small, bounded, read-only functions (`list_findings`, `ip_activity`, `list_logins` and so on) and gets JSON back. Then a deterministic checker reads its answer.

## The pipeline

```text
auth.log -> register (SHA-256, append-only manifest)
         -> parse (every line kept, UTC, line numbers)
         -> features (one row per source IP per 10-minute window)
         -> rule baseline + Isolation Forest -> findings with line ranges
         -> Marlowe: tools -> answer -> grounding check -> audit log
```

The data is synthetic on purpose: measuring a detector needs ground truth, and real logs almost never have reliable labels. The generator injects brute force, password spraying and stolen-credential logins, plus benign "hard negatives" that look suspicious but aren't (a monitoring account with a stale password failing every five minutes for ten hours, users who forgot a changed password).

Detection results on the held-out last 40% of the timeline (a time-based split, since a random split would leak the future):

| Detector | Precision | Recall | Avg. precision | Incidents found |
|---|---|---|---|---|
| Rules | 0.89 | 0.73 | – | 5 of 5 |
| Isolation Forest | 1.00 | 0.45 | 0.96 | 2 of 5 |

The rules look strong, but that is partly circular: the same person wrote the attack generator and the rules. The Isolation Forest ranks very well (average precision 0.96) but its pre-set threshold is conservative, and moving that threshold changes more than changing the model would. The two are complementary: rules explain known patterns, and the model ranks unusual ones. The full error analysis, including a window-boundary bug that hid the single most important login, is in [methodology.md](methodology.md).

## What the grounding checks catch

Every answer gets one of three statuses: **verified** (everything it cites checks out), **general** (it answers a general question, carries a "General guidance" label and names nothing from the evidence) or **failed**. A failed answer goes back to the model once, with the specific problems listed. Both attempts go into the audit log.

The checks were not designed up front. Almost every one was added after reading a real failure by llama3.1:8b:

| What the model did | The check that now catches it |
|---|---|
| Cited `(lines 1309-1548)` instead of `[lines ...]`, so the first checker wrongly said "no citations" | Every "line N" mention is verified, whatever the brackets |
| Called `ip_activity("192.168.1.100")`, an IP it made up, got "not found" and answered **"no source IP appears to be attempting a brute force"**: a false negative on the most serious incident | Lookup errors return the real candidates; an answer built only on failed tool calls fails |
| Cited `[lines 1-539]` so that every line "was seen somewhere" | A citation wider than 40 lines must match one block a tool returned |
| Gave an end time for an attack that no tool had returned | Every ISO timestamp, to the minute, must have appeared in a tool result |
| Said, twice, that "the attackers haven't been very successful" about the brute-force IP that guessed the root password and logged in | The **completeness check**: an answer that names a flagged IP which logged in, without saying so, fails |

That last one is worth dwelling on. Nothing in the answer was invented. Every line it cited was real. It was simply wrong in the most dangerous direction: it told the investigator a successful compromise had failed. The successful root login sat just after the flagged window and was in the tool output as an item in a list of usernames, and the model didn't connect it. The fix was partly in code (findings now carry a plain-sentence alert when their IP ever logged in) and partly a new check.

## What they can't catch

This is the most important limitation, so it belongs in plain words: **the grounding check confirms that cited evidence exists and was seen, not that the model interpreted it correctly.** An answer can cite real lines and still draw the wrong conclusion. The completeness check covers one specific, high-stakes omission (an attacker got in); it doesn't cover every possible wrong inference. A model can also mislabel an evidence question as general guidance, which is why the "general" badge says outright that the answer was not checked.

Other things the checks don't know about:

- Whether the detectors were right in the first place. The checker trusts the findings it was given.
- Anything outside IPs, line numbers, hashes and timestamps. Usernames and counts are not verified token by token.
- Real-world data. Everything here is measured on one synthetic host over 14 days.

The investigator stays in the loop. Marlowe's job is to make a wrong answer visible, not to make it impossible.

## The personality slider experiment

### The question

A small model asked to play a character can decide the character "would" embellish. For a forensics assistant, a detail invented for atmosphere is exactly the failure everything above exists to prevent. So the persona was built cautiously: the voice applies to tone only, the evidence section stays plain, the rules prompt is identical at every level (a test enforces this), and the voice repeats that the rules win.

That makes the question measurable as a dose-response: run the same 8 questions at each of the 5 levels, and see whether grounding gets worse as the character gets stronger. Each answer is scored for grounding (the app's own check), correctness against the synthetic ground truth, and how much voice it actually had (similes, first person and period vocabulary per 100 words). The voice score matters: if it doesn't rise with the slider, the model ignored the persona and "no accuracy cost" would mean nothing.

### Result 1 (persona v2): character costs completeness, not honesty

| Level | Final grounded | Completeness failures (of 8) | Voice score |
|---|---|---|---|
| 0 Plain | 1.00 | 0 | 0.36 |
| 1 Dry | 1.00 | 0 (of 7) | 1.33 |
| 2 Marlowe | 0.88 | 1 | 1.71 |
| 3 Hard-boiled | 0.88 | 1 | 1.36 |
| 4 Full noir | 0.75 | 2 | 1.85 |

No level invented a line, an IP, a hash or a timestamp, and nothing figurative leaked into an evidence section. Every final failure, at every level, was the completeness check: the answer named an attacking IP and left out that it had logged in. Those failures went 0, 0, 1, 1, 2 from Plain to Full noir. A Cochran–Armitage trend test gives p ≈ 0.07.

That is suggestive, not conclusive, and the caveats are real: the counts are tiny, and the trend test was chosen after seeing the data. But there was a plausible mechanism. The persona's guardrails repeated the rule against invention. They didn't repeat the rule about completeness. A model spending attention on style kept the rule it had been reminded of and let the other one slip.

### Result 2 (persona v3): restate the rule where the style lives

Persona v3 added one paragraph to every voice's guardrails and changed nothing else:

> Style never costs a fact. If an IP address you mention logged in successfully, say so plainly, with the username and the line citation, before any colour. Leaving out that an attacker got in is worse than any lapse in character.

The success criterion was set before the rerun: completeness failures at levels 2 and 4 back to 0 or near it, **without the voice score falling**. A falling voice score would mean the rule worked by suppressing the character, which is a different and less useful result.

| | v2 (levels 2 + 4) | v3 (levels 2 + 4) |
|---|---|---|
| Completeness failures | 3 of 16 | **0 of 16** |
| First-try grounded | 6 of 16 | 11 of 16 |
| Final grounded | 0.88, 0.75 | **1.00, 1.00** |
| Voice score, level 4 | 1.85 | **2.98** |
| Voice score, level 2 | 1.71 | 1.32 |
| Correct (known-answer questions) | 0.8, 0.6 | 0.8, 0.6 |

The gap closed, and the character didn't pay for it: Full noir actually got more noir. Level 2's voice dipped, but by about as much as levels 2 and 3 differed from each other in v2, so it looks like noise rather than suppression.

### What these numbers can and can't support

Fisher's exact test on completeness failures, v2 against v3, gives p ≈ 0.23. With 16 answers per arm, that can't establish the effect. A rate of 8 out of 8 is consistent with a true rate as low as 0.68. The honest summary is **a consistent improvement with a plausible mechanism, matching a hypothesis stated in advance, but not a proven one.** More questions, not more repeats, would be the way to firm it up: at temperature 0 the same question gives nearly the same answer every time.

"Correct" didn't move, and the two remaining misses may be the scorer's fault rather than the model's. On "what is a password spray?" the model tied its answer to the case and cited lines instead of using the "General guidance" label, which the prompt allows. At level 4, an answer about an IP that isn't in the log passed grounding but wasn't recognised as saying the IP is absent. Both need reading in the audit log before anyone counts them as model errors.

### The lesson

**When a style instruction competes with a safety rule, restate the rule where the style instruction lives.** Saying it once in the system prompt wasn't enough. Saying it again inside the persona, in the persona's own terms ("style never costs a fact"), was.

This generalises beyond noir. Any product that layers a tone, a brand voice or a role on top of a model's rules is running the same experiment, usually without measuring it.

## Engineering notes

- **115 tests, no GPU needed.** The agent loop is tested with a scripted fake model, and the real HTTP client against a fake Ollama server. Both real failures from the error analysis are replayed as regression tests.
- **The benchmark is safe to stop.** A full 40-answer run takes 1.5 to 2 hours on the laptop, so results are written after every answer, `--resume` picks up where it left off, and `--from-audit` rebuilds the results from the audit log without asking the model again.
- **A timeout that turned out to be a runaway reply.** One question timed out at 300 s and again at 600 s. At this machine's speed, 600 s is thousands of tokens, against a few hundred for a normal answer, so replies are now capped at 1024 tokens and a stuck reply gets graded instead of hanging.
- **About 80 lines of standard-library HTTP instead of an Ollama SDK**, to keep dependencies down and make the client easy to fake.
- **Streamlit web app** with findings, timeline charts and chat on one page, a grounding badge on every answer, and CSS-only smoke effects that respect "reduce motion".

## What I'd do next

- Read the two remaining "correct" misses in the audit log and fix whichever of the model or the scorer is wrong.
- Add questions to the slider benchmark so the v2/v3 difference can be tested properly.
- Validate the detectors on a public dataset with real behaviour, which is the biggest gap in the detection results.
- Try sliding windows or a look-back feature to fix the window-boundary miss.

## Limitations, in one place

Synthetic data from one host. Detectors and data designed by the same person. 8 questions per persona level, so every rate has a wide interval. One model, one machine. The grounding check verifies that evidence was real and seen, not that the conclusion is right. Marlowe-DFIR is a research and portfolio project, not a certified forensic tool: its findings are leads, not proof.
