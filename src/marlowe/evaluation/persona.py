"""Benchmarking the personality slider: does more character cost accuracy?

The experiment is a dose-response test. The rules part of the system prompt
is identical at every slider level (a test guarantees it), so the only thing
that changes between levels is the voice. Ask the same questions at every
level and compare:

- **Grounding** (the existing deterministic check): first-try and final pass
  rates, each with a Wilson 95% interval, because with a handful of questions
  a difference of one answer is 20 percentage points and mostly noise.
- **Correctness** on facts we know from the synthetic ground truth, such as
  naming the brute-force IP and saying that it logged in as root.
- **Voice**: whether the answer actually sounds different. Without this, "no
  accuracy cost" could just mean the model ignored the persona.
- **Leakage**: figurative language inside the **Evidence** section, which every
  level says must stay plain.

The voice measures are simple text statistics (similes, first person,
period vocabulary), not a judgement of quality. They are crude on purpose:
they are transparent, deterministic and can be unit tested, which an LLM
judge could not be.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

# --- Questions -----------------------------------------------------------------

# An IP in the documentation range that the synthetic log never uses. Asking
# about it tests that the voice doesn't talk the model into inventing activity.
ABSENT_IP = "203.0.113.77"


@dataclass(frozen=True)
class BenchmarkQuestion:
    text: str
    # "evidence": should be grounded; "general": should keep the label and
    # not need tools; "absent": should say the IP isn't in the evidence.
    kind: str = "evidence"
    # Strings the answer must contain to count as correct. "{top_ip}" and
    # "{top_user}" are filled in from the analysis (the top finding's IP and
    # the account it logged in as).
    must_mention: tuple[str, ...] = ()


QUESTIONS: tuple[BenchmarkQuestion, ...] = (
    BenchmarkQuestion(
        "Give me an overview of this evidence and the most serious finding.",
        must_mention=("{top_ip}",),
    ),
    BenchmarkQuestion(
        "Which source IP looks most like a brute-force attack, and did it ever log in "
        "successfully?",
        must_mention=("{top_ip}", "{top_user}"),
    ),
    BenchmarkQuestion(
        "Are there any successful logins at unusual hours from new addresses? List them."
    ),
    BenchmarkQuestion(
        "Is finding F2 likely to be malicious? Show me the log lines that support your view."
    ),
    BenchmarkQuestion("Which flagged findings could plausibly be benign, and why?"),
    BenchmarkQuestion(
        f"What did {ABSENT_IP} do on this server?", kind="absent", must_mention=(ABSENT_IP,)
    ),
    BenchmarkQuestion(
        "Was the root account compromised? If so, when and from where?", must_mention=("{top_ip}",)
    ),
    BenchmarkQuestion(
        "What is a password spray, and how is it different from brute force?", kind="general"
    ),
)

# --- Voice measures ------------------------------------------------------------

_WORD = re.compile(r"[A-Za-z']+")
_SENTENCE_END = re.compile(r"[.!?]+(?:\s|$)")
# "like a ..." / "like the ..." and "as cold as ...". Not "looks like" in the
# sense of "appears to be": that is common in plain analysis ("looks like a
# brute force"), so verbs of appearance before "like" are excluded.
_SIMILE = re.compile(
    r"(?<!looks )(?<!look )(?<!seems )(?<!sounds )\blike (?:a|an|the|some)\b"
    r"|\bas \w+ as (?:a|an|the)\b",
    re.IGNORECASE,
)
_FIRST_PERSON = re.compile(r"\b(?:I|I'm|I've|I'd|me|my|mine)\b")
# Period atmosphere. A word list is crude, but it can only rise if the model
# reaches for the setting, and it is the same list at every level. Words a
# plain answer about logins might use ("night", "midnight", "client") are left
# out, so off-hours findings don't score as noir.
NOIR_WORDS = frozenset(
    """
    rain rainy raining smoke smoky cigarette cigarettes ashtray whiskey bourbon rye
    gin dame dames gumshoe shamus sap mug joint palooka pal sucker heater gat bulls
    copper coppers shadow shadows alley alleys neon fog trench fedora doll
    """.split()
)
_HEADING = re.compile(r"^\s*\*\*([^*]+)\*\*\s*:?", re.MULTILINE)


def evidence_section(text: str) -> str:
    """The text under the **Evidence** heading, up to the next bold heading."""
    headings = list(_HEADING.finditer(text))
    for i, h in enumerate(headings):
        if h.group(1).strip().rstrip(":").lower() == "evidence":
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            return text[h.end() : end]
    return ""


def _prose(text: str) -> str:
    """The answer minus its Evidence section and bold headings.

    Headings are the same at every level ("**What I'd do next**" would add a
    first-person "I'd" to every answer), so they are not counted as voice.
    """
    section = evidence_section(text)
    text = text.replace(section, " ") if section else text
    return _HEADING.sub(" ", text)


def voice_metrics(text: str) -> dict[str, float]:
    """Text statistics that rise with the persona. Rates are per 100 words."""
    prose = _prose(text)
    words = _WORD.findall(prose)
    n = len(words) or 1
    sentences = max(1, len(_SENTENCE_END.findall(prose)))
    similes = len(_SIMILE.findall(prose))
    first = len(_FIRST_PERSON.findall(prose))
    noir = sum(w.lower() in NOIR_WORDS for w in words)
    evidence = evidence_section(text)
    ev_words = [w.lower() for w in _WORD.findall(evidence)]
    leak = len(_SIMILE.findall(evidence)) + sum(w in NOIR_WORDS for w in ev_words)
    return {
        "words": float(len(words)),
        "mean_sentence_words": round(len(words) / sentences, 1),
        "similes_per_100w": round(100 * similes / n, 2),
        "first_person_per_100w": round(100 * first / n, 2),
        "noir_words_per_100w": round(100 * noir / n, 2),
        # One number to plot against the slider: the three style rates summed.
        "voice_score": round(100 * (similes + first + noir) / n, 2),
        "evidence_leaks": float(leak),
    }


# --- Statistics ----------------------------------------------------------------


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion.

    Preferred over the textbook p ± z·sqrt(p(1-p)/n) because that one collapses
    to [1, 1] at 5 out of 5, which claims certainty that 5 questions can't give.
    """
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


# --- Scoring one answer --------------------------------------------------------


def score_answer(question: BenchmarkQuestion, answer: Any, facts: dict[str, str]) -> dict[str, Any]:
    """One row of benchmark results for an ``Answer`` from ``Analyst.ask``."""
    v = answer.verification
    needed = [m.format(**facts) for m in question.must_mention]
    text_lower = answer.text.lower()
    if question.kind == "general":
        # Right if it kept the label and so was recognised as general guidance.
        correct = v.status == "general"
    elif question.kind == "absent":
        correct = v.passed and bool(v.reported_absent)
    elif needed:
        correct = all(m.lower() in text_lower for m in needed)
    else:
        correct = None  # no known answer to check against; left out of the rate
    # A general question has nothing to ground; count it as passing grounding
    # if it was recognised as general, so all levels are scored on all questions.
    ok_status = ("verified", "general") if question.kind == "general" else ("verified",)
    return {
        "kind": question.kind,
        "question": question.text,
        "tool_calls": len(answer.tool_calls),
        "fetched_raw_lines": any(c.name == "get_log_lines" for c in answer.tool_calls),
        "saw_raw_evidence": answer.saw_raw_evidence,
        # A general answer never "passes" (it has nothing to cite); on the first
        # try it is right if it came back as general without needing a retry.
        "first_attempt_grounded": (
            v.status == "general" and answer.retries == 0
            if question.kind == "general"
            else answer.first_attempt_passed
        ),
        "retries": answer.retries,
        "grounded": v.status in ok_status,
        "grounding_status": v.status,
        "correct": correct,
        "cited_lines": len(v.cited_lines),
        "hit_step_limit": answer.hit_step_limit,
        "tools_used": " > ".join(c.name for c in answer.tool_calls),
        "grounding": v.summary(),
        **voice_metrics(answer.text),
    }


# --- Running and summarising ---------------------------------------------------


@dataclass
class PersonaBenchmark:
    """Ask every question at every slider level, with a fresh Analyst each time.

    ``make_analyst(level)`` returns a new ``Analyst`` for that level. Keeping
    construction outside lets the same code run against Ollama (the script) or
    a scripted fake client (the tests).
    """

    make_analyst: Callable[[int], Any]
    facts: dict[str, str]
    questions: Iterable[BenchmarkQuestion] = QUESTIONS
    on_row: Callable[[dict[str, Any]], None] | None = None
    rows: list[dict[str, Any]] = field(default_factory=list)
    # (model, level, repeat, question) already answered, e.g. by an earlier run
    # that was stopped. They are skipped, so a long run can be resumed.
    done: set[tuple[Any, int, int, str]] = field(default_factory=set)

    def run(self, levels: Iterable[int], repeats: int = 1, **extra: Any) -> pd.DataFrame:
        import time

        for level in levels:
            for repeat in range(repeats):
                for q in self.questions:
                    if (extra.get("model"), level, repeat, q.text) in self.done:
                        continue
                    base = {**extra, "persona_level": level, "repeat": repeat}
                    analyst = self.make_analyst(level)
                    start = time.perf_counter()
                    try:
                        answer = analyst.ask(q.text)
                    except Exception as exc:  # report and carry on
                        row = {**base, "kind": q.kind, "question": q.text, "error": str(exc)}
                    else:
                        row = {
                            **base,
                            "seconds": round(time.perf_counter() - start, 1),
                            **score_answer(q, answer, self.facts),
                            "error": "",
                        }
                    self.rows.append(row)
                    if self.on_row:
                        self.on_row(row)
        return pd.DataFrame(self.rows)


def done_keys(df: pd.DataFrame) -> set[tuple[Any, int, int, str]]:
    """The answers in an earlier results table that need not be asked again.

    Rows that errored (a timeout, say) are not counted as done, so a resumed
    run asks them again.
    """
    if df.empty:
        return set()
    ok = df[df["error"].fillna("") == ""]
    return {
        (r.model, int(r.persona_level), int(r.repeat), r.question)
        for r in ok.itertuples(index=False)
    }


def rows_from_audit(
    path: str | Path,
    facts: dict[str, str],
    questions: Iterable[BenchmarkQuestion] = QUESTIONS,
    since: str | None = None,
) -> pd.DataFrame:
    """Rebuild benchmark rows from the audit log, without asking the model again.

    The audit log is written after every answer, so this recovers a run that
    was stopped before it saved its results table. It keeps records that have
    a ``persona_level`` (written since the slider), match a benchmark question
    and, if ``since`` is given (ISO time, UTC), were written at or after it.
    Where a question was answered more than once at a level, the latest answer
    wins. Latency is not in the audit log, so ``seconds`` is left empty.
    """
    from marlowe.assistant.agent import Answer, ToolCallRecord, Verification

    by_text = {q.text: q for q in questions}
    latest: dict[tuple[str, int, str], dict[str, Any]] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if "persona_level" not in rec or rec.get("question") not in by_text:
            continue
        if since and rec.get("time_utc", "") < since:
            continue
        latest[(rec["model"], rec["persona_level"], rec["question"])] = rec

    rows = []
    for (model, level, text), rec in latest.items():
        verification = Verification(**rec["grounding"])
        answer = Answer(
            question=text,
            text=rec["answer"],
            tool_calls=[ToolCallRecord(**c) for c in rec["tool_calls"]],
            verification=verification,
            model=model,
            steps=0,
            hit_step_limit=rec["answer"].startswith("I stopped after reaching the tool-call"),
            retries=rec["retries"],
            first_attempt_passed=rec["first_attempt_passed"],
            saw_raw_evidence=rec["saw_raw_evidence"],
        )
        rows.append(
            {
                "model": model,
                "persona_level": level,
                "repeat": 0,
                "seconds": float("nan"),
                **score_answer(by_text[text], answer, facts),
                "error": "",
            }
        )
    order = {q.text: i for i, q in enumerate(by_text.values())}
    df = pd.DataFrame(rows)
    if not df.empty:
        df["_order"] = df["question"].map(order)
        df = df.sort_values(["model", "persona_level", "_order"]).drop(columns="_order")
    return df.reset_index(drop=True)


def summarise_by_level(df: pd.DataFrame, by: tuple[str, ...] = ("persona_level",)) -> pd.DataFrame:
    """Per-level rates with Wilson intervals, plus the voice measures."""
    ok = df[df["error"] == ""].copy()
    out = []
    for key, g in ok.groupby(list(by)):
        key = key if isinstance(key, tuple) else (key,)
        row: dict[str, Any] = dict(zip(by, key, strict=True))
        row["n"] = len(g)
        for col in ("first_attempt_grounded", "grounded", "correct"):
            scored = g[col].dropna().astype(bool)
            k, n = int(scored.sum()), len(scored)
            lo, hi = wilson_interval(k, n)
            row[col] = round(k / n, 2) if n else float("nan")
            row[f"{col}_ci"] = f"{lo:.2f}-{hi:.2f}"
        row["median_seconds"] = g["seconds"].median()
        row["mean_tool_calls"] = round(g["tool_calls"].mean(), 2)
        for col in ("voice_score", "similes_per_100w", "first_person_per_100w", "words"):
            row[f"mean_{col}"] = round(g[col].mean(), 2)
        row["evidence_leaks"] = int(g["evidence_leaks"].sum())
        out.append(row)
    errors = df.groupby(list(by))["error"].apply(lambda e: int((e != "").sum())).reset_index()
    errors = errors.rename(columns={"error": "errors"})
    if not out:  # every answer errored
        return errors
    return pd.DataFrame(out).merge(errors, on=list(by), how="right")
