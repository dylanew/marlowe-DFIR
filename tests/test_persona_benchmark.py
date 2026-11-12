"""The personality-slider benchmark: voice measures, statistics and a full offline run."""

import json
import math

import pandas as pd
import pytest

from marlowe.assistant import AnalysisTools, Analyst
from marlowe.assistant.prompts import PERSONA_LEVELS
from marlowe.evaluation.persona import (
    ABSENT_IP,
    QUESTIONS,
    PersonaBenchmark,
    done_keys,
    evidence_section,
    rows_from_audit,
    summarise_by_level,
    voice_metrics,
    wilson_interval,
)

PLAIN = """203.0.113.62 ran a brute force against root and then logged in.

**Evidence**:
- 130 failed passwords from 203.0.113.62 [lines 1309-1311]
- Accepted password for root [line 1553]

**What I'd do next**: reset the root password and check other hosts."""

NOIR = """I've seen this kind of thing before. 203.0.113.62 came at root like a drunk \
at a locked door, all night, in the rain, and then the door opened. My bourbon went cold.

**Evidence**:
- 130 failed passwords from 203.0.113.62 [lines 1309-1311]
- Accepted password for root [line 1553]

**What it means**: the kind of luck that's as cheap as a two-bit cigar. I'd call it a compromise."""


def test_evidence_section_is_the_text_under_its_heading():
    section = evidence_section(PLAIN)
    assert "[lines 1309-1311]" in section and "[line 1553]" in section
    assert "reset the root password" not in section
    assert evidence_section("No headings at all.") == ""


def test_voice_metrics_separate_plain_from_noir():
    plain, noir = voice_metrics(PLAIN), voice_metrics(NOIR)
    assert plain["similes_per_100w"] == 0
    assert plain["first_person_per_100w"] == 0  # the "What I'd do next" heading isn't voice
    assert plain["noir_words_per_100w"] == 0
    assert noir["similes_per_100w"] > 0  # "like a drunk", "as cheap as a"
    assert noir["first_person_per_100w"] > 0
    assert noir["noir_words_per_100w"] > 0  # rain, bourbon
    assert noir["voice_score"] > plain["voice_score"]
    assert plain["evidence_leaks"] == noir["evidence_leaks"] == 0


def test_plain_analysis_phrasing_is_not_counted_as_a_simile():
    text = "This looks like a brute force. It seems like a password spray. It ran at night."
    m = voice_metrics(text)
    assert m["similes_per_100w"] == 0
    assert m["noir_words_per_100w"] == 0  # "night" is ordinary in off-hours findings


def test_figurative_language_in_the_evidence_section_is_a_leak():
    leaky = PLAIN.replace("[line 1553]", "[line 1553], as slick as a wet alley")
    assert voice_metrics(leaky)["evidence_leaks"] == 2  # a simile and "alley"


def test_wilson_interval():
    lo, hi = wilson_interval(5, 5)
    assert hi == 1.0 and 0.5 < lo < 0.6  # 5 of 5 is not proof of 100%
    lo, hi = wilson_interval(0, 5)
    assert lo == 0.0 and 0.4 < hi < 0.5
    lo, hi = wilson_interval(50, 100)
    assert math.isclose(lo, 0.404, abs_tol=0.001) and math.isclose(hi, 0.596, abs_tol=0.001)
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_question_set_covers_each_kind():
    kinds = [q.kind for q in QUESTIONS]
    assert kinds.count("general") == 1 and kinds.count("absent") == 1
    assert any("{top_user}" in m for q in QUESTIONS for m in q.must_mention)


class VoicedFakeLLM:
    """A stand-in model whose voice follows the slider level in its system prompt.

    It looks up F1, then answers with real citations. At ``break_at`` and above it
    also invents a timestamp "for atmosphere", which the grounding check should
    catch, so the benchmark has a real cost to detect.
    """

    model = "fake-voiced"

    def __init__(self, level, analysis, break_at=4):
        self.level, self.break_at = level, break_at
        tools = AnalysisTools(analysis)
        f1 = tools.get_finding("F1")
        self.ip, self.first = f1["src_ip"], f1["line_nos"][0]
        self.login = tools.successful_logins(self.ip)[0]["line_no"]

    def chat(self, messages, tools=None):
        question = next(m["content"] for m in messages if m["role"] == "user")
        if "password spray" in question:
            return final("A spray tries one password on many accounts. " + GENERAL)
        if messages[-1]["role"] != "tool":
            if ABSENT_IP in question:
                return tool_call("ip_activity", src_ip=ABSENT_IP)
            return tool_call("get_finding", finding_id="F1")
        if ABSENT_IP in question:
            return final(f"{ABSENT_IP} does not appear in the evidence.")
        colour = " It came at root like a drunk at a locked door, in the rain." * self.level
        invented = " The rain stopped at 2026-10-14T23:59." if self.level >= self.break_at else ""
        return final(
            f"{self.ip} brute-forced root and logged in.{colour}{invented}\n\n"
            f"**Evidence**:\n- failures [lines {self.first}-{self.first + 2}]\n"
            f"- logged in as root [line {self.login}]"
        )


GENERAL = "General guidance, not drawn from this evidence."


def tool_call(name, **arguments):
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": arguments}}],
    }


def final(text):
    return {"role": "assistant", "content": text}


@pytest.fixture
def bench(analysis):
    tools = AnalysisTools(analysis)
    ip = tools.findings.iloc[0]["src_ip"]
    facts = {"top_ip": ip, "top_user": tools.successful_logins(ip)[0]["user"]}

    def make_analyst(level):
        return Analyst(VoicedFakeLLM(level, analysis), AnalysisTools(analysis), persona=level)

    return PersonaBenchmark(make_analyst, facts)


def test_benchmark_detects_a_grounding_cost_at_the_top_of_the_slider(bench):
    df = bench.run(PERSONA_LEVELS, model="fake")
    assert len(df) == len(PERSONA_LEVELS) * len(QUESTIONS)
    assert (df["error"] == "").all()
    summary = summarise_by_level(df).set_index("persona_level")

    # Levels 0-3: every answer grounded and every checked fact right.
    assert (summary.loc[0:3, "grounded"] == 1.0).all()
    assert (summary.loc[0:3, "correct"] == 1.0).all()
    # Level 4 invents a timestamp in the evidence questions, which the check catches.
    assert summary.loc[4, "grounded"] < 1.0
    assert summary.loc[4, "first_attempt_grounded"] < summary.loc[3, "first_attempt_grounded"]
    # The general and absent questions stay right at every level.
    special = df[df["kind"].isin(["general", "absent"])]
    assert special["grounded"].all() and special["correct"].all()
    # The voice measure rises with the slider (this is what makes "no cost" meaningful).
    voice = summary["mean_voice_score"]
    assert voice.is_monotonic_increasing and voice[0] == 0 < voice[4]
    assert summary["evidence_leaks"].sum() == 0
    assert summary["errors"].sum() == 0
    lo, hi = (float(x) for x in summary.loc[0, "grounded_ci"].split("-"))
    assert lo < 1.0 == hi


def test_benchmark_records_errors_and_carries_on(analysis):
    class Broken:
        model = "broken"

        def chat(self, messages, tools=None):
            raise RuntimeError("Ollama went away")

    bench = PersonaBenchmark(
        lambda level: Analyst(Broken(), AnalysisTools(analysis), persona=level),
        {"top_ip": "x", "top_user": "y"},
    )
    df = bench.run([0, 2])
    assert (df["error"] == "Ollama went away").all()
    summary = summarise_by_level(df)
    assert list(summary["errors"]) == [len(QUESTIONS)] * 2


def test_a_stopped_run_resumes_without_asking_again(analysis, bench):
    first = bench.run([0], model="fake")
    asked = []

    def make_analyst(level):
        asked.append(level)
        return Analyst(VoicedFakeLLM(level, analysis), AnalysisTools(analysis), persona=level)

    failed = first.copy()
    failed.loc[0, "error"] = "timed out"  # a timed-out answer is asked again
    resumed = PersonaBenchmark(make_analyst, bench.facts, done=done_keys(failed))
    df = resumed.run([0, 1], model="fake")
    assert asked == [0] + [1] * len(QUESTIONS)
    assert df.iloc[0]["question"] == QUESTIONS[0].text
    assert done_keys(pd.DataFrame()) == set()


def test_results_rebuilt_from_the_audit_log_match_the_live_run(analysis, tmp_path):
    audit = tmp_path / "audit.jsonl"
    tools = AnalysisTools(analysis)
    ip = tools.findings.iloc[0]["src_ip"]
    facts = {"top_ip": ip, "top_user": tools.successful_logins(ip)[0]["user"]}

    def make_analyst(level):
        return Analyst(
            VoicedFakeLLM(level, analysis), AnalysisTools(analysis), persona=level, audit_path=audit
        )

    live = PersonaBenchmark(make_analyst, facts).run([0, 4], model="fake-voiced")
    # An older record without persona_level (from before the slider) is ignored.
    with audit.open("a") as f:
        f.write(json.dumps({"model": "fake-voiced", "question": QUESTIONS[0].text}) + "\n")

    rebuilt = rows_from_audit(audit, facts)
    cols = ["persona_level", "question", "grounded", "first_attempt_grounded", "correct"]
    cols += ["voice_score", "evidence_leaks", "tool_calls", "retries"]
    pd.testing.assert_frame_equal(
        rebuilt[cols].reset_index(drop=True), live[cols].reset_index(drop=True), check_dtype=False
    )
    assert rebuilt["seconds"].isna().all()  # latency isn't in the audit log
    assert rows_from_audit(audit, facts, since="2999-01-01").empty
