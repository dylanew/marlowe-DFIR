"""The analyst loop: question -> tool calls -> grounded answer -> verification.

How tool calling works
    1. We send the conversation plus the tool definitions to the model.
    2. Rather than answering, the model may reply with ``tool_calls``: the
       names and arguments of functions it wants run.
    3. *We* run them (only those in ``AnalysisTools``) and send the JSON
       results back as ``tool`` messages.
    4. Repeat until the model answers in text, or a step limit is hit.

The model never executes anything itself. It can only ask, and our code
decides.

After the answer, a deterministic **grounding check** verifies what can be
verified mechanically: cited line numbers must be ones the tools actually
returned, IP addresses must occur in the evidence, and any SHA-256 must be
the evidence hash. This doesn't prove the answer correct, but it catches the
most damaging failure, which is invented evidence. If the check fails, the
answer goes back to the model once with the specific problems (verify, then
retry), and both attempts are recorded in the audit log.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from marlowe.assistant.ollama import ChatClient
from marlowe.assistant.prompts import (
    PERSONA_LEVELS,
    PERSONA_VERSION,
    PROMPT_VERSION,
    resolve_persona_level,
    system_prompt,
)
from marlowe.assistant.tools import AnalysisTools

# Any mention of "line N" / "lines N-M, K", whatever brackets surround it.
# The prompt asks for [line N], but models often write (lines N-M) or plain
# prose. We verify every line number claimed, not just neatly formatted ones;
# a stricter format check would fail correct answers and miss nothing extra.
_RANGE = r"\d+(?:\s*[-–]\s*\d+)?"
_CITATION = re.compile(rf"\blines?\s+({_RANGE}(?:\s*(?:,|and|&)\s*{_RANGE})*)", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
# ISO-style timestamps, to the minute. Every one in an answer must have
# appeared in a tool result: a real answer turned a window starting 16:50
# into "between 16:50 and 17:40", and 17:40 came from nowhere.
_TIMESTAMP = re.compile(r"\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})")


def _timestamps(text: str) -> set[str]:
    return {f"{d}T{t}" for d, t in _TIMESTAMP.findall(text)}


_SUCCESS_WORDS = re.compile(
    r"logged in|log in|logins?\b|success|compromis|gained access|got in|accepted", re.IGNORECASE
)
_FINDING_REF = re.compile(r"\bF\d{1,3}\b")
# The prompt asks general answers to say so in these words. Requiring the
# label means an unlabelled, uncited claim ("It was a brute force attack.")
# still fails rather than slipping through as "general".
_GENERAL_LABEL = re.compile(r"\bgeneral guidance\b", re.IGNORECASE)

# A citation wider than this must sit inside one range a tool returned (a
# finding's window). Otherwise "[lines 1-539]" would pass simply because every
# line in it was seen somewhere, while pointing at nothing in particular.
# 40 matches the most get_log_lines returns at once.
MAX_CITATION_SPAN = 40

# Wording that reports an absence. Used only when a tool confirmed the absence,
# so an answer can't claim "nothing found" for something that is there.
_ABSENCE = re.compile(
    r"\b(?:not (?:appear|present|found|in the (?:log|evidence))|does(?: not|n't) appear|"
    r"no (?:record|trace|evidence|activity|events?|sign)|isn't in|is not in|never appears?)\b",
    re.IGNORECASE,
)


@dataclass
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result_chars: int


@dataclass
class Verification:
    cited_lines: list[int] = field(default_factory=list)
    unverified_lines: list[int] = field(default_factory=list)
    unknown_ips: list[str] = field(default_factory=list)
    wrong_hashes: list[str] = field(default_factory=list)
    has_citations: bool = False
    # Tool calls that returned an error, as "tool: message". An answer built
    # only on failed calls must not pass, however it is worded.
    tool_errors: list[str] = field(default_factory=list)
    no_successful_tool_result: bool = False
    # Citations wider than MAX_CITATION_SPAN that no tool returned as one range.
    too_wide_citations: list[str] = field(default_factory=list)
    # Values a tool confirmed are NOT in the evidence and the answer says so.
    reported_absent: list[str] = field(default_factory=list)
    # Flagged IPs the answer names without saying that they logged in.
    missed_logins: list[str] = field(default_factory=list)
    # Timestamps (to the minute) that no tool returned.
    unknown_times: list[str] = field(default_factory=list)
    # True if the answer is labelled as general guidance and names nothing
    # from the evidence (no citations, IPs, hashes or finding IDs).
    general: bool = False

    @property
    def absence_answer(self) -> bool:
        """An uncited answer whose point is that something isn't in the evidence."""
        return not self.has_citations and bool(self.reported_absent)

    @property
    def passed(self) -> bool:
        return (
            not self.no_successful_tool_result
            and (self.has_citations or self.absence_answer)
            and not self.unverified_lines
            and not self.too_wide_citations
            and not self.unknown_times
            and not self.missed_logins
            and not self.unknown_ips
            and not self.wrong_hashes
        )

    @property
    def status(self) -> str:
        """ "verified", "general" (makes no evidence claims) or "failed"."""
        if self.passed:
            return "verified"
        return "general" if self.general else "failed"

    def summary(self) -> str:
        if self.status == "general":
            return (
                "General answer: it names nothing from this evidence, so there was nothing "
                "to verify. Treat it as general guidance."
            )
        if self.passed and self.absence_answer:
            return (
                "Grounding check passed: the answer reports that "
                f"{', '.join(self.reported_absent)} is not in the evidence, as the tools confirmed."
            )
        if self.passed:
            return f"Grounding check passed: {len(self.cited_lines)} cited lines all verified."
        problems = []
        if self.no_successful_tool_result:
            problems.append("answered without any successful tool result")
        if not self.has_citations and not self.absence_answer:
            problems.append("no line citations")
        if self.too_wide_citations:
            problems.append(
                f"citations too wide to point at specific evidence: {self.too_wide_citations[:5]}"
            )
        if self.unverified_lines:
            problems.append(f"lines not returned by any tool: {self.unverified_lines[:10]}")
        if self.unknown_ips:
            problems.append(f"IPs not in the evidence: {self.unknown_ips}")
        if self.missed_logins:
            problems.append(
                "left out that an attacking IP logged in: " + "; ".join(self.missed_logins)
            )
        if self.unknown_times:
            problems.append(f"timestamps not returned by any tool: {self.unknown_times[:5]}")
        if self.wrong_hashes:
            problems.append("a SHA-256 that is not the evidence hash")
        return "Grounding check FAILED: " + "; ".join(problems)


@dataclass
class Answer:
    question: str
    text: str
    tool_calls: list[ToolCallRecord]
    verification: Verification
    model: str
    steps: int
    hit_step_limit: bool = False
    retries: int = 0
    first_attempt_passed: bool = True
    first_attempt_text: str = ""
    saw_raw_evidence: bool = False


def _parse_ranges(spec: str) -> list[tuple[int, int]]:
    """ "12-15, 20 and 31" -> [(12, 15), (20, 20), (31, 31)]."""
    ranges: list[tuple[int, int]] = []
    for part in re.split(r",|\band\b|&", spec):
        part = part.strip().replace("–", "-")
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                lo, hi = sorted((int(a), int(b)))
                ranges.append((lo, hi))
        elif part.isdigit():
            ranges.append((int(part), int(part)))
    return ranges


def _parse_line_refs(spec: str) -> list[int]:
    lines: list[int] = []
    for lo, hi in _parse_ranges(spec):
        lines.extend(range(lo, min(hi, lo + 5000) + 1))
    return lines


def _ranges_in_tool_output(payload: Any) -> set[tuple[int, int]]:
    """Every contiguous block a tool presented as one unit (a finding's lines)."""
    found: set[tuple[int, int]] = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key == "line_nos" and isinstance(value, list):
                nums = [v for v in value if isinstance(v, int)]
                if nums:
                    found.add((min(nums), max(nums)))
            elif key == "line_range" and isinstance(value, str):
                found.update(_parse_ranges(value))
            else:
                found |= _ranges_in_tool_output(value)
    elif isinstance(payload, list):
        for item in payload:
            found |= _ranges_in_tool_output(item)
    return found


def _lines_in_tool_output(payload: Any) -> set[int]:
    """Collect every line number a tool result mentioned (line_no, line_nos, line_range)."""
    found: set[int] = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key == "line_no" and isinstance(value, int):
                found.add(value)
            elif key == "line_nos" and isinstance(value, list):
                found.update(v for v in value if isinstance(v, int))
            elif key == "line_range" and isinstance(value, str):
                found.update(_parse_line_refs(value))
            else:
                found |= _lines_in_tool_output(value)
    elif isinstance(payload, list):
        for item in payload:
            found |= _lines_in_tool_output(item)
    return found


def _contains_raw_lines(payload: Any) -> bool:
    """True if a tool result included raw log text (any ``untrusted_log_lines`` list)."""
    if isinstance(payload, dict):
        if payload.get("untrusted_log_lines"):
            return True
        return any(_contains_raw_lines(v) for v in payload.values())
    if isinstance(payload, list):
        return any(_contains_raw_lines(v) for v in payload)
    return False


def _retry_message(v: Verification) -> str:
    msg = (
        "[Automated evidence check, not the investigator] Your previous answer failed "
        f"verification: {v.summary().removeprefix('Grounding check FAILED: ')}. "
    )
    if v.tool_errors:
        msg += (
            "These tool calls failed: "
            + "; ".join(v.tool_errors[:5])
            + ". A failed call is not evidence that something did not happen. Follow the "
            "hints in the errors and call the right tool BEFORE answering. "
        )
    if v.unverified_lines or (not v.has_citations and not v.tool_errors):
        msg += (
            "Totals from get_overview have no line numbers to cite. Look up the relevant "
            "findings with get_finding (and get_log_lines if needed) and cite those lines. "
        )
    if v.too_wide_citations:
        msg += (
            f"Cite the specific lines behind each claim (at most {MAX_CITATION_SPAN} per "
            "range, or one finding's own range), not one wide range. "
        )
    return msg + (
        "Then rewrite the answer. Cite the line numbers that tools returned, as [line N] "
        "or [lines N-M]. Remove any IP address, hash or line number that no tool returned."
    )


def verify_answer(
    text: str,
    tools: AnalysisTools,
    referenced_lines: set[int],
    tool_errors: list[str] | None = None,
    n_successful_tool_results: int | None = None,
    referenced_ranges: set[tuple[int, int]] | None = None,
    confirmed_absent: set[str] | None = None,
    seen_times: set[str] | None = None,
) -> Verification:
    v = Verification(tool_errors=list(tool_errors or []))
    v.no_successful_tool_result = n_successful_tool_results == 0
    blocks = referenced_ranges or set()
    for match in _CITATION.finditer(text):
        v.cited_lines.extend(_parse_line_refs(match.group(1)))
        for lo, hi in _parse_ranges(match.group(1)):
            wide = hi - lo + 1 > MAX_CITATION_SPAN
            if wide and not any(a <= lo and hi <= b for a, b in blocks):
                v.too_wide_citations.append(f"{lo}-{hi}")
    v.cited_lines = sorted(set(v.cited_lines))
    v.has_citations = bool(v.cited_lines)
    v.unverified_lines = [n for n in v.cited_lines if n not in referenced_lines]

    absent = confirmed_absent or set()
    if _ABSENCE.search(text):
        v.reported_absent = sorted(a for a in absent if a and a in text)

    # An IP a tool confirmed is absent may be named, to say it is absent.
    known_ips = set(tools.events["src_ip"].dropna().unique()) | absent
    v.unknown_ips = sorted({ip for ip in _IPV4.findall(text) if ip not in known_ips})
    # Completeness, for the single most important fact: a flagged IP that the
    # answer discusses and that logged in successfully. Two real answers about
    # the brute force said it "hadn't been very successful" when it got root.
    flagged = set(tools.findings["src_ip"])
    for ip in sorted({ip for ip in _IPV4.findall(text) if ip in flagged}):
        logins = tools.successful_logins(ip)
        users = sorted({x["user"] for x in logins})
        said = _SUCCESS_WORDS.search(text) and any(u in text for u in users)
        if logins and not said:
            v.missed_logins.append(
                f"{ip} logged in as {', '.join(users)} [line {logins[0]['line_no']}]"
            )

    if seen_times is not None:
        v.unknown_times = sorted(_timestamps(text) - seen_times)
    v.general = bool(_GENERAL_LABEL.search(text)) and not (
        v.has_citations
        or v.reported_absent
        or _IPV4.search(text)
        or _SHA256.search(text)
        or _FINDING_REF.search(text)
    )

    sha = tools.result.evidence.sha256.lower()
    v.wrong_hashes = sorted({h for h in _SHA256.findall(text) if h.lower() != sha})
    return v


class Analyst:
    def __init__(
        self,
        client: ChatClient,
        tools: AnalysisTools,
        max_steps: int = 8,
        max_retries: int = 1,
        audit_path: str | Path | None = None,
        persona: bool | int = False,
    ):
        self.client = client
        self.tools = tools
        self.max_steps = max_steps
        self.max_retries = max_retries
        self._saw_raw_evidence = False
        self._tool_errors: list[str] = []
        self._n_ok = 0
        self._n_ok_before = 0  # successful tool results from earlier questions
        self.audit_path = Path(audit_path) if audit_path else None
        # A personality-slider level, 0 (plain) to 4 (full noir). True/False
        # from the old on/off switch map to the default level and 0.
        self.persona_level = resolve_persona_level(persona)
        self.history: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt(self.persona_level)}
        ]
        self.referenced_lines: set[int] = set()
        self.referenced_ranges: set[tuple[int, int]] = set()
        self.confirmed_absent: set[str] = set()
        self._question = ""
        self.seen_times: set[str] = set()

    @property
    def persona(self) -> bool:
        """True if any persona is on (level 1 or above)."""
        return self.persona_level > 0

    def _run_tools_loop(self, records: list[ToolCallRecord]) -> tuple[str, int, bool]:
        """Let the model call tools until it answers in text. Returns (text, steps, hit_limit)."""
        steps = 0
        while True:
            steps += 1
            message = self.client.chat(self.history, tools=self.tools.schemas())
            message.pop("_metrics", None)
            calls = message.get("tool_calls") or []
            self.history.append(
                {
                    "role": "assistant",
                    "content": message.get("content", "") or "",
                    **({"tool_calls": calls} if calls else {}),
                }
            )
            if not calls:
                return message.get("content", "") or "", steps, False
            if steps >= self.max_steps:
                return (
                    "I stopped after reaching the tool-call limit without a final answer. "
                    "Try a narrower question.",
                    steps,
                    True,
                )
            for call in calls:
                fn = call.get("function", {})
                name, args = fn.get("name", ""), fn.get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args) if args.strip() else {}
                    except json.JSONDecodeError:
                        args = {"_unparseable": args}
                result = self.tools.call(name, args)
                self.seen_times |= _timestamps(result)
                try:
                    payload = json.loads(result)
                    if isinstance(payload, dict) and "error" in payload:
                        self._tool_errors.append(f"{name}: {payload['error']}")
                        # "Not in the evidence" is a real answer, not a failure, but
                        # only for something the investigator asked about. A value the
                        # model guessed (e.g. 192.168.1.100) proves nothing.
                        missing = str(payload.get("not_found") or "")
                        if missing and missing.lower() in self._question.lower():
                            self.confirmed_absent.add(missing)
                            self._n_ok += 1
                    else:
                        self._n_ok += 1
                    self.referenced_lines |= _lines_in_tool_output(payload)
                    self.referenced_ranges |= _ranges_in_tool_output(payload)
                    if _contains_raw_lines(payload):
                        self._saw_raw_evidence = True
                except json.JSONDecodeError:
                    pass
                records.append(ToolCallRecord(name, args, len(result)))
                self.history.append({"role": "tool", "tool_name": name, "content": result})

    def ask(self, question: str) -> Answer:
        self.history.append({"role": "user", "content": question})
        self._question = question
        records: list[ToolCallRecord] = []
        self._saw_raw_evidence = False
        self._tool_errors: list[str] = []
        self._n_ok = 0

        text, steps, hit_limit = self._run_tools_loop(records)
        verification = self._verify(text)
        first_passed, first_text, retries = verification.passed, text, 0

        # Verify, then retry: a failed grounding check goes back to the model
        # once, with the specific problems. The corrective note is labelled as
        # coming from the evidence checker, not from the investigator.
        # A general answer (nothing from the evidence) has nothing to fix.
        while verification.status == "failed" and not hit_limit and retries < self.max_retries:
            retries += 1
            self.history.append({"role": "user", "content": _retry_message(verification)})
            text, more_steps, hit_limit = self._run_tools_loop(records)
            steps += more_steps
            verification = self._verify(text)

        answer = Answer(
            question=question,
            text=text,
            tool_calls=records,
            verification=verification,
            model=self.client.model,
            steps=steps,
            hit_step_limit=hit_limit,
            retries=retries,
            first_attempt_passed=first_passed,
            first_attempt_text=first_text if retries else "",
            saw_raw_evidence=self._saw_raw_evidence,
        )
        self._audit(answer)
        self._n_ok_before += self._n_ok
        return answer

    def _verify(self, text: str) -> Verification:
        # Successful results from earlier questions in the conversation count too:
        # the model may legitimately answer a follow-up from what it already has.
        n_ok = self._n_ok + self._n_ok_before
        return verify_answer(
            text,
            self.tools,
            self.referenced_lines,
            self._tool_errors,
            n_ok,
            self.referenced_ranges,
            self.confirmed_absent,
            self.seen_times,
        )

    def _audit(self, answer: Answer) -> None:
        """Append-only record of what was asked, which tools ran and what was said."""
        if self.audit_path is None:
            return
        record = {
            "time_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "evidence_id": self.tools.result.evidence.evidence_id,
            "model": answer.model,
            "prompt_version": PROMPT_VERSION,
            "persona_version": PERSONA_VERSION if self.persona_level else None,
            "persona_level": self.persona_level,
            "persona_name": PERSONA_LEVELS[self.persona_level],
            "question": answer.question,
            "tool_calls": [asdict(c) for c in answer.tool_calls],
            "answer": answer.text,
            "retries": answer.retries,
            "first_attempt_passed": answer.first_attempt_passed,
            "first_attempt_answer": answer.first_attempt_text or None,
            "saw_raw_evidence": answer.saw_raw_evidence,
            "grounding_passed": answer.verification.passed,
            "grounding_status": answer.verification.status,
            "grounding": asdict(answer.verification),
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
