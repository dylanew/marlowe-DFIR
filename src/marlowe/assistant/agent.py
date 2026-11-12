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
most damaging failure, which is invented evidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from marlowe.assistant.ollama import ChatClient
from marlowe.assistant.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from marlowe.assistant.tools import AnalysisTools

# Any mention of "line N" / "lines N-M, K", whatever brackets surround it.
# The prompt asks for [line N], but models often write (lines N-M) or plain
# prose. We verify every line number claimed, not just neatly formatted ones;
# a stricter format check would fail correct answers and miss nothing extra.
_RANGE = r"\d+(?:\s*[-–]\s*\d+)?"
_CITATION = re.compile(rf"\blines?\s+({_RANGE}(?:\s*(?:,|and|&)\s*{_RANGE})*)", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)


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

    @property
    def passed(self) -> bool:
        return (
            self.has_citations
            and not self.unverified_lines
            and not self.unknown_ips
            and not self.wrong_hashes
        )

    def summary(self) -> str:
        if self.passed:
            return f"Grounding check passed: {len(self.cited_lines)} cited lines all verified."
        problems = []
        if not self.has_citations:
            problems.append("no line citations")
        if self.unverified_lines:
            problems.append(f"lines not returned by any tool: {self.unverified_lines[:10]}")
        if self.unknown_ips:
            problems.append(f"IPs not in the evidence: {self.unknown_ips}")
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


def _parse_line_refs(spec: str) -> list[int]:
    lines: list[int] = []
    for part in re.split(r",|\band\b|&", spec):
        part = part.strip().replace("–", "-")
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                lo, hi = sorted((int(a), int(b)))
                lines.extend(range(lo, min(hi, lo + 5000) + 1))
        elif part.isdigit():
            lines.append(int(part))
    return lines


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


def verify_answer(text: str, tools: AnalysisTools, referenced_lines: set[int]) -> Verification:
    v = Verification()
    for match in _CITATION.finditer(text):
        v.cited_lines.extend(_parse_line_refs(match.group(1)))
    v.cited_lines = sorted(set(v.cited_lines))
    v.has_citations = bool(v.cited_lines)
    v.unverified_lines = [n for n in v.cited_lines if n not in referenced_lines]

    known_ips = set(tools.events["src_ip"].dropna().unique())
    v.unknown_ips = sorted({ip for ip in _IPV4.findall(text) if ip not in known_ips})

    sha = tools.result.evidence.sha256.lower()
    v.wrong_hashes = sorted({h for h in _SHA256.findall(text) if h.lower() != sha})
    return v


class Analyst:
    def __init__(
        self,
        client: ChatClient,
        tools: AnalysisTools,
        max_steps: int = 8,
        audit_path: str | Path | None = None,
    ):
        self.client = client
        self.tools = tools
        self.max_steps = max_steps
        self.audit_path = Path(audit_path) if audit_path else None
        self.history: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.referenced_lines: set[int] = set()

    def ask(self, question: str) -> Answer:
        self.history.append({"role": "user", "content": question})
        records: list[ToolCallRecord] = []
        text, steps, hit_limit = "", 0, False

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
                text = message.get("content", "") or ""
                break
            if steps >= self.max_steps:
                hit_limit = True
                text = (
                    "I stopped after reaching the tool-call limit without a final answer. "
                    "Try a narrower question."
                )
                break
            for call in calls:
                fn = call.get("function", {})
                name, args = fn.get("name", ""), fn.get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args) if args.strip() else {}
                    except json.JSONDecodeError:
                        args = {"_unparseable": args}
                result = self.tools.call(name, args)
                try:
                    self.referenced_lines |= _lines_in_tool_output(json.loads(result))
                except json.JSONDecodeError:
                    pass
                records.append(ToolCallRecord(name, args, len(result)))
                self.history.append({"role": "tool", "tool_name": name, "content": result})

        verification = verify_answer(text, self.tools, self.referenced_lines)
        answer = Answer(
            question=question,
            text=text,
            tool_calls=records,
            verification=verification,
            model=self.client.model,
            steps=steps,
            hit_step_limit=hit_limit,
        )
        self._audit(answer)
        return answer

    def _audit(self, answer: Answer) -> None:
        """Append-only record of what was asked, which tools ran and what was said."""
        if self.audit_path is None:
            return
        record = {
            "time_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "evidence_id": self.tools.result.evidence.evidence_id,
            "model": answer.model,
            "prompt_version": PROMPT_VERSION,
            "question": answer.question,
            "tool_calls": [asdict(c) for c in answer.tool_calls],
            "answer": answer.text,
            "grounding_passed": answer.verification.passed,
            "grounding": asdict(answer.verification),
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
