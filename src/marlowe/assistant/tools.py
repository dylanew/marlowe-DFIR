"""The only things the LLM is allowed to do: read-only queries over computed results.

Design principle: **the LLM explains; deterministic code computes.**

The model never sees the whole log, never runs code, and never touches the
filesystem. It can only call the functions registered here. Each one:

* is **read-only**: it reads an ``AnalysisResult`` that was already computed;
* returns **small, bounded JSON**, which keeps the context window under
  control on a 16 GB laptop;
* includes **evidence references** (``evidence_id`` + ``line_nos``), so every
  claim can be checked;
* **never exposes ground-truth labels.** On synthetic data the labels exist
  for evaluation, but an analyst wouldn't have them, so neither does the model.

Raw log text is returned under an ``untrusted_log_lines`` key. Log content is
attacker-controllable (a username can be any string), so the model is told
to treat it as data, never as instructions (see ``prompts.py``).
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pandas as pd

from marlowe.detection.rules import RULES
from marlowe.pipeline import AnalysisResult

MAX_LINES = 40
MAX_FINDINGS = 25
SAMPLE_LINES = 7


class ToolError(Exception):
    """An expected problem with a tool call (bad ID, unknown IP...), reported to the model.

    Anything else is a bug in our code and is allowed to raise, so it can't
    hide behind an innocent-looking "error" message to the model.

    ``details`` makes the error *recoverable*. Benchmarking showed that a small
    model which guesses an IP (e.g. 192.168.1.100) and gets a bare "not found"
    will conclude there is no attack. So errors return the real candidates and
    the next tool to call.
    """

    def __init__(self, message: str, **details: Any):
        super().__init__(message)
        self.details = details


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    func: Callable[..., dict[str, Any]]

    def schema(self) -> dict[str, Any]:
        """Tool definition in the format Ollama (and OpenAI-style APIs) expect."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def _as_int(value: Any, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ToolError(f"{name} must be an integer, got {value!r}") from None


def _iso(ts: Any) -> str | None:
    return None if pd.isna(ts) else pd.Timestamp(ts).isoformat()


def _line_range(line_nos: list[int]) -> str:
    return f"{line_nos[0]}-{line_nos[-1]}" if len(line_nos) > 1 else str(line_nos[0])


class AnalysisTools:
    """Read-only tool functions bound to one completed analysis."""

    def __init__(self, result: AnalysisResult):
        self.result = result
        self.events = result.events.set_index("line_no", drop=False)
        # Stable finding IDs: F1 is the most anomalous flagged window.
        w = result.windows
        findings = w[w["rule_flag"] | w["if_flag"]]
        findings = findings.sort_values("if_score", ascending=False).reset_index(drop=True)
        findings.insert(0, "finding_id", [f"F{i + 1}" for i in range(len(findings))])
        self.findings = findings

        self.tools: dict[str, Tool] = {
            t.name: t
            for t in [
                Tool(
                    "get_overview",
                    "Summary of the evidence file and the analysis: hash, time range, "
                    "parsed event counts, detectors and number of findings. Call this first.",
                    {"type": "object", "properties": {}},
                    self.get_overview,
                ),
                Tool(
                    "list_findings",
                    "List flagged windows (one source IP in one 10-minute window), most "
                    "anomalous first, with the reasons each detector flagged them.",
                    {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "description": "max rows (<= 25)"},
                            "detector": {
                                "type": "string",
                                "enum": ["any", "rules", "isolation_forest"],
                            },
                        },
                    },
                    self.list_findings,
                ),
                Tool(
                    "get_finding",
                    "All features and detector explanations for one finding, by finding_id "
                    "(e.g. 'F1').",
                    {
                        "type": "object",
                        "properties": {"finding_id": {"type": "string"}},
                        "required": ["finding_id"],
                    },
                    self.get_finding,
                ),
                Tool(
                    "get_log_lines",
                    "Return raw log lines by line number range, so claims can be checked "
                    f"against the evidence. At most {MAX_LINES} lines.",
                    {
                        "type": "object",
                        "properties": {
                            "start_line": {"type": "integer"},
                            "end_line": {"type": "integer"},
                        },
                        "required": ["start_line"],
                    },
                    self.get_log_lines,
                ),
                Tool(
                    "ip_activity",
                    "Everything a source IP did across the whole log: event counts, "
                    "usernames tried, first/last seen and flagged windows.",
                    {
                        "type": "object",
                        "properties": {"src_ip": {"type": "string"}},
                        "required": ["src_ip"],
                    },
                    self.ip_activity,
                ),
                Tool(
                    "list_logins",
                    "Successful logins across ALL users, optionally only off-hours "
                    "(before 07:00 or from 20:00 UTC) and/or only from a source IP the "
                    "user had never logged in from before. Includes the raw log lines.",
                    {
                        "type": "object",
                        "properties": {
                            "off_hours_only": {"type": "boolean"},
                            "new_source_only": {"type": "boolean"},
                            "limit": {"type": "integer", "description": "max rows (<= 25)"},
                        },
                    },
                    self.list_logins,
                ),
                Tool(
                    "user_activity",
                    "Login history for one username: successes, failures, source IPs "
                    "and off-hours logins.",
                    {
                        "type": "object",
                        "properties": {"user": {"type": "string"}},
                        "required": ["user"],
                    },
                    self.user_activity,
                ),
            ]
        }

    # ------------------------------------------------------------------ dispatch

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self.tools.values()]

    def call(self, name: str, arguments: dict[str, Any] | str | None) -> str:
        """Run a tool by name and return JSON. Errors are returned, not raised,
        so the model can see what went wrong and try again."""
        if name not in self.tools:
            return json.dumps({"error": f"unknown tool '{name}'", "available": list(self.tools)})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments.strip() else {}
            except json.JSONDecodeError:
                return json.dumps({"error": "arguments were not valid JSON"})
        func = self.tools[name].func
        try:
            inspect.signature(func).bind(**(arguments or {}))
        except TypeError as exc:
            return json.dumps(
                {
                    "error": f"bad arguments for {name}: {exc}",
                    "valid_parameters": self.tools[name].parameters.get("properties", {}),
                    "available_tools": list(self.tools),
                    "hint": "Retry with only the valid parameters, or pick a tool that does "
                    "what you need (e.g. list_logins for logins across all users). Never "
                    "answer from a failed tool call.",
                },
                default=str,
            )
        try:
            return json.dumps(func(**(arguments or {})), default=str)
        except ToolError as exc:
            return json.dumps({"error": str(exc), **exc.details}, default=str)

    # --------------------------------------------------------------------- tools

    def get_overview(self) -> dict[str, Any]:
        r = self.result
        ts = r.events["timestamp_utc"]
        return {
            "evidence": {
                "evidence_id": r.evidence.evidence_id,
                "file_name": r.evidence.file_name,
                "sha256": r.evidence.sha256,
                "size_bytes": r.evidence.size_bytes,
            },
            "time_range_utc": [_iso(ts.min()), _iso(ts.max())],
            "total_lines": int(len(r.events)),
            "event_counts": {k: int(v) for k, v in r.parse_summary.items()},
            "analysis_window": "10 minutes per source IP",
            "detection_period_starts_utc": _iso(r.cutoff),
            "note": (
                "Detectors are trained on the period before detection_period_starts_utc "
                "and only report findings after it."
            ),
            "detectors": {
                "rules": {rule.name: rule.description for rule in RULES},
                "isolation_forest": "unsupervised anomaly score; higher = more unusual",
            },
            "n_findings": int(len(self.findings)),
        }

    def _finding_summary(self, row: pd.Series) -> dict[str, Any]:
        return {
            "finding_id": row["finding_id"],
            "src_ip": row["src_ip"],
            "window_start_utc": _iso(row["window_start"]),
            "n_events": int(row["n_events"]),
            "n_failed": int(row["n_failed"]),
            "n_success": int(row["n_success"]),
            "n_distinct_users": int(row["n_distinct_users"]),
            "flagged_by_rules": bool(row["rule_flag"]),
            "rule_reasons": row["rule_reasons"] or None,
            "flagged_by_isolation_forest": bool(row["if_flag"]),
            "anomaly_score": round(float(row["if_score"]), 3),
            "isolation_forest_reasons": row["if_reasons"] or None,
            "evidence_id": row["evidence_id"],
            "line_range": _line_range(row["line_nos"]),
        }

    def list_findings(self, limit: int = 10, detector: str = "any") -> dict[str, Any]:
        f = self.findings
        if detector == "rules":
            f = f[f["rule_flag"]]
        elif detector == "isolation_forest":
            f = f[f["if_flag"]]
        elif detector != "any":
            raise ToolError("detector must be 'any', 'rules' or 'isolation_forest'")
        limit = max(1, min(_as_int(limit, "limit"), MAX_FINDINGS))
        return {
            "total": int(len(f)),
            "returned": int(min(limit, len(f))),
            "findings": [self._finding_summary(row) for _, row in f.head(limit).iterrows()],
        }

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        match = self.findings[self.findings["finding_id"] == str(finding_id).strip().upper()]
        if match.empty:
            raise ToolError(f"no finding '{finding_id}'; ids run F1..F{len(self.findings)}")
        row = match.iloc[0]
        out = self._finding_summary(row)
        out["features"] = {c: round(float(row[c]), 3) for c in self.result.detector.features}
        out["line_nos"] = list(map(int, row["line_nos"]))[:MAX_LINES]
        out["sample_evidence"] = self._sample_evidence(row["line_nos"])
        return out

    def _sample_evidence(self, line_nos: list[int], max_lines: int = SAMPLE_LINES) -> dict:
        """A few representative raw lines, so the model sees the source without asking.

        Benchmarking showed that an 8B model rarely calls get_log_lines on its own,
        even when the prompt tells it to. Putting the evidence in front of it is
        more reliable than asking. We pick the first lines (how it started), any
        successful logins (usually the most important lines) and the last line.
        """
        line_nos = [int(n) for n in line_nos]
        rows = self.events.loc[line_nos]
        successes = rows.index[rows["event_type"] == "auth_success"].tolist()
        picked = line_nos[:3] + successes[:3] + line_nos[-1:]
        picked = sorted(dict.fromkeys(picked))[:max_lines]
        return {
            "note": f"{len(picked)} of {len(line_nos)} lines; use get_log_lines for more",
            "untrusted_log_lines": [
                {"line_no": n, "text": self.events.at[n, "raw"]} for n in picked
            ],
        }

    def get_log_lines(self, start_line: int, end_line: int | None = None) -> dict[str, Any]:
        start = _as_int(start_line, "start_line")
        end = _as_int(end_line, "end_line") if end_line is not None else start
        if end < start:
            start, end = end, start
        truncated = end - start + 1 > MAX_LINES
        end = min(end, start + MAX_LINES - 1)
        rows = self.events.loc[self.events.index.intersection(range(start, end + 1))]
        if rows.empty:
            raise ToolError(f"no lines in range {start}-{end}; file has {len(self.events)} lines")
        return {
            "evidence_id": self.result.evidence.evidence_id,
            "truncated_to_max_lines": truncated,
            "untrusted_log_lines": [
                {"line_no": int(n), "text": text} for n, text in rows["raw"].items()
            ],
        }

    def ip_activity(self, src_ip: str) -> dict[str, Any]:
        ev = self.events[self.events["src_ip"] == src_ip]
        if ev.empty:
            raise ToolError(
                f"IP {src_ip} does not appear in the log. Do not guess IP addresses.",
                flagged_ips=list(dict.fromkeys(self.findings["src_ip"]))[:15],
                hint="Call list_findings to see which IPs were flagged, then retry "
                "ip_activity with one of those.",
            )
        flagged = self.findings[self.findings["src_ip"] == src_ip]
        return {
            "src_ip": src_ip,
            "first_seen_utc": _iso(ev["timestamp_utc"].min()),
            "last_seen_utc": _iso(ev["timestamp_utc"].max()),
            "event_counts": {k: int(v) for k, v in ev["event_type"].value_counts().items()},
            "usernames_tried": sorted(ev["user"].dropna().unique().tolist())[:30],
            "successful_logins_as": sorted(
                ev.loc[ev["event_type"] == "auth_success", "user"].dropna().unique().tolist()
            ),
            "flagged_findings": flagged["finding_id"].tolist(),
            # Deliberately not "line_range": an IP's activity can span the whole
            # file, and the grounding check should only accept precise references.
            "first_line": int(ev["line_no"].min()),
            "last_line": int(ev["line_no"].max()),
            "sample_evidence": self._sample_evidence(ev["line_no"].tolist()),
        }

    def user_activity(self, user: str) -> dict[str, Any]:
        ev = self.events[
            (self.events["user"] == user)
            & self.events["event_type"].isin(["auth_success", "auth_failure", "invalid_user"])
        ]
        if ev.empty:
            raise ToolError(
                f"user '{user}' has no authentication events. Do not guess usernames.",
                known_users=sorted(
                    self.events.loc[self.events["event_type"] == "auth_success", "user"]
                    .dropna()
                    .unique()
                    .tolist()
                )[:30],
                hint="To find logins across all users (e.g. off-hours or from new "
                "addresses), call list_logins instead.",
            )
        succ = ev[ev["event_type"] == "auth_success"]
        hours = succ["timestamp_utc"].dt.hour
        return {
            "user": user,
            "n_successful_logins": int(len(succ)),
            "n_failed_attempts": int((ev["event_type"] != "auth_success").sum()),
            "source_ips": {k: int(v) for k, v in ev["src_ip"].value_counts().head(15).items()},
            "successful_login_hours_utc": {
                int(k): int(v) for k, v in hours.value_counts().sort_index().items()
            },
            "off_hours_successes": [
                {
                    "line_no": int(r["line_no"]),
                    "time_utc": _iso(r["timestamp_utc"]),
                    "src_ip": r["src_ip"],
                }
                for _, r in succ[(hours < 7) | (hours >= 20)].head(10).iterrows()
            ],
        }

    def list_logins(
        self, off_hours_only: Any = False, new_source_only: Any = False, limit: Any = 20
    ) -> dict[str, Any]:
        off_only, new_only = _as_bool(off_hours_only), _as_bool(new_source_only)
        limit = max(1, min(_as_int(limit, "limit"), MAX_FINDINGS))
        succ = self.events[self.events["event_type"] == "auth_success"].sort_index()
        hours = succ["timestamp_utc"].dt.hour
        off = (hours < 7) | (hours >= 20)
        new = ~succ.duplicated(["user", "src_ip"])
        mask = pd.Series(True, index=succ.index)
        if off_only:
            mask &= off
        if new_only:
            mask &= new
        rows = succ[mask]
        return {
            "filters": {"off_hours_only": off_only, "new_source_only": new_only},
            "total": int(len(rows)),
            "returned": int(min(limit, len(rows))),
            "note": (
                "'New source' means the first successful login for that user from that IP "
                "in this log, so every login on the log's first day counts as new."
            ),
            "logins": [
                {
                    "line_no": int(r["line_no"]),
                    "time_utc": _iso(r["timestamp_utc"]),
                    "user": r["user"],
                    "src_ip": r["src_ip"],
                    "off_hours": bool(off[i]),
                    "new_source": bool(new[i]),
                }
                for i, r in rows.head(limit).iterrows()
            ],
            "untrusted_log_lines": [
                {"line_no": int(r["line_no"]), "text": r["raw"]}
                for _, r in rows.head(limit).iterrows()
            ],
        }
