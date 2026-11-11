"""Parser for Linux ``auth.log`` / ``secure`` files (OpenSSH and PAM messages).

Output is one row per input line in a fixed schema (see ``COLUMNS``). Some
deliberate choices:

* **Every line becomes a row, including lines we don't understand.** Those
  get ``event_type == "unparsed"``. Silently dropping input is a classic way
  for a forensic tool to hide evidence; this way the gaps are countable.
* **Provenance on every row:** ``evidence_id`` (from the evidence manifest)
  and ``line_no`` (1-based) let any finding be traced to the exact line.
* **The original text is kept** in ``raw`` and the original timestamp in
  ``timestamp_raw``. Normalised values sit alongside, never replace them.
* **Timestamps are normalised to UTC.** Syslog timestamps have no year and
  no timezone, so the caller must supply both. A year rollover (Dec -> Jan)
  is detected when the month goes backwards.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd

COLUMNS = [
    "evidence_id",
    "line_no",
    "timestamp_utc",
    "timestamp_raw",
    "host",
    "process",
    "pid",
    "event_type",
    "user",
    "src_ip",
    "src_port",
    "auth_method",
    "invalid_user",
    "raw",
]

# "Nov  3 09:15:02 srv01 sshd[1234]: message"
_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

# Order matters: more specific patterns first.
_MESSAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "auth_success",
        re.compile(
            r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        "auth_failure",
        re.compile(
            r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        "invalid_user",
        re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
    ),
    (
        "session_open",
        re.compile(r"^pam_unix\([\w\-]+:session\): session opened for user (?P<user>[^\s(]+)"),
    ),
    (
        "session_close",
        re.compile(r"^pam_unix\([\w\-]+:session\): session closed for user (?P<user>\S+)"),
    ),
]


def _parse_timestamp(raw: str, year: int, tz: ZoneInfo) -> datetime:
    local = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)
    return local.astimezone(ZoneInfo("UTC"))


def parse_lines(
    lines: Iterable[str],
    year: int,
    tz: str = "UTC",
    evidence_id: str = "",
) -> pd.DataFrame:
    """Parse auth.log lines into a DataFrame with the ``COLUMNS`` schema.

    ``year`` is the year of the *first* line; ``tz`` is the timezone the
    logging host's clock was set to (an IANA name such as "Europe/London").
    """
    zone = ZoneInfo(tz)
    rows = []
    current_year, last_month = year, None

    for line_no, line in enumerate(lines, start=1):
        line = line.rstrip("\n")
        row = dict.fromkeys(COLUMNS)
        row.update(evidence_id=evidence_id, line_no=line_no, raw=line, event_type="unparsed")

        header = _SYSLOG.match(line)
        if header is None:
            rows.append(row)
            continue

        ts_raw = re.sub(r"\s+", " ", header["ts"])
        try:
            month = datetime.strptime(ts_raw[:3], "%b").month
        except ValueError:
            rows.append(row)
            continue
        if last_month is not None and month < last_month:
            current_year += 1  # e.g. Dec 31 -> Jan 1
        last_month = month

        try:
            row["timestamp_utc"] = _parse_timestamp(ts_raw, current_year, zone)
        except ValueError:
            rows.append(row)  # e.g. "Feb 30": keep as unparsed rather than guess
            continue

        row.update(
            timestamp_raw=header["ts"],
            host=header["host"],
            process=header["process"],
            pid=int(header["pid"]) if header["pid"] else None,
            event_type="other",
        )

        msg = header["msg"]
        for event_type, pattern in _MESSAGE_PATTERNS:
            m = pattern.match(msg)
            if m is None:
                continue
            groups = m.groupdict()
            row["event_type"] = event_type
            row["user"] = groups.get("user")
            row["src_ip"] = groups.get("ip")
            row["src_port"] = int(groups["port"]) if groups.get("port") else None
            row["auth_method"] = groups.get("method")
            row["invalid_user"] = event_type == "invalid_user" or bool(groups.get("invalid"))
            break

        rows.append(row)

    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True)
    df["pid"] = df["pid"].astype("Int64")
    df["src_port"] = df["src_port"].astype("Int64")
    df["invalid_user"] = df["invalid_user"].astype("boolean")
    return df


def parse_auth_log(
    path: str | Path, year: int, tz: str = "UTC", evidence_id: str = ""
) -> pd.DataFrame:
    """Parse an auth.log file. The file is opened read-only."""
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, year=year, tz=tz, evidence_id=evidence_id)
