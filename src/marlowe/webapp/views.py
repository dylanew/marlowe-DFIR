"""Data preparation for the web app, kept free of Streamlit so it can be unit-tested.

The Streamlit script (``app.py``) should only lay out widgets and call these
functions. Anything that computes or reshapes data lives here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pandas as pd

from marlowe.pipeline import AnalysisResult

AUTH_TYPES = ["auth_success", "auth_failure", "invalid_user"]


def save_upload(data: bytes, name: str, upload_dir: str | Path) -> Path:
    """Store an uploaded file as a read-only evidence copy, named by its hash.

    Naming by content hash means uploading the same file twice reuses one
    copy, and an upload can never overwrite a different file.
    """
    digest = hashlib.sha256(data).hexdigest()[:12]
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(name).name)[:80]
    path = Path(upload_dir) / f"{digest}_{safe or 'upload.log'}"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o444)
    return path


def overview_stats(result: AnalysisResult) -> dict:
    ev = result.events
    ts = ev["timestamp_utc"]
    counts = ev["event_type"].value_counts()
    return {
        "lines": int(len(ev)),
        "unparsed": int(counts.get("unparsed", 0)),
        "start": ts.min(),
        "end": ts.max(),
        "source_ips": int(ev["src_ip"].nunique()),
        "users": int(ev.loc[ev["event_type"].isin(AUTH_TYPES), "user"].nunique()),
        "findings": int((result.windows["rule_flag"] | result.windows["if_flag"]).sum()),
        "event_counts": counts.rename_axis("event_type").reset_index(name="lines"),
    }


def findings_table(result: AnalysisResult) -> pd.DataFrame:
    """Flagged windows for display, most anomalous first, with stable F-numbers.

    Uses the same ordering as the assistant's tools, so "F1" means the same
    thing in the table and in Marlowe's answers.
    """
    w = result.windows
    f = w[w["rule_flag"] | w["if_flag"]].sort_values("if_score", ascending=False)
    f = f.reset_index(drop=True)
    detectors = f.apply(
        lambda r: " + ".join(
            name for name, on in (("rules", r["rule_flag"]), ("ML", r["if_flag"])) if on
        ),
        axis=1,
    )
    return pd.DataFrame(
        {
            "finding": [f"F{i + 1}" for i in range(len(f))],
            "source IP": f["src_ip"],
            "window (UTC)": f["window_start"].dt.strftime("%Y-%m-%d %H:%M"),
            "flagged by": detectors,
            "anomaly score": f["if_score"].round(3),
            "failed": f["n_failed"],
            "success": f["n_success"],
            "users tried": f["n_distinct_users"],
            "why (rules)": f["rule_reasons"],
            "why (model)": f["if_reasons"],
            "lines": f["line_nos"].map(lambda n: f"{n[0]}-{n[-1]}" if len(n) > 1 else str(n[0])),
        }
    )


def finding_lines(result: AnalysisResult, finding_index: int, max_lines: int = 40) -> pd.DataFrame:
    """Raw evidence lines behind one finding (0-based index into ``findings_table``)."""
    w = result.windows
    f = w[w["rule_flag"] | w["if_flag"]].sort_values("if_score", ascending=False)
    line_nos = list(f.iloc[finding_index]["line_nos"])[:max_lines]
    ev = result.events.set_index("line_no")
    return pd.DataFrame({"line": line_nos, "text": ev.loc[line_nos, "raw"].to_list()})


def hourly_activity(result: AnalysisResult) -> pd.DataFrame:
    """Authentication events per hour, split into successes and failures (long format)."""
    ev = result.events[result.events["event_type"].isin(AUTH_TYPES)].copy()
    ev["kind"] = ev["event_type"].map(
        lambda t: "success" if t == "auth_success" else "failure / invalid user"
    )
    hourly = ev.set_index("timestamp_utc").groupby("kind").resample("1h").size()
    return hourly.rename("events").reset_index()


def anomaly_scores(result: AnalysisResult) -> pd.DataFrame:
    """Every scored window in the detection period, for the anomaly-score timeline."""
    w = result.windows
    return pd.DataFrame(
        {
            "window_start": w["window_start"],
            "src_ip": w["src_ip"],
            "anomaly score": w["if_score"],
            "status": (w["rule_flag"] | w["if_flag"]).map({True: "flagged", False: "normal"}),
            "failed": w["n_failed"],
        }
    )
