"""Feature engineering: from individual auth events to (source IP, time window) rows.

Why aggregate at all?
    A single "Failed password" line tells you almost nothing. Forty of them
    from one address in ten minutes is a brute-force attack. Most SSH attacks
    are defined by *volume, variety and sequence* over a short period, so
    the unit we analyse is "everything one source IP did in one time window".

Why source IP rather than user?
    Brute force and password spraying are attacker-centric. The attacker has
    one (or a few) addresses and many target usernames, so grouping by IP
    makes the attack one dense row. User-centric (UEBA) features would be a
    natural next step and are noted in the roadmap.

Every window keeps ``line_nos``, the source lines it was built from, so any
flagged window can be traced straight back to the evidence.
"""

from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd

AUTH_EVENT_TYPES = ("auth_success", "auth_failure", "invalid_user")

# Features passed to statistical / ML models. Identifiers, timestamps and
# provenance columns are deliberately excluded.
MODEL_FEATURES = [
    "n_events",
    "n_failed",
    "n_success",
    "n_invalid_user",
    "n_distinct_users",
    "failure_ratio",
    "success_after_failure",
    "n_success_off_hours",
    "n_new_user_ip_success",
    "is_new_ip",
    "is_internal_ip",
    "hour_sin",
    "hour_cos",
]

COUNT_FEATURES = [
    "n_events",
    "n_failed",
    "n_success",
    "n_invalid_user",
    "n_distinct_users",
    "n_success_off_hours",
    "n_new_user_ip_success",
]


# What counts as "inside our network". This is deliberately explicit rather
# than using Python's ``ip_address(...).is_private``. That property also
# returns True for the IETF documentation ranges (e.g. 203.0.113.0/24) and
# other reserved blocks, so every external attacker in our synthetic data
# would be marked as internal. A real deployment would set this to the
# organisation's own address ranges.
DEFAULT_INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")


def _make_is_internal(networks: tuple[str, ...]):
    nets = [ipaddress.ip_network(n) for n in networks]

    def is_internal(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in nets)

    return is_internal


def build_ip_windows(
    events: pd.DataFrame,
    window: str = "10min",
    working_hours: tuple[int, int] = (7, 20),
    internal_networks: tuple[str, ...] = DEFAULT_INTERNAL_NETWORKS,
) -> pd.DataFrame:
    """Aggregate parsed auth events into one row per (src_ip, window_start).

    ``working_hours`` is (start, end) in UTC hours; successes outside it count
    as off-hours. History-based features (``is_new_ip``,
    ``n_new_user_ip_success``) only look *backwards* in time, so they never
    leak information from the future into the past.
    """
    auth = events[events["event_type"].isin(AUTH_EVENT_TYPES) & events["src_ip"].notna()].copy()
    auth = auth.sort_values(["timestamp_utc", "line_no"])

    auth["window_start"] = auth["timestamp_utc"].dt.floor(window)
    auth["is_failure"] = auth["event_type"] == "auth_failure"
    auth["is_success"] = auth["event_type"] == "auth_success"
    auth["is_invalid"] = auth["event_type"] == "invalid_user"
    hour = auth["timestamp_utc"].dt.hour
    auth["off_hours"] = (hour < working_hours[0]) | (hour >= working_hours[1])

    # A successful login for a (user, ip) pair never seen succeeding before.
    pair_first = ~auth.loc[auth["is_success"]].duplicated(["user", "src_ip"])
    auth["is_new_pair_success"] = False
    auth.loc[pair_first.index, "is_new_pair_success"] = pair_first

    auth["failure_ts"] = auth["timestamp_utc"].where(auth["is_failure"])
    auth["success_ts"] = auth["timestamp_utc"].where(auth["is_success"])

    grouped = auth.groupby(["src_ip", "window_start"], sort=False)
    windows = grouped.agg(
        first_seen=("timestamp_utc", "min"),
        last_seen=("timestamp_utc", "max"),
        n_events=("event_type", "size"),
        n_failed=("is_failure", "sum"),
        n_success=("is_success", "sum"),
        n_invalid_user=("is_invalid", "sum"),
        n_distinct_users=("user", "nunique"),
        n_new_user_ip_success=("is_new_pair_success", "sum"),
        first_failure=("failure_ts", "min"),
        last_success=("success_ts", "max"),
        line_nos=("line_no", list),
        evidence_id=("evidence_id", "first"),
    ).reset_index()

    off_hours_success = (
        auth[auth["is_success"] & auth["off_hours"]]
        .groupby(["src_ip", "window_start"])
        .size()
        .rename("n_success_off_hours")
    )
    windows = windows.merge(off_hours_success, on=["src_ip", "window_start"], how="left")
    windows["n_success_off_hours"] = windows["n_success_off_hours"].fillna(0)

    attempts = windows["n_failed"] + windows["n_success"]
    windows["failure_ratio"] = np.where(
        attempts > 0, windows["n_failed"] / attempts.clip(lower=1), 0
    )
    windows["success_after_failure"] = (
        windows["last_success"].notna()
        & windows["first_failure"].notna()
        & (windows["last_success"] > windows["first_failure"])
    ).astype(int)

    windows = windows.sort_values(["window_start", "src_ip"]).reset_index(drop=True)
    windows["is_new_ip"] = (~windows.duplicated("src_ip")).astype(int)
    windows["is_internal_ip"] = (
        windows["src_ip"].map(_make_is_internal(internal_networks)).astype(int)
    )

    # Encode hour of day on a circle so 23:00 and 01:00 are close together.
    hours = windows["window_start"].dt.hour + windows["window_start"].dt.minute / 60
    windows["hour_sin"] = np.sin(2 * np.pi * hours / 24)
    windows["hour_cos"] = np.cos(2 * np.pi * hours / 24)

    for col in COUNT_FEATURES:
        windows[col] = windows[col].astype(int)

    return windows.drop(columns=["first_failure", "last_success"])


def attach_labels(windows: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Add ground truth to windows: a window is an attack if any of its lines is.

    Only used for evaluation. Detectors never see these columns.
    """
    attack_lines = labels.loc[labels["is_attack"] == 1].set_index("line_no")["attack_id"]
    lookup = attack_lines.to_dict()

    def ids_for(line_nos: list[int]) -> str:
        ids = sorted({lookup[n] for n in line_nos if n in lookup})
        return ",".join(ids)

    out = windows.copy()
    out["attack_ids"] = out["line_nos"].map(ids_for)
    out["is_attack"] = (out["attack_ids"] != "").astype(int)
    return out
