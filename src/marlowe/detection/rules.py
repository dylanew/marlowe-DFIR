"""Transparent rule baseline.

Why start with rules?
    A baseline tells us whether ML adds anything. If four readable rules
    already catch every attack with few false positives, an Isolation Forest
    is extra complexity for no gain, and we should say so. Rules are also
    what a SOC analyst would write first, and every flag comes with a
    human-readable reason.

The thresholds come from common SSH-hardening guidance (e.g. fail2ban's
default of 5 failures, raised to 10 for a 10-minute window) and were fixed
*before* looking at evaluation results, to avoid tuning on the test set.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    predicate: Callable[[pd.DataFrame], pd.Series]


RULES = [
    Rule(
        "brute_force",
        ">= 10 failed passwords from one IP in a window",
        lambda w: w["n_failed"] >= 10,
    ),
    Rule(
        "password_spray",
        ">= 5 distinct usernames from one IP in a window, mostly failing",
        lambda w: (w["n_distinct_users"] >= 5) & (w["failure_ratio"] >= 0.8),
    ),
    Rule(
        "success_after_failures",
        "a successful login after >= 3 failures from the same IP in a window",
        lambda w: (w["success_after_failure"] == 1) & (w["n_failed"] >= 3),
    ),
    Rule(
        "off_hours_new_source",
        "an off-hours successful login for a user from an IP they have never used",
        lambda w: (w["n_success_off_hours"] >= 1) & (w["n_new_user_ip_success"] >= 1),
    ),
]


def apply_rules(windows: pd.DataFrame, rules: list[Rule] = RULES) -> pd.DataFrame:
    """Return ``windows`` with one boolean column per rule, ``rule_flag`` and ``rule_reasons``."""
    out = windows.copy()
    names = []
    for rule in rules:
        col = f"rule_{rule.name}"
        out[col] = rule.predicate(out).astype(bool)
        names.append((col, rule))
    out["rule_flag"] = out[[c for c, _ in names]].any(axis=1)
    out["rule_reasons"] = out.apply(
        lambda row: "; ".join(r.description for c, r in names if row[c]), axis=1
    )
    return out
