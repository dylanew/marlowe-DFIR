import pandas as pd

from marlowe.features import attach_labels, build_ip_windows
from marlowe.parsers import parse_lines


def _events(lines):
    return parse_lines(lines, year=2026, evidence_id="ev1")


BRUTE = [
    f"Oct  5 10:0{i // 6}:{(i % 6) * 10:02d} h sshd[1]: Failed password for root from "
    f"203.0.113.5 port {40000 + i} ssh2"
    for i in range(12)
] + ["Oct  5 10:02:30 h sshd[2]: Accepted password for root from 203.0.113.5 port 41000 ssh2"]


def test_counts_for_one_window():
    w = build_ip_windows(_events(BRUTE))
    assert len(w) == 1
    row = w.iloc[0]
    assert row["src_ip"] == "203.0.113.5"
    assert row["n_failed"] == 12
    assert row["n_success"] == 1
    assert row["n_distinct_users"] == 1
    assert row["failure_ratio"] == 12 / 13
    assert row["success_after_failure"] == 1
    assert row["is_internal_ip"] == 0
    assert row["line_nos"] == list(range(1, 14))
    assert row["evidence_id"] == "ev1"


def test_windows_split_by_ip_and_time():
    lines = [
        "Oct  5 10:00:00 h sshd[1]: Failed password for a from 10.0.0.1 port 1 ssh2",
        "Oct  5 10:01:00 h sshd[1]: Failed password for a from 10.0.0.2 port 1 ssh2",
        "Oct  5 10:15:00 h sshd[1]: Failed password for a from 10.0.0.1 port 1 ssh2",
    ]
    w = build_ip_windows(_events(lines))
    assert len(w) == 3
    assert w["is_internal_ip"].tolist() == [1, 1, 1]


def test_non_auth_events_ignored():
    lines = [
        "Oct  5 10:00:00 h CRON[1]: pam_unix(cron:session): session opened for user root(uid=0)",
        "Oct  5 10:00:01 h sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2",
    ]
    w = build_ip_windows(_events(lines))
    assert w["n_events"].tolist() == [1]


def test_history_features_only_look_backwards():
    lines = [
        "Oct  5 03:00:00 h sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2",
        "Oct  6 03:00:00 h sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2",
    ]
    w = build_ip_windows(_events(lines))
    assert w["is_new_ip"].tolist() == [1, 0]
    assert w["n_new_user_ip_success"].tolist() == [1, 0]
    assert w["n_success_off_hours"].tolist() == [1, 1]


def test_attach_labels():
    w = build_ip_windows(_events(BRUTE))
    labels = pd.DataFrame(
        {
            "line_no": range(1, 14),
            "is_attack": [1] * 13,
            "attack_type": ["brute_force"] * 13,
            "attack_id": ["A01"] * 13,
        }
    )
    out = attach_labels(w, labels)
    assert out["is_attack"].tolist() == [1]
    assert out["attack_ids"].tolist() == ["A01"]
    assert "is_attack" not in w  # original untouched
