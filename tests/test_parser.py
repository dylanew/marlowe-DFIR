import pandas as pd

from marlowe.parsers import COLUMNS, parse_auth_log, parse_lines

LINES = [
    "Oct  5 09:00:01 srv01 sshd[101]: Accepted password for alice from 10.0.1.20 port 50000 ssh2",
    "Oct  5 09:00:05 srv01 sshd[102]: Failed password for root from 203.0.113.5 port 40000 ssh2",
    "Oct  5 09:00:06 srv01 sshd[103]: Invalid user admin from 203.0.113.5 port 40001",
    "Oct  5 09:00:07 srv01 sshd[103]: Failed password for invalid user admin from 203.0.113.5 "
    "port 40001 ssh2",
    "Oct  5 09:00:08 srv01 sshd[104]: Accepted publickey for backup from 10.0.5.10 port 51000 ssh2",
    "Oct  5 09:00:09 srv01 sshd[101]: pam_unix(sshd:session): session opened for user "
    "alice(uid=1001) by (uid=0)",
    "Oct  5 09:30:00 srv01 sshd[101]: pam_unix(sshd:session): session closed for user alice",
    "Oct  5 09:31:00 srv01 sshd[105]: Received disconnect from 10.0.1.20 port 50000:11",
    "this line is garbage",
]


def test_schema_and_one_row_per_line():
    df = parse_lines(LINES, year=2026, evidence_id="abc123")
    assert list(df.columns) == COLUMNS
    assert len(df) == len(LINES)
    assert df["line_no"].tolist() == list(range(1, len(LINES) + 1))
    assert (df["evidence_id"] == "abc123").all()
    assert df["raw"].tolist() == LINES


def test_event_types():
    df = parse_lines(LINES, year=2026)
    assert df["event_type"].tolist() == [
        "auth_success",
        "auth_failure",
        "invalid_user",
        "auth_failure",
        "auth_success",
        "session_open",
        "session_close",
        "other",
        "unparsed",
    ]


def test_fields_extracted():
    df = parse_lines(LINES, year=2026)
    first = df.iloc[0]
    assert first["user"] == "alice"
    assert first["src_ip"] == "10.0.1.20"
    assert first["src_port"] == 50000
    assert first["auth_method"] == "password"
    assert first["pid"] == 101
    assert not first["invalid_user"]

    assert df.iloc[3]["user"] == "admin"
    assert df.iloc[3]["invalid_user"]
    assert df.iloc[4]["auth_method"] == "publickey"
    assert df.iloc[5]["user"] == "alice"  # "(uid=1001)" stripped


def test_unparsed_line_is_kept_not_dropped():
    df = parse_lines(LINES, year=2026)
    bad = df.iloc[-1]
    assert bad["event_type"] == "unparsed"
    assert bad["raw"] == "this line is garbage"
    assert pd.isna(bad["timestamp_utc"])


def test_timezone_converted_to_utc_and_raw_kept():
    # 5 Oct 2026 is during British Summer Time (UTC+1).
    df = parse_lines(LINES[:1], year=2026, tz="Europe/London")
    assert df.iloc[0]["timestamp_utc"] == pd.Timestamp("2026-10-05 08:00:01", tz="UTC")
    assert df.iloc[0]["timestamp_raw"] == "Oct  5 09:00:01"


def test_year_rollover():
    lines = [
        "Dec 31 23:59:59 h sshd[1]: Invalid user a from 1.2.3.4",
        "Jan  1 00:00:01 h sshd[2]: Invalid user b from 1.2.3.4",
    ]
    df = parse_lines(lines, year=2025)
    assert df["timestamp_utc"].dt.year.tolist() == [2025, 2026]


def test_impossible_date_is_unparsed():
    df = parse_lines(["Feb 30 10:00:00 h sshd[1]: Invalid user a from 1.2.3.4"], year=2026)
    assert df.iloc[0]["event_type"] == "unparsed"


def test_parse_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(LINES) + "\n")
    df = parse_auth_log(path, year=2026)
    assert len(df) == len(LINES)
