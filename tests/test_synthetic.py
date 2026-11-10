import pandas as pd

from marlowe.parsers import parse_lines
from marlowe.synthetic import generate_auth_log
from marlowe.synthetic.authlog import ATTACK_SCHEDULE


def test_same_seed_same_log():
    assert generate_auth_log(seed=1).lines() == generate_auth_log(seed=1).lines()
    assert generate_auth_log(seed=1).lines() != generate_auth_log(seed=2).lines()


def test_lines_are_time_ordered_and_all_parse():
    log = generate_auth_log()
    df = parse_lines(log.lines(), year=2026)
    assert (df["event_type"] != "unparsed").all()
    assert df["timestamp_utc"].is_monotonic_increasing


def test_every_scheduled_attack_is_present():
    log = generate_auth_log()
    ids = {e.attack_id for e in log.events if e.attack_id}
    assert ids == {f"A{n + 1:02d}" for n in range(len(ATTACK_SCHEDULE))}


def test_labels_align_with_lines(tmp_path):
    log = generate_auth_log(days=4)
    log.write(tmp_path / "auth.log", tmp_path / "labels.csv")
    lines = (tmp_path / "auth.log").read_text().splitlines()
    labels = pd.read_csv(tmp_path / "labels.csv")
    assert len(lines) == len(labels)
    assert labels["line_no"].tolist() == list(range(1, len(lines) + 1))
    # Spot check: attack lines come from the documentation range.
    for _, row in labels[labels["is_attack"] == 1].iterrows():
        line = lines[row["line_no"] - 1]
        if " from " in line:
            assert "203.0.113." in line
