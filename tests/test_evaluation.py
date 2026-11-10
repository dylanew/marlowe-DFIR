import pandas as pd

from marlowe.evaluation import average_precision, incident_detection, time_split, window_metrics


def test_window_metrics():
    y = pd.Series([1, 1, 0, 0, 0])
    p = pd.Series([1, 0, 1, 0, 0])
    m = window_metrics(y, p)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 2)
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1"] == 0.5


def test_window_metrics_no_predictions():
    m = window_metrics(pd.Series([1, 0]), pd.Series([0, 0]))
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["f1"] == 0.0


def test_average_precision_perfect_ranking():
    assert average_precision(pd.Series([0, 0, 1]), pd.Series([0.1, 0.2, 0.9])) == 1.0


def test_time_split_has_no_overlap():
    w = pd.DataFrame({"window_start": pd.date_range("2026-10-01", periods=10, freq="D", tz="UTC")})
    train, test, cutoff = time_split(w, train_fraction=0.5)
    assert train["window_start"].max() < cutoff <= test["window_start"].min()
    assert len(train) + len(test) == len(w)


def test_incident_detection():
    w = pd.DataFrame(
        {
            "is_attack": [1, 1, 1, 0],
            "attack_ids": ["A01", "A01", "A02", ""],
            "flag": [False, True, False, True],
        }
    )
    inc = incident_detection(w, "flag").set_index("attack_id")
    assert inc.loc["A01", "detected"]
    assert inc.loc["A01", "n_windows"] == 2
    assert not inc.loc["A02", "detected"]
