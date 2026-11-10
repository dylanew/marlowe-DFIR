import numpy as np
import pandas as pd
import pytest

from marlowe.detection import IsolationForestDetector, apply_rules
from marlowe.features import MODEL_FEATURES


def _window(**overrides):
    base = dict.fromkeys(MODEL_FEATURES, 0)
    base.update(n_events=1, n_success=1, is_internal_ip=1, hour_sin=0.0, hour_cos=-1.0)
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "overrides, rule",
    [
        ({"n_failed": 10}, "rule_brute_force"),
        ({"n_distinct_users": 5, "failure_ratio": 0.9}, "rule_password_spray"),
        ({"success_after_failure": 1, "n_failed": 3}, "rule_success_after_failures"),
        ({"n_success_off_hours": 1, "n_new_user_ip_success": 1}, "rule_off_hours_new_source"),
    ],
)
def test_each_rule_fires(overrides, rule):
    out = apply_rules(pd.DataFrame([_window(**overrides)]))
    assert out[rule].iloc[0]
    assert out["rule_flag"].iloc[0]
    assert out["rule_reasons"].iloc[0]


def test_normal_window_not_flagged():
    out = apply_rules(pd.DataFrame([_window()]))
    assert not out["rule_flag"].iloc[0]
    assert out["rule_reasons"].iloc[0] == ""


def _normal_windows(n=300, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        hour = rng.normal(12.5, 2)
        rows.append(
            _window(
                n_events=rng.integers(1, 3),
                n_failed=rng.integers(0, 2),
                n_success=1,
                n_distinct_users=1,
                hour_sin=np.sin(2 * np.pi * hour / 24),
                hour_cos=np.cos(2 * np.pi * hour / 24),
            )
        )
    return pd.DataFrame(rows)


def test_isolation_forest_flags_obvious_outlier_and_explains_it():
    train = _normal_windows()
    detector = IsolationForestDetector(random_state=0).fit(train)
    attack = pd.DataFrame(
        [
            _window(
                n_events=150,
                n_failed=120,
                n_invalid_user=60,
                n_distinct_users=6,
                n_success=0,
                failure_ratio=1.0,
                is_internal_ip=0,
                hour_sin=-0.7,
                hour_cos=0.7,
            )
        ]
    )
    test = pd.concat([_normal_windows(50, seed=1), attack], ignore_index=True)
    out = detector.predict(test)
    assert out["if_flag"].iloc[-1]
    # Isolation Forest scores saturate for extreme points (they are isolated
    # in very few splits), so a rare-but-benign combination can score about
    # as high. Require a top-3 rank rather than strictly the maximum.
    assert out["if_score"].rank(ascending=False).iloc[-1] <= 3
    assert "n_failed" in out["if_reasons"].iloc[-1]
    assert out["if_flag"].iloc[:-1].mean() < 0.2


def test_isolation_forest_is_reproducible():
    train = _normal_windows()
    a = IsolationForestDetector(random_state=7).fit(train).score(train)
    b = IsolationForestDetector(random_state=7).fit(train).score(train)
    np.testing.assert_array_equal(a, b)


def test_predict_before_fit_raises():
    with pytest.raises(RuntimeError):
        IsolationForestDetector().predict(_normal_windows(5))
