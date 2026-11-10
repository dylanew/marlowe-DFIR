"""End-to-end auth.log analysis: register -> parse -> features -> detect -> evaluate.

This is the single function the CLI, notebooks and (later) the LLM assistant
all call. Keeping it in one place means every interface gets the same,
tested behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from marlowe.detection import IsolationForestDetector, apply_rules
from marlowe.evaluation import average_precision, incident_detection, time_split, window_metrics
from marlowe.features import attach_labels, build_ip_windows
from marlowe.forensics import EvidenceRecord, register_evidence
from marlowe.parsers import parse_auth_log


@dataclass
class AnalysisResult:
    evidence: EvidenceRecord
    events: pd.DataFrame
    windows: pd.DataFrame  # test-period windows with both detectors' outputs
    train_windows: pd.DataFrame
    cutoff: pd.Timestamp
    detector: IsolationForestDetector
    metrics: dict[str, dict] = field(default_factory=dict)
    incidents: pd.DataFrame | None = None

    @property
    def parse_summary(self) -> pd.Series:
        return self.events["event_type"].value_counts()

    def findings(self) -> pd.DataFrame:
        """Flagged windows in the test period, most anomalous first, with source line numbers."""
        cols = [
            "src_ip",
            "window_start",
            "n_events",
            "n_failed",
            "n_success",
            "n_distinct_users",
            "rule_flag",
            "rule_reasons",
            "if_flag",
            "if_score",
            "if_reasons",
            "evidence_id",
            "line_nos",
        ]
        if "is_attack" in self.windows:
            cols += ["is_attack", "attack_ids"]
        flagged = self.windows[self.windows["rule_flag"] | self.windows["if_flag"]]
        return flagged.sort_values("if_score", ascending=False)[cols]


def analyse_auth_log(
    log_path: str | Path,
    manifest_path: str | Path,
    year: int,
    tz: str = "UTC",
    labels_path: str | Path | None = None,
    window: str = "10min",
    train_fraction: float = 0.6,
    contamination: float = 0.02,
    random_state: int = 42,
) -> AnalysisResult:
    evidence = register_evidence(log_path, manifest_path, notes="auth.log analysis")
    events = parse_auth_log(log_path, year=year, tz=tz, evidence_id=evidence.evidence_id)
    windows = build_ip_windows(events, window=window)

    if labels_path is not None:
        windows = attach_labels(windows, pd.read_csv(labels_path))

    train, test, cutoff = time_split(windows, train_fraction=train_fraction)
    detector = IsolationForestDetector(contamination=contamination, random_state=random_state)
    detector.fit(train)
    test = detector.predict(apply_rules(test))

    result = AnalysisResult(
        evidence=evidence,
        events=events,
        windows=test,
        train_windows=train,
        cutoff=cutoff,
        detector=detector,
    )

    if "is_attack" in test:
        y = test["is_attack"]
        result.metrics = {
            "rules": window_metrics(y, test["rule_flag"]),
            "isolation_forest": window_metrics(y, test["if_flag"]),
            "either": window_metrics(y, test["rule_flag"] | test["if_flag"]),
        }
        result.metrics["isolation_forest"]["average_precision"] = average_precision(
            y, test["if_score"]
        )
        rules_inc = incident_detection(test, "rule_flag").rename(
            columns={"n_flagged": "rules_flagged", "detected": "rules_detected"}
        )
        if_inc = incident_detection(test, "if_flag")[["attack_id", "n_flagged", "detected"]].rename(
            columns={"n_flagged": "if_flagged", "detected": "if_detected"}
        )
        result.incidents = rules_inc.merge(if_inc, on="attack_id")
        labels = pd.read_csv(labels_path)
        types = labels.loc[labels["is_attack"] == 1].drop_duplicates("attack_id")
        result.incidents = result.incidents.merge(
            types[["attack_id", "attack_type"]], on="attack_id", how="left"
        )

    return result
