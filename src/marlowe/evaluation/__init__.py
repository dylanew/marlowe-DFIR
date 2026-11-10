"""Evaluation against ground truth: splits and metrics."""

from __future__ import annotations

import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix


def time_split(
    windows: pd.DataFrame, train_fraction: float = 0.6, time_col: str = "window_start"
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Timestamp]:
    """Split by time: everything before the cutoff trains, everything after tests.

    A random split would let the model "see" the future (for example, an IP
    first used in the test period would no longer look new), which inflates
    the scores. Real detection always runs on data newer than the training data.
    """
    start, end = windows[time_col].min(), windows[time_col].max()
    cutoff = start + (end - start) * train_fraction
    train = windows[windows[time_col] < cutoff]
    test = windows[windows[time_col] >= cutoff]
    return train, test, cutoff


def window_metrics(y_true: pd.Series, y_pred: pd.Series) -> dict[str, float]:
    """Precision, recall, F1 and confusion counts at window level."""
    tn, fp, fn, tp = confusion_matrix(y_true.astype(int), y_pred.astype(int), labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
    }


def average_precision(y_true: pd.Series, scores: pd.Series) -> float:
    """Area under the precision-recall curve: threshold-free and suited to rare positives."""
    return float(average_precision_score(y_true.astype(int), scores))


def incident_detection(windows: pd.DataFrame, flag_col: str) -> pd.DataFrame:
    """Per attack: was *any* of its windows flagged?

    This is closer to what an investigator cares about than window recall.
    Catching one window of a 30-minute spray is enough to start looking.
    """
    rows = []
    attacks = windows.loc[windows["is_attack"] == 1]
    for attack_id in sorted({a for ids in attacks["attack_ids"] for a in ids.split(",") if a}):
        mask = attacks["attack_ids"].str.split(",").map(lambda ids, a=attack_id: a in ids)
        hit = attacks.loc[mask]
        rows.append(
            {
                "attack_id": attack_id,
                "n_windows": int(len(hit)),
                "n_flagged": int(hit[flag_col].sum()),
                "detected": bool(hit[flag_col].any()),
            }
        )
    return pd.DataFrame(rows, columns=["attack_id", "n_windows", "n_flagged", "detected"])
