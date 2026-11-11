"""Detectors: a transparent rule baseline and an unsupervised ML model."""

from marlowe.detection.isolation_forest import IsolationForestDetector
from marlowe.detection.rules import RULES, Rule, apply_rules

__all__ = ["RULES", "IsolationForestDetector", "Rule", "apply_rules"]
