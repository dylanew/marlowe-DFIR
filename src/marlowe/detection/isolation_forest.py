"""Isolation Forest anomaly detector, with per-flag explanations.

How Isolation Forest works, briefly
    It builds many random trees, each splitting the data on a random
    feature at a random value. Unusual points are *easy to isolate*: they
    end up alone after only a few splits. The average path length over all
    trees becomes an anomaly score. It needs no labels, which suits security
    data, where labelled attacks are rare.

Design choices
    * **Trained only on the earlier part of the timeline** (see
      ``marlowe.evaluation.time_split``). It is scored on later windows, as
      it would be in real use. Training on everything would leak the future.
    * **Counts are log-transformed** (``log1p``) before scaling. A burst of
      150 failures and one of 40 are both "a lot"; without the log, a single
      extreme value dominates the scale of a feature.
    * **The flag threshold comes from the training scores** (the
      ``contamination`` quantile), never from the test set.
    * **Every flag gets an explanation:** the features furthest from their
      training median, in robust (median/IQR) units. This is a simple,
      honest proxy for "why", not a full attribution method such as SHAP.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from marlowe.features.auth_windows import COUNT_FEATURES, MODEL_FEATURES


class IsolationForestDetector:
    def __init__(
        self,
        features: list[str] = MODEL_FEATURES,
        contamination: float = 0.02,
        n_estimators: int = 300,
        random_state: int = 42,
    ):
        self.features = list(features)
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination="auto",
            random_state=random_state,
        )
        self.scaler = StandardScaler()
        self.threshold_: float | None = None
        self._median: pd.Series | None = None
        self._iqr: pd.Series | None = None

    def _transform(self, windows: pd.DataFrame) -> pd.DataFrame:
        x = windows[self.features].astype(float).copy()
        for col in self.features:
            if col in COUNT_FEATURES:
                x[col] = np.log1p(x[col])
        return x

    def fit(self, train_windows: pd.DataFrame) -> IsolationForestDetector:
        x = self._transform(train_windows)
        self.model.fit(self.scaler.fit_transform(x))
        train_scores = self.score(train_windows)
        self.threshold_ = float(np.quantile(train_scores, 1 - self.contamination))
        self._median = x.median()
        iqr = x.quantile(0.75) - x.quantile(0.25)
        # Features that are constant in training (IQR 0) fall back to std, then 1.
        self._iqr = iqr.where(iqr > 0, x.std()).replace(0, 1).fillna(1)
        return self

    def score(self, windows: pd.DataFrame) -> np.ndarray:
        """Anomaly score: higher means more anomalous."""
        x = self.scaler.transform(self._transform(windows))
        return -self.model.score_samples(x)

    def explain(self, windows: pd.DataFrame, top_k: int = 3) -> pd.Series:
        """For each window, the ``top_k`` features furthest from typical training values."""
        x = self._transform(windows)
        z = (x - self._median) / self._iqr

        def describe(i: int) -> str:
            row = z.iloc[i]
            top = row.abs().sort_values(ascending=False).head(top_k)
            raw = windows.iloc[i]
            return "; ".join(
                f"{f}={raw[f]:.3g} ({'high' if row[f] > 0 else 'low'}, {abs(row[f]):.1f} IQR)"
                for f in top.index
                if abs(row[f]) > 0
            )

        return pd.Series([describe(i) for i in range(len(windows))], index=windows.index)

    def predict(self, windows: pd.DataFrame) -> pd.DataFrame:
        if self.threshold_ is None:
            raise RuntimeError("Call fit() before predict().")
        out = windows.copy()
        out["if_score"] = self.score(windows)
        out["if_flag"] = out["if_score"] >= self.threshold_
        out["if_reasons"] = ""
        flagged = out["if_flag"]
        if flagged.any():
            out.loc[flagged, "if_reasons"] = self.explain(windows.loc[flagged])
        return out
