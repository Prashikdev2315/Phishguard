"""Serializable two-stage gate for the experimental URL classifier."""
from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import HistGradientBoostingClassifier

from ml.feature_extraction import FEATURE_NAMES

TOP_DOMAIN_RANK = 10_000
ROOT_RISK_CAP = 0.149


class GatedURLClassifier(BaseEstimator, ClassifierMixin):
    """Cap risk for ranked bare roots and score all other URLs normally."""

    def __init__(
        self,
        max_depth: int = 7,
        learning_rate: float = 0.04,
        max_leaf_nodes: int = 31,
        max_iter: int = 300,
        random_state: int = 42,
    ) -> None:
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.max_leaf_nodes = max_leaf_nodes
        self.max_iter = max_iter
        self.random_state = random_state

    def _new_estimator(self) -> HistGradientBoostingClassifier:
        return HistGradientBoostingClassifier(
            learning_rate=self.learning_rate,
            max_iter=self.max_iter,
            max_depth=self.max_depth,
            max_leaf_nodes=self.max_leaf_nodes,
            class_weight="balanced",
            random_state=self.random_state,
        )

    def fit(self, x: np.ndarray, y: np.ndarray) -> "GatedURLClassifier":
        self.estimator_ = self._new_estimator()
        self.estimator_.fit(x, y)
        self.classes_ = self.estimator_.classes_
        self._root_index = FEATURE_NAMES.index("is_root_domain")
        self._rank_index = FEATURE_NAMES.index("log_tranco_rank")
        return self

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        if not hasattr(self, "estimator_"):
            raise RuntimeError("GatedURLClassifier must be fitted before scoring")
        probabilities = self.estimator_.predict_proba(x)
        trusted_root = (
            (x[:, self._root_index] == 1)
            & (x[:, self._rank_index] <= np.log10(TOP_DOMAIN_RANK))
        )
        probabilities[trusted_root, 1] = np.minimum(probabilities[trusted_root, 1], ROOT_RISK_CAP)
        probabilities[trusted_root, 0] = 1.0 - probabilities[trusted_root, 1]
        return probabilities

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self.predict_proba(x).argmax(axis=1)
