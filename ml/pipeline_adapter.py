"""Mode-aware adapter for production and experimental URL scoring."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import numpy as np

from ml.enforcement_pipeline import ProductionURLClassifier
from ml.features import extract_vector as extract_fs1_vector

T_BLOCK = 0.70
T_WARN = 0.35


class HybridURLClassifier:
    """Expose one URL interface while keeping production behavior unchanged."""

    def __init__(
        self,
        mode: str = "production",
        production_model: Any | None = None,
        experimental_model: Any | None = None,
        allowlist_domains: Iterable[str] = (),
        brand_keywords: Iterable[str] = (),
    ) -> None:
        if mode not in {"production", "experimental"}:
            raise ValueError(f"Unsupported mode: {mode}")
        self.mode = mode
        self.production_model = production_model
        self.experimental_model = experimental_model
        self._rules = (
            ProductionURLClassifier(
                experimental_model,
                allowlist_domains,
                brand_keywords,
            )
            if mode == "experimental"
            else None
        )

    @staticmethod
    def _urls(urls: str | Iterable[str]) -> tuple[list[str], bool]:
        if isinstance(urls, str):
            return [urls], True
        return list(urls), False

    def _production_probability(self, urls: list[str]) -> np.ndarray:
        if self.production_model is None:
            raise ValueError("production_model is required in production mode")
        vectors = np.asarray([extract_fs1_vector(url) for url in urls], dtype=np.float64)
        return self.production_model.predict_proba(vectors)[:, 1]

    def predict_proba(self, urls: str | Iterable[str]) -> np.ndarray:
        values, _ = self._urls(urls)
        if self.mode == "production":
            return self._production_probability(values)
        if self._rules is None:
            raise RuntimeError("Experimental rules are not configured")
        probabilities = []
        for url in values:
            rule_score = self._rules.rule_risk(url)
            if rule_score is not None:
                probabilities.append(rule_score / 100.0)
            else:
                probabilities.append(self._rules._model_probability(url))
        return np.asarray(probabilities, dtype=np.float64)

    def predict_risk(self, urls: str | Iterable[str]) -> int | list[int]:
        values, scalar = self._urls(urls)
        risks = [int(max(0.0, min(1.0, probability)) * 100) for probability in self.predict_proba(values)]
        return risks[0] if scalar else risks

    def predict(self, urls: str | Iterable[str], threshold: float = T_BLOCK) -> np.ndarray:
        return (self.predict_proba(urls) >= threshold).astype(int)
