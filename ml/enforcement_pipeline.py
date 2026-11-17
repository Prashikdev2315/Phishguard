"""Experimental rule pre-filter around a URL probability model.

This module is not wired into the extension. It is an opt-in comparison path
for evaluating high-confidence trusted-domain and impersonation rules.
"""
from __future__ import annotations

from collections.abc import Callable, Collection
from typing import Any

from ml.normalize import normalize

_PATH_KEYWORDS = ("login", "verify", "update", "banking")


class ProductionURLClassifier:
    """Apply explicit rules before delegating long-tail URLs to the ML model."""

    def __init__(
        self,
        ml_model: Any,
        allowlist_domains: Collection[str],
        brand_keywords: Collection[str],
        feature_builder: Callable[[str], Any] | None = None,
    ) -> None:
        self.ml_model = ml_model
        self.allowlist_domains = {
            domain.lower().removeprefix("www.") for domain in allowlist_domains
        }
        self.brand_keywords = {keyword.lower() for keyword in brand_keywords}
        self.feature_builder = feature_builder

    def _model_probability(self, url: str) -> float:
        model_input: Any = url
        if self.feature_builder is not None:
            model_input = self.feature_builder(url)
        elif isinstance(model_input, str):
            model_input = [model_input]
        probabilities = self.ml_model.predict_proba(model_input)
        if hasattr(probabilities, "ndim") and probabilities.ndim == 2:
            return float(probabilities[0, 1])
        return float(probabilities[1])

    def predict_risk(self, url: str) -> int:
        rule_score = self.rule_risk(url)
        if rule_score is not None:
            return rule_score
        return int(max(0.0, min(1.0, self._model_probability(url))) * 100)

    def rule_risk(self, url: str) -> int | None:
        """Return a rule score, or ``None`` when the ML fallback should run."""
        result = normalize(url)
        if result.error:
            raise ValueError(f"URL normalization failed: {result.error}")
        registrable_domain = (result.registrable_domain or "").lower()
        full_host = (result.puny_host or "").lower()
        path_query = f"{result.path}{result.query}{result.fragment}".lower()

        if registrable_domain in self.allowlist_domains:
            if len(path_query) < 5 or not any(keyword in path_query for keyword in _PATH_KEYWORDS):
                return 5

        for brand in self.brand_keywords:
            if brand in full_host or brand in path_query:
                if brand not in registrable_domain:
                    return 95
        return None
