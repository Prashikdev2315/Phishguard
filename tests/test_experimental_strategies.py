import numpy as np

from ml.enforcement_pipeline import ProductionURLClassifier
from ml.threshold_analysis import optimize_threshold


class StubModel:
    def predict_proba(self, value):
        return np.asarray([[0.2, 0.8]])


def test_rule_prefilter_handles_trusted_domains_and_impersonation():
    classifier = ProductionURLClassifier(
        StubModel(),
        {"facebook.com", "google.com"},
        {"facebook", "google", "paypal"},
    )
    assert classifier.predict_risk("https://facebook.com/messages/t/100012345") == 5
    assert classifier.predict_risk("https://facebook-verify-account.suspicious-domain.com/login") == 95
    assert classifier.predict_risk("https://unknown.example/path") == 80


def test_threshold_search_is_recommendation_only():
    result = optimize_threshold(
        np.asarray([0.1, 0.2, 0.8, 0.9]),
        np.asarray([0, 0, 1, 1]),
    )
    assert result["validation_bacc"] == 1.0
    assert result["frozen_default_threshold"] == 0.70
