import math

from ml.feature_extraction import FEATURE_NAMES, extract_features, extract_vector, mask_query
from ml.gated_classifier import GatedURLClassifier, ROOT_RISK_CAP


def test_v2_features_have_stable_order_and_types():
    row = extract_features("https://facebook.com/messages/t/12345?ref=home", tranco_rank=10)
    assert len(FEATURE_NAMES) == 35
    assert len(extract_vector("https://example.com")) == len(FEATURE_NAMES)
    assert all(isinstance(row[name], (int, float)) for name in FEATURE_NAMES)


def test_domain_anchor_and_root_features():
    root = extract_features("https://example.com", tranco_rank=100)
    endpoint = extract_features("https://facebook.com/messages/t/12345", tranco_rank=10)
    unranked = extract_features("https://example.xyz/secure", tranco_rank=None)
    assert root["is_root_domain"] == 1
    assert endpoint["is_root_domain"] == 0
    assert root["log_tranco_rank"] == math.log10(100)
    assert unranked["log_tranco_rank"] == 7.0
    assert unranked["tld_risk_score"] > root["tld_risk_score"]


def test_endpoint_ratios_and_masked_query_metrics():
    row = extract_features("https://example.com/a/b/123?one=123&two=value")
    assert row["path_depth"] == 3
    assert row["query_param_count"] == 2
    assert 0 < row["query_value_density"] < 1
    assert row["digit_to_alpha_ratio_path"] > 0
    assert 0 <= row["path_entropy_relative"] <= 1
    assert mask_query("one=123&two=value") == "one=<NUM>&two=<STR>"


def test_suspicious_keywords_are_separated_and_anomalies_counted():
    row = extract_features("https://login.example.com/admin//verify/%deadbeef@x")
    assert row["domain_suspicious_keyword_count"] == 1
    assert row["path_suspicious_keyword_count"] >= 2
    assert row["double_slash_in_path"] == 1
    assert row["at_symbol_in_url"] == 1
    assert row["hex_pattern_count"] >= 1


def test_gated_classifier_caps_ranked_root_risk():
    import numpy as np

    x = np.asarray([
        extract_vector("https://example.com", tranco_rank=10),
        extract_vector("https://example.com/login", tranco_rank=10),
    ])
    model = GatedURLClassifier(max_iter=10).fit(x, np.asarray([0, 1]))
    assert model.predict_proba(x)[0, 1] <= ROOT_RISK_CAP
