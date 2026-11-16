import math

from ml.features import FEATURE_NAMES, extract_features, extract_vector, derive_suspicious_tlds


def test_fs1_has_exactly_50_ordered_features():
    assert len(FEATURE_NAMES) == 50
    assert len(set(FEATURE_NAMES)) == 50
    assert "is_https" not in FEATURE_NAMES
    assert not any(name.startswith("whois_") for name in FEATURE_NAMES)


def test_scheme_is_stripped_for_string_length_features():
    http = extract_features("http://example.com/a")
    https = extract_features("https://example.com/a")
    assert http["url_length"] == https["url_length"]
    assert http["url_length"] == len("example.com/a")


def test_url_components_and_keywords():
    row = extract_features("https://login-paypal.example.com/verify?account=1#top")
    assert row["sensitive_word_count"] >= 2
    assert row["keyword_in_host"] == 1
    assert row["keyword_in_path"] == 1
    assert row["brand_in_subdomain_or_path"] == 1
    assert row["query_param_count"] == 1
    assert row["fragment_length"] == 3


def test_ip_host_and_domain_constants():
    row = extract_features("http://192.168.1.10/login")
    assert row["has_ip_host"] == 1
    assert row["tld_length"] == 0
    assert row["registrable_domain_length"] == 0
    assert row["subdomain_count"] == 0
    assert row["domain_hyphen_count"] == 0
    assert row["domain_digit_count"] == 0
    assert row["is_punycode"] == 0
    assert row["mixed_script_host"] == 0
    assert row["suspicious_tld"] == 0
    assert row["longest_subdomain_label"] == 0


def test_empty_path_and_query_entropy_are_zero():
    row = extract_features("https://example.com")
    assert row["path_entropy"] == 0
    assert row["query_entropy"] == 0
    assert row["url_entropy"] > 0


def test_invalid_url_rejected():
    import pytest
    with pytest.raises(ValueError):
        extract_features("not a valid url")


def test_vector_order_matches_spec():
    url = "https://example.com/path"
    vector = extract_vector(url)
    row = extract_features(url)
    assert len(vector) == 50
    assert vector == [row[name] for name in FEATURE_NAMES]


def test_keyword_in_path_excludes_query_parameters():
    query_only = extract_features("https://example.com/?login=1")
    path_only = extract_features("https://example.com/login")
    assert query_only["keyword_in_path"] == 0
    assert path_only["keyword_in_path"] == 1
    # Whole-URL lexical counts continue to inspect the decoded query.
    assert query_only["sensitive_word_count"] >= 1


def test_brand_in_subdomain_or_path_excludes_query_parameters():
    query_only = extract_features("https://example.com/?paypal=1")
    path_only = extract_features("https://example.com/paypal")
    assert query_only["brand_in_subdomain_or_path"] == 0
    assert path_only["brand_in_subdomain_or_path"] == 1
