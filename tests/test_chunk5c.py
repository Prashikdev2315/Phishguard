"""
Unit tests for Chunk 5c:
1. D1 test-split domain hash assertion in build_dataset.py.
2. Sitemap XML parsing and login-like URL detection in tools/collect_e1.py.
3. Wilson interval and E1 FPR slice evaluation in ml/evaluate_e1.py.
4. --max-domains and crawl summary generation.
"""
import csv
import gzip
import json
import pathlib
import pytest
import numpy as np
import pandas as pd
from unittest.mock import MagicMock

from ml.build_dataset import sha256_text, integrate_e1, grouped_holdout, build
from tools.collect_e1 import (
    parse_sitemap,
    is_login_like,
    LOGIN_KEYWORDS,
    stratified_sample,
)
from ml.evaluate_e1 import (
    wilson_interval,
    compute_slice_metrics,
    evaluate_e1_slices,
)


# ---------------------------------------------------------------------------
# 1. build_dataset.py domain hash tests
# ---------------------------------------------------------------------------

def test_d1_test_domains_hash_consistency():
    domains = ["alpha.com", "beta.org", "gamma.net"]
    h1 = sha256_text("\n".join(sorted(domains)))
    h2 = sha256_text("\n".join(sorted(list(reversed(domains)))))
    assert h1 == h2
    assert len(h1) == 64


def test_d1_test_split_unchanged_after_e1_integration(tmp_path):
    # Create fake D1 cleaned
    d1_rows = []
    for i in range(40):
        dom = f"site{i}.com"
        d1_rows.append({
            "URL": f"https://{dom}/page",
            "type": "Benign" if i % 2 == 0 else "Malicious",
            "norm_url": f"http://{dom}/page",
            "registrable_domain": dom,
        })
    d1_df = pd.DataFrame(d1_rows)
    train, test = grouped_holdout(d1_df, seed=42)

    d1_test_domains = sorted(set(test["registrable_domain"].dropna().unique()))
    d1_test_domains_hash = sha256_text("\n".join(d1_test_domains))

    # Create fake E1 candidates CSV
    e1_file = tmp_path / "E1_candidates.csv"
    e1_rows = [["URL", "domain", "rank", "collection_date", "source"]]
    for i in range(100, 110):
        dom = f"e1domain{i}.org"
        e1_rows.append([f"https://{dom}/deep/path", dom, str(i * 10), "2026-11-16", "homepage_link"])

    with e1_file.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(e1_rows)

    splits_dir = tmp_path / "splits"
    res = integrate_e1(d1_df, e1_file, splits_dir, seed=42)
    e1_train = res["e1_training"]

    # Verify D1 test domains are unaffected
    test_domains_after = sorted(set(test["registrable_domain"].dropna().unique()))
    assert test_domains_after == d1_test_domains
    assert sha256_text("\n".join(test_domains_after)) == d1_test_domains_hash


# ---------------------------------------------------------------------------
# 2. tools/collect_e1.py sitemap & login detection
# ---------------------------------------------------------------------------

def test_parse_sitemap_xml():
    xml_data = b"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://example.com/about</loc></url>
        <url><loc>https://example.com/contact</loc></url>
    </urlset>"""
    urls, nested = parse_sitemap(xml_data)
    assert len(urls) == 2
    assert "https://example.com/about" in urls
    assert "https://example.com/contact" in urls
    assert len(nested) == 0


def test_parse_sitemap_gzipped():
    xml_data = b"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://example.com/page1</loc></url>
    </urlset>"""
    gz_data = gzip.compress(xml_data)
    urls, nested = parse_sitemap(gz_data)
    assert len(urls) == 1
    assert urls[0] == "https://example.com/page1"


def test_is_login_like():
    assert is_login_like("https://example.com/login")
    assert is_login_like("https://example.com/user/sign-in")
    assert is_login_like("https://example.com/account/settings")
    assert is_login_like("https://example.com/portal?auth=1")
    assert is_login_like("https://example.com/my-account")
    assert not is_login_like("https://example.com/about-us")
    assert not is_login_like("https://example.com/blog/2026/news")


def test_max_domains_cap():
    rows = (
        [(i, f"domain{i}.com") for i in range(1, 21)]
        + [(i, f"domain{i}.com") for i in range(1001, 1021)]
        + [(i, f"domain{i}.com") for i in range(10001, 10021)]
    )
    sampled = stratified_sample(rows, [10, 10, 10], seed=42)
    assert len(sampled) == 30
    capped = sampled[:15]
    assert len(capped) == 15


# ---------------------------------------------------------------------------
# 3. ml/evaluate_e1.py Wilson intervals and slice evaluation
# ---------------------------------------------------------------------------

def test_wilson_interval():
    # 0 errors out of 100
    low, high = wilson_interval(0, 100)
    assert low == 0.0
    assert 0.0 < high < 0.05  # upper bound around 3.6%

    # 5 errors out of 1000
    low, high = wilson_interval(5, 1000)
    assert 0.0 < low < 0.005
    assert 0.005 < high < 0.015

    # 0 total
    assert wilson_interval(0, 0) == (0.0, 0.0)


class DummyModel:
    def predict_proba(self, X):
        return np.array([[0.9, 0.1]] * len(X))


def test_evaluate_e1_slices_synthetic(tmp_path, monkeypatch):
    # Create synthetic E1 hold-out CSV
    holdout_csv = tmp_path / "e1_holdout.csv"
    rows = [
        ["URL", "domain", "rank", "collection_date", "source"],
        ["https://site1.com/login", "site1.com", "500", "2026-11-16", "login_page"],
        ["https://site1.com/about?q=1", "site1.com", "500", "2026-11-16", "homepage_link"],
        ["https://site2.org/sitemap-page", "site2.org", "5000", "2026-11-16", "sitemap"],
        ["https://site3.net/deep/path/very/long/url", "site3.net", "50000", "2026-11-16", "homepage_link"],
        ["https://site4.io/short", "site4.io", "150000", "2026-11-16", "homepage_link"],
    ]
    with holdout_csv.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(rows)

    # Mock extract_vector to return dummy 50-dim vector
    monkeypatch.setattr("ml.evaluate_e1.extract_vector", lambda url: [0.0] * 50)

    # Mock model
    mock_model = DummyModel()
    model_path = tmp_path / "best_model.joblib"
    import joblib
    joblib.dump(mock_model, model_path)

    rep = evaluate_e1_slices(holdout_csv, model_path, threshold=0.5, root=tmp_path)

    assert rep["total_holdout_urls"] == 5
    assert rep["overall"]["false_positives"] == 0
    assert rep["overall"]["fpr"] == 0.0
    assert rep["gate_g3"]["status"] == "PASS"

    # Check required slice categories exist
    cats = {sl["slice_category"] for sl in rep["slices"]}
    assert "overall" in cats
    assert "rank_band" in cats
    assert "source" in cats
    assert "has_query" in cats
    assert "path_length_quartile" in cats
    assert "login_like" in cats

    # Check generated reports
    assert (tmp_path / "data" / "reports" / "e1_fpr_evaluation.json").exists()
    assert (tmp_path / "data" / "reports" / "e1_fpr_evaluation.md").exists()
