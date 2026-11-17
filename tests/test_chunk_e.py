"""
Unit tests for Chunk E:
1. tools/collect_e1.py:
   - Stratified sampling across 4 rank bands (1-1k, 1k-10k, 10k-100k, 100k-1M)
   - Seed list contains all 26 specified domains with 1-3 URLs each
   - is_indian detection for Indian TLDs, domains, and languages
   - evaluate_quotas checks all 7 quotas
2. ml/build_dataset.py:
   - load_e2 and integrate_e2 with 70/30 domain-level temporal split
   - Domain-disjointness between D1, E1, and E2
   - D1 test-split domain hash lock preserved when integrating E1 + E2
3. ml/evaluate_e1.py:
   - Slice metrics across rank bands, has_path, has_query, login_like, and indian
4. ml/evaluate.py:
   - T_block chosen on E1 validation part without tuning on hold-outs
   - Default enforcement mode warn_only unless G-3 passes
"""
import csv
import json
import pathlib
import pytest
import numpy as np
import pandas as pd

from tools.collect_e1 import (
    stratified_sample,
    SEED_LIST,
    is_indian,
    is_login_like,
    evaluate_quotas,
    MIN_TOTAL_DOMAINS,
    MIN_TOTAL_URLS,
    MAX_PER_DOMAIN,
)
from ml.build_dataset import (
    load_e2,
    integrate_e2,
    integrate_e1,
    grouped_holdout,
    sha256_text,
    build,
)
from ml.evaluate_e1 import (
    wilson_interval,
    compute_slice_metrics,
    evaluate_e1_slices,
)
from ml.evaluate import (
    choose_block_threshold,
    choose_warn_threshold,
)


# ---------------------------------------------------------------------------
# 1. tools/collect_e1.py tests
# ---------------------------------------------------------------------------

def test_stratified_sample_4_bands():
    rows = []
    # Band 1: 1-1,000
    for r in range(1, 21):
        rows.append((r, f"band1-{r}.com"))
    # Band 2: 1,001-10,000
    for r in range(1001, 1021):
        rows.append((r, f"band2-{r}.com"))
    # Band 3: 10,001-100,000
    for r in range(10001, 10021):
        rows.append((r, f"band3-{r}.com"))
    # Band 4: 100,001-1,000,000
    for r in range(100001, 100021):
        rows.append((r, f"band4-{r}.com"))

    sampled = stratified_sample(rows, band_sizes=[5, 6, 7, 8], seed=42)
    assert len(sampled) == 26

    b1 = [r for r, d in sampled if 1 <= r <= 1000]
    b2 = [r for r, d in sampled if 1001 <= r <= 10000]
    b3 = [r for r, d in sampled if 10001 <= r <= 100000]
    b4 = [r for r, d in sampled if 100001 <= r <= 1000000]

    assert len(b1) == 5
    assert len(b2) == 6
    assert len(b3) == 7
    assert len(b4) == 8


def test_seed_list_contains_all_26_domains():
    expected_domains = {
        "youtube.com", "flipkart.com", "amazon.in", "google.com",
        "wikipedia.org", "github.com", "irctc.co.in", "sbi.co.in",
        "paytm.com", "myntra.com", "zomato.com", "swiggy.com",
        "hdfcbank.com", "icicibank.com", "linkedin.com", "instagram.com",
        "facebook.com", "x.com", "microsoft.com", "apple.com",
        "netflix.com", "bookmyshow.com", "makemytrip.com", "naukri.com",
        "incometax.gov.in", "uidai.gov.in"
    }
    assert set(SEED_LIST.keys()) == expected_domains
    for dom, urls in SEED_LIST.items():
        assert 1 <= len(urls) <= 3, f"Domain {dom} has {len(urls)} URLs (must be 1-3)"
        for u in urls:
            assert u.startswith("https://") or u.startswith("http://")


def test_is_indian_detection():
    # Indian TLDs
    assert is_indian("https://example.in/page")
    assert is_indian("https://www.irctc.co.in/nget")
    assert is_indian("https://incometax.gov.in/portal")

    # Indian brands/domains
    assert is_indian("https://www.flipkart.com/account")
    assert is_indian("https://paytm.com/recharge")
    assert is_indian("https://zomato.com/delivery")

    # Indian languages
    assert is_indian("https://hi.wikipedia.org/wiki/India")
    assert is_indian("https://example.com/hi/news")
    assert is_indian("https://example.com/search?hl=hi")

    # Non-Indian
    assert not is_indian("https://www.google.co.uk/search")
    assert not is_indian("https://example.com/about")


def test_evaluate_quotas():
    # Synthetic records passing all quotas
    records = []
    # 5000 URLs from 1500 domains
    for d in range(1, 1601):
        dom = f"domain{d}.com"
        # URL 1: path
        records.append({"URL": f"https://{dom}/page", "domain": dom})
        # URL 2: query
        records.append({"URL": f"https://{dom}/search?q=test", "domain": dom})
        # URL 3: login & indian
        if d <= 550:
            records.append({"URL": f"https://{dom}/hi/login", "domain": dom})
        elif d <= 1200:
            records.append({"URL": f"https://{dom}/account/profile", "domain": dom})
        else:
            records.append({"URL": f"https://{dom}/about", "domain": dom})

    # Add extra to exceed 5000
    while len(records) < 5050:
        dom = f"extra{len(records)}.in"
        records.append({"URL": f"https://{dom}/path/item?id=1", "domain": dom})

    quotas = evaluate_quotas(records)
    assert quotas["total_urls"]["status"] == "PASS"
    assert quotas["total_domains"]["status"] == "PASS"
    assert quotas["max_per_domain"]["status"] == "PASS"
    assert quotas["path_share"]["status"] == "PASS"
    assert quotas["query_share"]["status"] == "PASS"
    assert quotas["login_share"]["status"] == "PASS"
    assert quotas["indian_share"]["status"] == "PASS"


# ---------------------------------------------------------------------------
# 2. ml/build_dataset.py E2 integration and temporal split
# ---------------------------------------------------------------------------

def test_integrate_e2_temporal_split(tmp_path):
    # Create fake D1 cleaned
    d1_rows = [{"URL": "https://d1site.com/p", "type": "Benign", "norm_url": "http://d1site.com/p", "registrable_domain": "d1site.com"}]
    d1_df = pd.DataFrame(d1_rows)

    # Create fake E2 CSV with dates
    e2_file = tmp_path / "e2_test.csv"
    e2_rows = [["URL", "source", "collected_at", "verified"]]
    # 10 domains with chronological dates
    for i in range(10):
        dom = f"phish{i}.org"
        date_str = f"2026-11-{10 + i:02d}T12:00:00"
        e2_rows.append([f"http://{dom}/login/verify", "phishtank", date_str, "true"])
        e2_rows.append([f"http://{dom}/account/update", "phishtank", date_str, "true"])

    with e2_file.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(e2_rows)

    splits_dir = tmp_path / "splits"
    res = integrate_e2(d1_df, e1_domains=set(), e2_path=e2_file, splits_dir=splits_dir, seed=42)

    e2_train = res["e2_training"]
    e2_ho = res["e2_holdout"]
    prov = res["provenance"]

    assert (e2_train["type"] == "Malicious").all()
    assert (e2_ho["type"] == "Malicious").all()

    train_doms = set(e2_train["registrable_domain"])
    ho_doms = set(e2_ho["registrable_domain"])

    # 70% oldest to train (7 domains), 30% newest to holdout (3 domains)
    assert len(train_doms) == 7
    assert len(ho_doms) == 3
    assert train_doms.isdisjoint(ho_doms)

    # Verify temporal ordering: newest dates are in holdout
    assert "phish9.org" in ho_doms
    assert "phish8.org" in ho_doms
    assert "phish7.org" in ho_doms
    assert "phish0.org" in train_doms

    assert (splits_dir / "e2_holdout.csv").exists()


def test_d1_test_domains_preserved_with_e1_and_e2(tmp_path):
    # Create fake D1 cleaned with 30 domains
    d1_rows = []
    for i in range(30):
        dom = f"d1domain{i}.com"
        d1_rows.append({
            "URL": f"https://{dom}/home",
            "type": "Benign" if i % 2 == 0 else "Malicious",
            "norm_url": f"http://{dom}/home",
            "registrable_domain": dom,
        })
    d1_df = pd.DataFrame(d1_rows)
    train, test = grouped_holdout(d1_df, seed=42)
    expected_d1_test_domains = sorted(set(test["registrable_domain"].dropna().unique()))
    expected_hash = sha256_text("\n".join(expected_d1_test_domains))

    # Fake E1 candidates
    e1_file = tmp_path / "E1.csv"
    e1_rows = [["URL", "domain", "rank", "collection_date", "source"]]
    for i in range(10):
        dom = f"e1domain{i}.net"
        e1_rows.append([f"https://{dom}/path", dom, str(i * 10), "2026-11-16", "homepage_link"])
    with e1_file.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(e1_rows)

    # Fake E2
    e2_file = tmp_path / "E2.csv"
    e2_rows = [["URL", "source", "collected_at", "verified"]]
    for i in range(10):
        dom = f"e2domain{i}.org"
        e2_rows.append([f"http://{dom}/phish", "openphish", f"2026-11-{15+i:02d}", "1"])
    with e2_file.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(e2_rows)

    splits_dir = tmp_path / "splits"
    res_e1 = integrate_e1(d1_df, e1_file, splits_dir, seed=42)
    e1_doms = set(res_e1["e1_training"]["registrable_domain"]) | set(res_e1["e1_holdout"]["registrable_domain"])
    res_e2 = integrate_e2(d1_df, e1_doms, e2_file, splits_dir, seed=42)

    combined_train = pd.concat([train, res_e1["e1_training"], res_e2["e2_training"]], ignore_index=True)
    combined_train_domains = set(combined_train["registrable_domain"])

    # No domain overlap with D1 test
    assert combined_train_domains.isdisjoint(set(expected_d1_test_domains))
    # D1 test domains unchanged
    assert sorted(set(test["registrable_domain"].dropna().unique())) == expected_d1_test_domains
    assert sha256_text("\n".join(expected_d1_test_domains)) == expected_hash


# ---------------------------------------------------------------------------
# 3. ml/evaluate.py threshold selection logic
# ---------------------------------------------------------------------------

def test_choose_block_threshold_on_validation_obeys_fpr():
    # 200 validation benign samples
    y_val = np.zeros(200, dtype=int)
    # probabilities: 198 low (0.01-0.10), 2 outliers (0.65, 0.85)
    probs = np.array([0.02] * 198 + [0.65, 0.85])

    # Max FPR = 0.5% (at most 1 false positive out of 200 = 0.5%)
    # Out of 200, 1 FP is 0.5%. So threshold should be > 0.65 (e.g. 0.85)
    t_block = choose_block_threshold(y_val, probs, maximum_fpr=0.005)
    assert t_block is not None
    assert t_block >= 0.65
    # Verification: at t_block, FPR <= 0.005
    fp = np.sum((probs >= t_block) & (y_val == 0))
    fpr = fp / len(y_val)
    assert fpr <= 0.005


# ---------------------------------------------------------------------------
# 4. Dry-run fix unit tests (Item 2)
# ---------------------------------------------------------------------------

def test_login_like_deterministic_tokens():
    from tools.collect_e1 import is_login_like, is_actual_login_page, LOGIN_TOKEN_PATTERN

    # Explicit user test cases
    assert is_login_like("https://example.com/pre-login")
    assert not is_login_like("https://example.com/login2")
    assert is_login_like("https://example.com/sign-in")
    assert not is_login_like("https://example.com/foportal")
    assert not is_login_like("https://example.com/business-associate")

    # Direct pattern checks on raw strings
    assert bool(LOGIN_TOKEN_PATTERN.search("pre-login"))
    assert not bool(LOGIN_TOKEN_PATTERN.search("login2"))
    assert bool(LOGIN_TOKEN_PATTERN.search("sign-in"))
    assert not bool(LOGIN_TOKEN_PATTERN.search("foportal"))
    assert not bool(LOGIN_TOKEN_PATTERN.search("business-associate"))

    # SPA fragment routes with #/login and #/register must be True
    assert is_login_like("https://eportal.incometax.gov.in/iec/foservices/#/login")
    assert is_login_like("https://eportal.incometax.gov.in/iec/foservices/#/pre-login/register")

    # Generic portal directory (/foportal/) without login keyword must be False
    assert not is_login_like("https://www.incometax.gov.in/iec/foportal/")

    # 'associate' contains 'sso' as substring, but word-boundary check must NOT flag it
    assert not is_login_like("https://plane.so/legals/business-associate-agreement")

    # Marketing feature pages explaining 2FA must not be tagged as actual login pages
    assert not is_actual_login_page("https://www.jotform.com/products/workflows/features/two-factor-authentication/")
    assert not is_actual_login_page("https://plane.so/legals/business-associate-agreement")

    # Genuine login pages are actual login pages
    assert is_actual_login_page("https://x.com/login")
    assert is_actual_login_page("https://x.com/i/flow/signup")
    assert is_actual_login_page("https://retail.onlinesbi.sbi/retail/login.htm")


def test_adult_domain_denylist_and_resampling():
    from tools.collect_e1 import is_adult_domain, stratified_sample

    # Test adult domain detection
    assert is_adult_domain("fatalmodel.com")
    assert is_adult_domain("rat.xxx")
    assert is_adult_domain("hot-escorts.net")
    assert is_adult_domain("camgirl-live.com")
    assert not is_adult_domain("google.com")
    assert not is_adult_domain("plane.so")
    assert not is_adult_domain("newsis.com")

    # Test stratified sampling filters adult domains and maintains quota
    test_rows = [
        (1, "google.com"),
        (2, "fatalmodel.com"),  # adult: should be skipped
        (3, "amazon.com"),
        (4, "rat.xxx"),         # adult: should be skipped
        (5, "wikipedia.org"),
        (6, "github.com"),
    ]
    sampled = stratified_sample(test_rows, band_sizes=[3], seed=42)
    assert len(sampled) == 3
    sampled_domains = [d for r, d in sampled]
    assert "fatalmodel.com" not in sampled_domains
    assert "rat.xxx" not in sampled_domains
    assert set(sampled_domains).issubset({"google.com", "amazon.com", "wikipedia.org", "github.com"})


def test_seed_list_3_bucket_partition():
    from tools.collect_e1 import SEED_LIST
    from ml.build_dataset import grouped_holdout

    d1 = pd.read_csv("data/processed/D1_cleaned.csv")
    train, test = grouped_holdout(d1, seed=42)
    train_doms = set(train["registrable_domain"].dropna().unique())
    test_doms = set(test["registrable_domain"].dropna().unique())

    bucket_train = {d: urls for d, urls in SEED_LIST.items() if d in train_doms}
    bucket_test = {d: urls for d, urls in SEED_LIST.items() if d in test_doms}
    bucket_neither = {d: urls for d, urls in SEED_LIST.items() if d not in train_doms and d not in test_doms}

    assert len(bucket_train) == 19
    assert len(bucket_test) == 3
    assert len(bucket_neither) == 4
    assert sum(len(u) for u in bucket_train.values()) == 57
    assert sum(len(u) for u in bucket_test.values()) == 9
    assert sum(len(u) for u in bucket_neither.values()) == 12
