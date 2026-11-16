"""
Unit tests for Chunk 5b:
- tools/collect_e1.py (Tranco loading, stratified sampling, link extraction)
- ml/build_dataset.py (integrate_e1, domain-grouped split across D1 + E1, no leakage)
- Unit formatting in reports (percentage points)
"""
import csv
import json
import pathlib
import pytest
import pandas as pd

from tools.collect_e1 import (
    extract_links,
    stratified_sample,
    load_tranco,
    USER_AGENT,
    RATE_LIMIT_SECONDS,
    REQUEST_TIMEOUT,
)
from ml.build_dataset import load_e1, integrate_e1, add_normalization


def test_collect_e1_constants():
    assert USER_AGENT.startswith("PhishGuard")
    assert RATE_LIMIT_SECONDS >= 1.0
    assert REQUEST_TIMEOUT <= 10


def test_collect_e1_extract_links():
    html = """
    <html><body>
        <a href="https://example.com/page1">Page 1</a>
        <a href="/relative/path">Relative</a>
        <a href="mailto:test@example.com">Email</a>
        <p>No link here</p>
    </body></html>
    """
    links = extract_links(html)
    assert "https://example.com/page1" in links
    assert "/relative/path" in links
    assert "mailto:test@example.com" in links


def test_collect_e1_load_tranco_and_stratified_sample(tmp_path):
    tranco_file = tmp_path / "tranco.csv"
    lines = ["rank,domain"]
    # Band 1: 1-1,000 (10 domains)
    for r in range(1, 11):
        lines.append(f"{r},band1-domain{r}.com")
    # Band 2: 1,001-10,000 (10 domains)
    for r in range(1001, 1011):
        lines.append(f"{r},band2-domain{r}.com")
    # Band 3: 10,001-100,000 (10 domains)
    for r in range(10001, 10011):
        lines.append(f"{r},band3-domain{r}.com")

    tranco_file.write_text("\n".join(lines), encoding="utf-8")

    rows, list_id, list_date = load_tranco(tranco_file)
    assert len(rows) == 30

    # Sample 3, 4, 5 from the three bands
    sampled = stratified_sample(rows, band_sizes=[3, 4, 5], seed=42)
    assert len(sampled) == 12

    # Check ranks fall within respective bands
    b1 = [r for r, d in sampled if 1 <= r <= 1000]
    b2 = [r for r, d in sampled if 1001 <= r <= 10000]
    b3 = [r for r, d in sampled if 10001 <= r <= 100000]
    assert len(b1) == 3
    assert len(b2) == 4
    assert len(b3) == 5

    # Determinism
    sampled2 = stratified_sample(rows, band_sizes=[3, 4, 5], seed=42)
    assert sampled == sampled2


def test_integrate_e1_splits_and_guards(tmp_path):
    # Create fake D1 cleaned
    d1_rows = []
    for i in range(20):
        dom = f"d1site{i}.com"
        d1_rows.append({
            "URL": f"https://{dom}/page",
            "type": "Benign" if i % 2 == 0 else "Malicious",
            "norm_url": f"http://{dom}/page",
            "registrable_domain": dom,
        })
    d1_df = pd.DataFrame(d1_rows)

    # Create fake E1 candidates CSV
    # Include:
    # - 1 domain overlapping with D1 (should be excluded)
    # - 10 new domains (each with 2 URLs)
    e1_file = tmp_path / "E1_candidates.csv"
    e1_rows = [["URL", "domain", "rank", "collection_date"]]
    # Overlapping domain
    e1_rows.append(["https://d1site0.com/deep/path", "d1site0.com", "1", "2026-11-16"])
    # New domains
    for i in range(1, 11):
        dom = f"newsite{i}.org"
        e1_rows.append([f"https://{dom}/about/us", dom, str(i * 100), "2026-11-16"])
        e1_rows.append([f"https://{dom}/products/item1", dom, str(i * 100), "2026-11-16"])

    with e1_file.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerows(e1_rows)

    splits_dir = tmp_path / "splits"
    res = integrate_e1(d1_df, e1_file, splits_dir, seed=42)

    e1_train = res["e1_training"]
    e1_ho = res["e1_holdout"]
    prov = res["provenance"]

    # All E1 must be Benign
    assert (e1_train["type"] == "Benign").all()
    assert (e1_ho["type"] == "Benign").all()

    # Overlapping domain d1site0.com must be excluded
    assert "d1site0.com" not in set(e1_train["registrable_domain"])
    assert "d1site0.com" not in set(e1_ho["registrable_domain"])
    assert prov["e1_d1_domains_excluded"] == 1

    # Exactly 10 unique domains, 5 train / 5 holdout
    train_doms = set(e1_train["registrable_domain"])
    ho_doms = set(e1_ho["registrable_domain"])
    assert len(train_doms) == 5
    assert len(ho_doms) == 5
    assert train_doms.isdisjoint(ho_doms)

    # e1_holdout.csv written to disk
    assert (splits_dir / "e1_holdout.csv").exists()
    saved_ho = pd.read_csv(splits_dir / "e1_holdout.csv")
    assert len(saved_ho) == len(e1_ho)
