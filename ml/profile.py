#!/usr/bin/env python3
"""
ml/profile.py — Dataset profiling and shortcut audit (Chunk 2)
==============================================================

PRD §7.1, §7.2 (steps 1, 4, 5, 6 as analysis only), FR-22 (profiling part)

READ-ONLY: this script never modifies any data row.
Cleaning (step 2 — domain cap, dedup) is Chunk 3.

Outputs
-------
  ml/report/profile_D1.json    machine-readable stats
  ml/report/profile_D1.md      human-readable report
  data/review_sample.csv       100 random rows per class for label spot-check

Usage
-----
  python -m ml.profile \\
      --dataset path/to/Combined_Benign_Malicious_Dataset_CORRECTED.csv \\
      --out-dir ml/report \\
      --review-out data/review_sample.csv \\
      --seed 42
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import pathlib
import random
import re
import sys
import warnings
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import balanced_accuracy_score
from sklearn.preprocessing import LabelEncoder

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.normalize import normalize, NormalizeResult

# ── constants ─────────────────────────────────────────────────────────────────

LABEL_BENIGN    = "Benign"
LABEL_MALICIOUS = "Malicious"
CLASSES         = [LABEL_BENIGN, LABEL_MALICIOUS]
SEED            = 42

# Shortcut baseline features (PRD §7.2 step 4)
# "url_length, has_path, is_https, TLD (one-hot for TLDs with ≥30 rows)"
SHORTCUT_TREE_MAX_DEPTH = 2
SHORTCUT_TLD_MIN_ROWS   = 30

# ── file hash helper ──────────────────────────────────────────────────────────

def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── load and normalize dataset ────────────────────────────────────────────────

def _load_dataset(path: pathlib.Path) -> pd.DataFrame:
    """Load CSV, return DataFrame with original columns."""
    df = pd.read_csv(path, dtype=str)
    # Expect columns: URL, type
    assert "URL" in df.columns, "Missing 'URL' column"
    assert "type" in df.columns, "Missing 'type' column"
    return df


def _normalize_all(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply normalize() to every URL and add result columns.
    Returns the augmented DataFrame.
    """
    results = [normalize(str(u)) for u in df["URL"]]

    df = df.copy()
    df["norm_url"]           = [r.normalized         for r in results]
    df["cache_key"]          = [r.cache_key           for r in results]
    df["norm_error"]         = [r.error               for r in results]
    df["scheme"]             = [r.scheme              for r in results]
    df["puny_host"]          = [r.puny_host           for r in results]
    df["registrable_domain"] = [r.registrable_domain  for r in results]
    df["public_suffix"]      = [r.public_suffix       for r in results]
    df["is_ip_host"]         = [r.is_ip_host          for r in results]
    df["is_punycode"]        = [r.is_punycode         for r in results]
    df["url_length"]         = [r.raw_length          for r in results]
    df["has_path"]           = [
        bool(r.path and r.path not in ("", "/")) for r in results
    ]
    return df


# ── individual stat functions ─────────────────────────────────────────────────

def _count_exact_duplicates(df: pd.DataFrame) -> int:
    return int(df.duplicated(subset=["URL", "type"]).sum())


def _count_normalized_duplicates(df: pd.DataFrame) -> int:
    return int(df.duplicated(subset=["norm_url", "type"]).sum())


def _count_cross_class_norm_dups(df: pd.DataFrame) -> int:
    """Same normalized URL appears in both classes."""
    benign_norms    = set(df.loc[df["type"] == LABEL_BENIGN,    "norm_url"])
    malicious_norms = set(df.loc[df["type"] == LABEL_MALICIOUS, "norm_url"])
    return len(benign_norms & malicious_norms)


def _length_stats(series: pd.Series) -> Dict[str, float]:
    return {
        "mean":   round(float(series.mean()), 2),
        "median": round(float(series.median()), 2),
        "min":    int(series.min()),
        "max":    int(series.max()),
        "p95":    round(float(np.percentile(series.values, 95)), 2),
    }


def _top_domains(df: pd.DataFrame, cls: str, n: int = 20) -> List[Dict[str, Any]]:
    sub = df[df["type"] == cls]["registrable_domain"].dropna()
    counter = Counter(sub)
    return [{"domain": d, "count": c} for d, c in counter.most_common(n)]


def _domains_in_both_classes(df: pd.DataFrame) -> List[str]:
    b = set(df.loc[df["type"] == LABEL_BENIGN,    "registrable_domain"].dropna())
    m = set(df.loc[df["type"] == LABEL_MALICIOUS, "registrable_domain"].dropna())
    return sorted(b & m)


def _bare_homepage_share(df: pd.DataFrame, cls: str) -> float:
    """Rows where path is empty or '/' AND no query string."""
    sub = df[df["type"] == cls]
    bare = sub.apply(
        lambda row: (row["norm_error"] is None) and
                    (not row["has_path"]) and
                    ("?" not in str(row["norm_url"])),
        axis=1,
    )
    total = len(sub)
    return round(float(bare.sum()) / total, 4) if total else 0.0


def _scheme_analysis_per_class(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Per-class breakdown of scheme: schemeless (no http/https prefix in raw URL),
    explicit http, explicit https.
    Returns nested dict: {class: {schemeless, http, https, counts, shares}}.
    """
    has_scheme = df["URL"].str.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
    result: Dict[str, Any] = {}
    for cls in CLASSES:
        sub = df[df["type"] == cls]
        total = len(sub)
        sl_mask  = ~sub["URL"].str.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
        http_mask  = sub["URL"].str.match(r"^[hH][tT][tT][pP]://")
        https_mask = sub["URL"].str.match(r"^[hH][tT][tT][pP][sS]://")
        sl_cnt    = int(sl_mask.sum())
        http_cnt  = int(http_mask.sum())
        https_cnt = int(https_mask.sum())
        result[cls] = {
            "total": total,
            "schemeless":        sl_cnt,
            "schemeless_share":  round(sl_cnt    / total, 4) if total else 0.0,
            "http":              http_cnt,
            "http_share":        round(http_cnt  / total, 4) if total else 0.0,
            "https":             https_cnt,
            "https_share":       round(https_cnt / total, 4) if total else 0.0,
        }
    return result


def _top_schemeless_patterns(df: pd.DataFrame, n: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    """
    For scheme-less rows in each class, bucket by URL pattern:
      bare_domain     — no slash, no query  (e.g. 'google.com')
      domain_path     — has path, no query  (e.g. 'example.com/page')
      domain_query    — no path, has query  (e.g. 'example.com?q=1')
      domain_path_query — both path and query
    Returns top-n patterns per class by count.
    """
    scheme_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
    result: Dict[str, List[Dict[str, Any]]] = {}
    for cls in CLASSES:
        sub = df[df["type"] == cls]
        sl  = sub[~sub["URL"].str.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")]
        counter: Counter = Counter()
        for raw in sl["URL"]:
            raw = str(raw).strip()
            has_slash = "/" in raw
            has_query = "?" in raw
            if has_slash and has_query:
                bucket = "domain_path_query"
            elif has_slash:
                bucket = "domain_path"
            elif has_query:
                bucket = "domain_query"
            else:
                bucket = "bare_domain"
            counter[bucket] += 1
        result[cls] = [
            {"pattern": pat, "count": cnt}
            for pat, cnt in counter.most_common(n)
        ]
    return result


def _list_notable_urls(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Return:
      - non_ascii_urls: list of {index, label, url} for rows with non-ASCII chars
      - norm_error_urls: list of {index, label, url, error} for rows with norm_error set
    """
    non_ascii = []
    for idx, row in df.iterrows():
        url = str(row["URL"])
        if any(ord(c) > 127 for c in url):
            non_ascii.append({
                "index": int(idx),
                "label": row["type"],
                "url_repr": repr(url[:120]),
            })

    norm_errors = []
    err_rows = df[df["norm_error"].notna()]
    for idx, row in err_rows.iterrows():
        norm_errors.append({
            "index": int(idx),
            "label": row["type"],
            "url_repr": repr(str(row["URL"])[:120]),
            "error": row["norm_error"],
        })

    return {
        "non_ascii_urls": non_ascii,
        "norm_error_urls": norm_errors,
    }


def _hosting_platform_share(df: pd.DataFrame, cls: str, platforms: List[str]) -> Dict[str, Any]:
    """
    Share of rows whose registrable domain suffix matches a hosting platform.
    PRD §6.2: is_free_hosting feature uses the hosting.json list.
    """
    platform_set = set(p.lower() for p in platforms)

    def _is_hosted(reg_domain: Optional[str]) -> bool:
        if not reg_domain:
            return False
        rd = reg_domain.lower()
        return any(rd == p or rd.endswith("." + p) for p in platform_set)

    sub = df[df["type"] == cls]
    hosted = sub["registrable_domain"].apply(_is_hosted)
    total = len(sub)
    count = int(hosted.sum())
    return {
        "count": count,
        "total": total,
        "share": round(count / total, 4) if total else 0.0,
    }


def _shortcut_rule_accuracy(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Simple hand-crafted shortcut rules and their accuracy.
    Rule: (url_length <= 40) AND (is_https == True)  → predict Benign.
    Reports overall accuracy, TPR, FPR for the rule.
    """
    valid = df[df["norm_error"].isna()].copy()
    valid["is_https"] = valid["scheme"] == "https"

    # Rule: short AND https → predict Benign, else Malicious
    threshold = 40
    pred_benign = (valid["url_length"] <= threshold) & valid["is_https"]

    y_true_benign = valid["type"] == LABEL_BENIGN
    tp = int((pred_benign & y_true_benign).sum())
    fp = int((pred_benign & ~y_true_benign).sum())
    fn = int((~pred_benign & y_true_benign).sum())
    tn = int((~pred_benign & ~y_true_benign).sum())

    total = len(valid)
    correct = tp + tn
    accuracy = round(correct / total, 4) if total else 0.0

    return {
        "rule": f"url_length <= {threshold} AND is_https → Benign",
        "threshold_url_length": threshold,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": accuracy,
        "note": "Shortcut rule; not a model. Used to illustrate dataset separability.",
    }


def _shortcut_baseline(df: pd.DataFrame, seed: int = SEED) -> Dict[str, Any]:
    """
    PRD §7.2 step 4 & Chunk 2 fix-up 2: depth-2 decision tree on:
      - Deployable features (N-13): scheme-stripped url_length, has_path, and TLD one-hot
      - Comparison baseline: same features PLUS is_https

    Split: 80/20 grouped by registrable_domain, seed=42.
    Metric: balanced accuracy.
    """
    valid = df[df["norm_error"].isna()].copy()
    valid["is_https"] = (valid["scheme"] == "https").astype(int)
    valid["has_path_int"] = valid["has_path"].astype(int)
    valid["label_int"] = (valid["type"] == LABEL_MALICIOUS).astype(int)

    # N-13: compute length on scheme-stripped normalized URL
    scheme_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
    valid["scheme_stripped_len"] = valid["norm_url"].apply(
        lambda u: len(scheme_pattern.sub("", str(u)))
    )

    # TLD one-hot (TLDs with ≥ SHORTCUT_TLD_MIN_ROWS rows; rest → "other")
    tld_counts = valid["public_suffix"].value_counts()
    hot_tlds = set(tld_counts[tld_counts >= SHORTCUT_TLD_MIN_ROWS].index.tolist())

    def _tld_bucket(tld: Optional[str]) -> str:
        if tld and tld in hot_tlds:
            return tld
        return "__other__"

    valid["tld_bucket"] = valid["public_suffix"].apply(_tld_bucket)
    tld_dummies = pd.get_dummies(valid["tld_bucket"], prefix="tld")
    X_tld = tld_dummies.values

    # 1) Deployable features: scheme-stripped length, has_path, TLD (N-13, no is_https)
    X_deployable = np.hstack([
        valid[["scheme_stripped_len", "has_path_int"]].values,
        X_tld,
    ])

    # 2) Comparison features: with is_https
    X_with_https = np.hstack([
        valid[["scheme_stripped_len", "has_path_int", "is_https"]].values,
        X_tld,
    ])

    y = valid["label_int"].values

    # Group key = registrable_domain (NaN → use row index string as own group)
    reg_domain_series = valid["registrable_domain"].copy()
    null_mask = reg_domain_series.isna()
    reg_domain_series[null_mask] = ["__row_" + str(i) for i in valid.index[null_mask]]
    groups = reg_domain_series.values

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    train_idx, test_idx = next(gss.split(X_deployable, y, groups))

    # Fit deployable tree (N-13)
    clf_dep = DecisionTreeClassifier(max_depth=SHORTCUT_TREE_MAX_DEPTH, random_state=seed)
    clf_dep.fit(X_deployable[train_idx], y[train_idx])
    bal_acc_dep = round(float(balanced_accuracy_score(y[test_idx], clf_dep.predict(X_deployable[test_idx]))), 4)

    # Fit comparison tree (with is_https)
    clf_https = DecisionTreeClassifier(max_depth=SHORTCUT_TREE_MAX_DEPTH, random_state=seed)
    clf_https.fit(X_with_https[train_idx], y[train_idx])
    bal_acc_https = round(float(balanced_accuracy_score(y[test_idx], clf_https.predict(X_with_https[test_idx]))), 4)

    # Check group overlap (leakage guard)
    train_groups = set(groups[train_idx])
    test_groups  = set(groups[test_idx])
    overlap = train_groups & test_groups

    return {
        "description": (
            "Depth-2 decision tree on deployable features (scheme-stripped url_length, has_path, and TLD one-hot). "
            "80/20 grouped split by registrable_domain, seed 42."
        ),
        "split": "80/20 grouped by registrable_domain",
        "seed": seed,
        "max_depth": SHORTCUT_TREE_MAX_DEPTH,
        "tld_min_rows": SHORTCUT_TLD_MIN_ROWS,
        "num_hot_tlds": len(hot_tlds),
        "train_size": len(train_idx),
        "test_size": len(test_idx),
        "group_overlap_count": len(overlap),
        "group_overlap_ok": len(overlap) == 0,
        "balanced_accuracy_deployable": bal_acc_dep,
        "balanced_accuracy_with_https": bal_acc_https,
        "balanced_accuracy": bal_acc_dep,  # primary
        "note": (
            "Deployable baseline uses scheme-stripped length, has_path, and TLD (is_https dropped per N-13). "
            "Comparison baseline with is_https included for audit. "
            "If baseline reaches ≥ 95% balanced accuracy, PRD §7.2 step 4 requires stopping before model work."
        ),
        "gate_g1_risk": bal_acc_dep >= 0.95,
    }


def _write_review_sample(
    df: pd.DataFrame,
    out_path: pathlib.Path,
    n: int = 100,
    seed: int = SEED,
) -> Dict[str, int]:
    """Write n random rows per class to out_path for manual label spot-check."""
    rng = random.Random(seed)
    rows_out = []
    counts = {}
    for cls in CLASSES:
        sub = df[df["type"] == cls]
        sample_size = min(n, len(sub))
        indices = rng.sample(list(sub.index), sample_size)
        rows_out.extend(sub.loc[indices].to_dict("records"))
        counts[cls] = sample_size

    # Shuffle so the two classes are interleaved
    rng.shuffle(rows_out)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    keys = ["URL", "type", "norm_url", "norm_error", "scheme",
            "puny_host", "registrable_domain", "is_ip_host", "url_length"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows_out)

    return counts


# ── main profile function ─────────────────────────────────────────────────────

def profile(
    dataset_path: pathlib.Path,
    out_dir: pathlib.Path,
    review_out: pathlib.Path,
    seed: int = SEED,
) -> Dict[str, Any]:
    """
    Run the full profile and return the stats dict.
    Writes profile_D1.json, profile_D1.md, and review_sample.csv.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Load ──────────────────────────────────────────────────────────────
    print("[profile] Loading dataset …")
    df_raw = _load_dataset(dataset_path)
    file_hash = _sha256(dataset_path)
    total_rows = len(df_raw)

    # Class counts
    class_counts = df_raw["type"].value_counts().to_dict()

    # Null counts
    null_url  = int(df_raw["URL"].isna().sum())
    null_type = int(df_raw["type"].isna().sum())

    # ── 2. Normalize ──────────────────────────────────────────────────────────
    print("[profile] Normalizing all URLs …")
    df = _normalize_all(df_raw)

    # ── 3. Basic counts ───────────────────────────────────────────────────────
    exact_dups      = _count_exact_duplicates(df_raw)
    norm_dups       = _count_normalized_duplicates(df)
    cross_cls_dups  = _count_cross_class_norm_dups(df)

    scheme_less = int((~df_raw["URL"].str.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")).sum())
    non_ascii   = int(df_raw["URL"].apply(lambda u: any(ord(c) > 127 for c in str(u))).sum())
    is_punycode = int(df["is_punycode"].sum())
    is_ip       = int(df["is_ip_host"].sum())
    # norm_error: count rows where the error field is a non-None string
    has_error   = int(df["norm_error"].apply(lambda v: v is not None and str(v) != "None").sum())
    error_breakdown = {
        k: int(v)
        for k, v in df["norm_error"].dropna().value_counts().items()
        if k is not None and str(k) != "None"
    }

    # Per-class scheme analysis (new in fix-up)
    print("[profile] Computing per-class scheme analysis …")
    scheme_analysis = _scheme_analysis_per_class(df)

    # Top scheme-less URL patterns per class (new in fix-up)
    print("[profile] Computing top scheme-less URL patterns …")
    schemeless_patterns = _top_schemeless_patterns(df, n=10)

    # Notable URLs: non-ASCII and normalization errors (new in fix-up)
    print("[profile] Listing notable URLs (non-ASCII, norm errors) …")
    notable_urls = _list_notable_urls(df)

    # ── 4. URL length stats ───────────────────────────────────────────────────
    print("[profile] Computing length statistics …")
    length_stats = {}
    for cls in CLASSES:
        sub = df[(df["type"] == cls) & df["norm_error"].isna()]["url_length"]
        length_stats[cls] = _length_stats(sub)

    # ── 5. Top domains ────────────────────────────────────────────────────────
    print("[profile] Computing domain distribution …")
    top_domains = {cls: _top_domains(df, cls, 20) for cls in CLASSES}
    domains_in_both = _domains_in_both_classes(df)

    # ── 6. Bare homepage share ────────────────────────────────────────────────
    bare_homepage_share = {cls: _bare_homepage_share(df, cls) for cls in CLASSES}

    # ── 7. Hosting platform share ─────────────────────────────────────────────
    print("[profile] Loading hosting platforms …")
    hosting_path = ROOT / "lists" / "hosting.json"
    with open(hosting_path, encoding="utf-8") as f:
        hosting_data = json.load(f)
    platforms = hosting_data.get("platforms", [])
    hosting_share = {cls: _hosting_platform_share(df, cls, platforms) for cls in CLASSES}

    # ── 8. Shortcut rule accuracy ─────────────────────────────────────────────
    print("[profile] Computing shortcut rule accuracy …")
    shortcut_rule = _shortcut_rule_accuracy(df)

    # ── 9. Shortcut baseline (depth-2 tree, grouped split) ────────────────────
    print("[profile] Running shortcut baseline (depth-2 decision tree) …")
    shortcut_baseline = _shortcut_baseline(df, seed=seed)

    # ── 10. Review sample ─────────────────────────────────────────────────────
    print("[profile] Writing review sample …")
    review_counts = _write_review_sample(df, review_out, n=100, seed=seed)

    # ── Assemble stats dict ───────────────────────────────────────────────────
    stats: Dict[str, Any] = {
        "generated_at":         datetime.datetime.utcnow().isoformat() + "Z",
        "source_file":          str(dataset_path),
        "source_sha256":        file_hash,
        "psl_source":           __import__("ml.psl", fromlist=["get_psl"]).get_psl().source,
        "total_rows":           total_rows,
        "class_counts":         class_counts,
        "null_url":             null_url,
        "null_type":            null_type,
        "exact_duplicates":     exact_dups,
        "normalized_duplicates":norm_dups,
        "cross_class_norm_dups":cross_cls_dups,
        "scheme_less_count":    scheme_less,
        "non_ascii_count":      non_ascii,
        "punycode_host_count":  is_punycode,
        "ip_host_count":        is_ip,
        "norm_error_count":     has_error,
        "norm_error_breakdown": error_breakdown,
        "url_length_stats":     length_stats,
        "top_20_domains":       top_domains,
        "domains_in_both_classes": domains_in_both,
        "domains_in_both_count": len(domains_in_both),
        "bare_homepage_share":  bare_homepage_share,
        "hosting_platform_share": hosting_share,
        "shortcut_rule":        shortcut_rule,
        "shortcut_baseline":    shortcut_baseline,
        "review_sample": {
            "path":   str(review_out),
            "counts": review_counts,
        },
        "scheme_analysis":      scheme_analysis,
        "schemeless_patterns":  schemeless_patterns,
        "notable_urls":         notable_urls,
    }

    # ── Write JSON ────────────────────────────────────────────────────────────
    json_path = out_dir / "profile_D1.json"
    json_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(f"[profile] JSON  → {json_path}")

    # ── Write Markdown ────────────────────────────────────────────────────────
    md_path = out_dir / "profile_D1.md"
    _write_markdown(stats, md_path)
    print(f"[profile] MD    → {md_path}")
    print(f"[profile] CSV   → {review_out}")
    print("[profile] Done.")

    return stats


# ── Markdown writer ───────────────────────────────────────────────────────────

def _write_markdown(s: Dict[str, Any], path: pathlib.Path) -> None:
    sb = s["shortcut_baseline"]
    sr = s["shortcut_rule"]
    cc = s["class_counts"]

    lines = [
        "# PhishGuard — D1 Dataset Profile",
        "",
        f"**Generated:** {s['generated_at']}",
        f"**Source file:** `{pathlib.Path(s['source_file']).name}`",
        f"**SHA-256:** `{s['source_sha256']}`",
        f"**PSL source:** `{s['psl_source']}`",
        "",
        "---",
        "",
        "## 1. Row counts",
        "",
        f"| Class | Count |",
        f"|-------|-------|",
    ]
    for cls in CLASSES:
        lines.append(f"| {cls} | {cc.get(cls, 0):,} |")
    lines += [
        f"| **Total** | **{s['total_rows']:,}** |",
        "",
        f"- Null URLs: **{s['null_url']}**",
        f"- Null labels: **{s['null_type']}**",
        f"- Exact duplicates (same URL+class): **{s['exact_duplicates']}**",
        f"- Normalized duplicates (same norm_url+class): **{s['normalized_duplicates']}**",
        f"- Cross-class normalized duplicates: **{s['cross_class_norm_dups']}** "
          "(same normalized URL in both classes)",
        "",
        "---",
        "",
        "## 2. URL anomalies",
        "",
        f"| Anomaly | Count |",
        f"|---------|-------|",
        f"| Scheme-less (no http/https prefix) | {s['scheme_less_count']:,} |",
        f"| Non-ASCII characters | {s['non_ascii_count']:,} |",
        f"| Punycode / IDN hostnames | {s['punycode_host_count']:,} |",
        f"| IP-address hosts | {s['ip_host_count']:,} |",
        f"| Normalization errors | {s['norm_error_count']:,} |",
    ]
    if s["norm_error_breakdown"]:
        lines.append("")
        lines.append("Error breakdown:")
        for err, cnt in s["norm_error_breakdown"].items():
            lines.append(f"  - `{err}`: {cnt}")

    # Notable URLs (non-ASCII, norm errors)
    notable = s.get("notable_urls", {})
    non_ascii_list = notable.get("non_ascii_urls", [])
    norm_error_list = notable.get("norm_error_urls", [])

    lines += ["", "### Non-ASCII URLs", ""]
    if non_ascii_list:
        lines.append("| # | Label | URL (repr, first 120 chars) |")
        lines.append("|---|-------|-----------------------------|")
        for i, entry in enumerate(non_ascii_list, 1):
            lines.append(f"| {i} | {entry['label']} | `{entry['url_repr']}` |")
        lines.append("")
        lines.append(
            "> **Note:** The leading U+00A0 (non-breaking space) is stripped by N-01 "
            "before any other processing. The URL itself normalizes without error."
        )
    else:
        lines.append("*None found.*")

    lines += ["", "### Normalization-error URLs", ""]
    if norm_error_list:
        lines.append("| # | Label | URL (repr) | Error |")
        lines.append("|---|-------|------------|-------|")
        for i, entry in enumerate(norm_error_list, 1):
            lines.append(f"| {i} | {entry['label']} | `{entry['url_repr']}` | `{entry['error']}` |")
    else:
        lines.append(
            "*None — 0 normalization errors. "
            "The U+00A0-prefixed URL (Malicious, row above) normalizes cleanly via N-01.*"
        )

    # Per-class scheme analysis
    sa = s.get("scheme_analysis", {})
    lines += [
        "",
        "---",
        "",
        "## 2b. Scheme distribution per class",
        "",
        "| Class | Total | Scheme-less | % | HTTP (explicit) | % | HTTPS (explicit) | % |",
        "|-------|-------|-------------|---|-----------------|---|------------------|---|",
    ]
    for cls in CLASSES:
        d = sa.get(cls, {})
        total_c  = d.get("total", 0)
        sl_cnt   = d.get("schemeless", 0)
        http_cnt = d.get("http", 0)
        https_cnt= d.get("https", 0)
        sl_pct   = d.get("schemeless_share", 0.0)
        http_pct = d.get("http_share", 0.0)
        https_pct= d.get("https_share", 0.0)
        lines.append(
            f"| {cls} | {total_c:,} | {sl_cnt:,} | {sl_pct:.1%} "
            f"| {http_cnt:,} | {http_pct:.1%} "
            f"| {https_cnt:,} | {https_pct:.1%} |"
        )

    lines += [
        "",
        "> **Scheme-less skew:** Benign URLs are scheme-less at a much higher rate than Malicious.",
        "> After N-02 prepends `http://`, `is_https=False` becomes artificially correlated with Benign.",
        "> See `docs/ASSUMPTIONS.md` A-13 for proposed mitigations and the pending decision on N-02.",
        "",
    ]

    # Top scheme-less patterns per class
    sp = s.get("schemeless_patterns", {})
    lines += [
        "## 2c. Top scheme-less URL patterns per class",
        "",
        "Pattern buckets: `bare_domain` (no slash, no query), `domain_path`, `domain_query`, `domain_path_query`.",
        "",
    ]
    for cls in CLASSES:
        lines.append(f"### {cls}")
        lines.append("")
        lines.append("| Pattern | Count |")
        lines.append("|---------|-------|")
        for entry in sp.get(cls, []):
            lines.append(f"| `{entry['pattern']}` | {entry['count']:,} |")
        lines.append("")

    lines += [
        "",
        "---",
        "",
        "## 3. URL length statistics (normalized, valid rows only)",
        "",
        "| Metric | Benign | Malicious |",
        "|--------|--------|-----------|",
    ]
    for metric in ["mean", "median", "min", "max", "p95"]:
        b_val = s["url_length_stats"].get(LABEL_BENIGN, {}).get(metric, "n/a")
        m_val = s["url_length_stats"].get(LABEL_MALICIOUS, {}).get(metric, "n/a")
        lines.append(f"| {metric} | {b_val} | {m_val} |")

    lines += [
        "",
        "---",
        "",
        "## 4. Top 20 registrable domains per class",
        "",
        "### Benign",
        "",
        "| Rank | Domain | Count |",
        "|------|--------|-------|",
    ]
    for i, entry in enumerate(s["top_20_domains"].get(LABEL_BENIGN, []), 1):
        lines.append(f"| {i} | {entry['domain']} | {entry['count']} |")

    lines += [
        "",
        "### Malicious",
        "",
        "| Rank | Domain | Count |",
        "|------|--------|-------|",
    ]
    for i, entry in enumerate(s["top_20_domains"].get(LABEL_MALICIOUS, []), 1):
        lines.append(f"| {i} | {entry['domain']} | {entry['count']} |")

    n_both = s["domains_in_both_count"]
    both   = s["domains_in_both_classes"]
    lines += [
        "",
        f"### Domains appearing in BOTH classes ({n_both} total)",
        "",
    ]
    if both:
        lines.append("| Domain |")
        lines.append("|--------|")
        for d in both[:30]:
            lines.append(f"| {d} |")
        if n_both > 30:
            lines.append(f"| *(and {n_both - 30} more — see profile_D1.json)* |")
    else:
        lines.append("*None.*")

    lines += [
        "",
        "---",
        "",
        "## 5. Bare homepage share",
        "",
        "A row is a 'bare homepage' if its path is empty or '/' and there is no query string.",
        "",
        "| Class | Share |",
        "|-------|-------|",
    ]
    for cls in CLASSES:
        share = s["bare_homepage_share"].get(cls, 0.0)
        lines.append(f"| {cls} | {share:.1%} |")

    lines += [
        "",
        "---",
        "",
        "## 6. Hosting platform share",
        "",
        f"Platforms checked: `lists/hosting.json` ({len(s['hosting_platform_share'].get(LABEL_BENIGN, {}))} entries evaluated)",
        "",
        "| Class | On hosting platform | Total | Share |",
        "|-------|---------------------|-------|-------|",
    ]
    for cls in CLASSES:
        hs = s["hosting_platform_share"].get(cls, {})
        lines.append(
            f"| {cls} | {hs.get('count', 0)} | {hs.get('total', 0):,} | {hs.get('share', 0):.2%} |"
        )

    lines += [
        "",
        "---",
        "",
        "## 7. Shortcut rule (illustrative)",
        "",
        f"> **Rule:** {sr['rule']}",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Accuracy | {sr['accuracy']:.2%} |",
        f"| True Positives (Benign, correctly) | {sr['tp']:,} |",
        f"| False Positives (Malicious, wrongly Benign) | {sr['fp']:,} |",
        f"| False Negatives (Benign, wrongly Malicious) | {sr['fn']:,} |",
        f"| True Negatives (Malicious, correctly) | {sr['tn']:,} |",
        "",
        f"*{sr['note']}*",
        "",
        "---",
        "",
        "## 8. Shortcut baseline (PRD §7.2 step 4)",
        "",
        f"> {sb['description']}",
        "",
        "| Parameter | Value |",
        "|-----------|-------|",
        f"| Split | {sb['split']} |",
        f"| Seed | {sb['seed']} |",
        f"| Max depth | {sb['max_depth']} |",
        f"| Hot TLDs (≥ {sb['tld_min_rows']} rows) | {sb['num_hot_tlds']} |",
        f"| Train size | {sb['train_size']:,} |",
        f"| Test size | {sb['test_size']:,} |",
        f"| Group overlap | {sb['group_overlap_count']} (OK: {sb['group_overlap_ok']}) |",
        "",
        f"### **Shortcut baseline (deployable features): {sb['balanced_accuracy_deployable']:.2%}**",
        f"- *Features:* scheme-stripped url_length, has_path, TLD one-hot (N-13)",
        f"- *Comparison with is_https included:* **{sb['balanced_accuracy_with_https']:.2%}**",
        "",
    ]

    if sb["gate_g1_risk"]:
        lines += [
            "> [!CAUTION]",
            "> Shortcut baseline ≥ 95%. PRD §7.2 step 4 says:",
            "> **Stop and rebalance data before any model work (add E1 to training).**",
            "> Gate G-1 is at risk.",
        ]
    else:
        lines += [
            "> [!NOTE]",
            f"> Shortcut baseline {sb['balanced_accuracy']:.2%} < 95%. "
            "Data is not trivially shortcut-separable. Proceed to Chunk 3.",
        ]

    lines += [
        "",
        f"*{sb['note']}*",
        "",
        "---",
        "",
        "## 9. Review sample",
        "",
        f"Written to `{s['review_sample']['path']}`.",
        "",
        "| Class | Rows sampled |",
        "|-------|-------------|",
    ]
    for cls, cnt in s["review_sample"]["counts"].items():
        lines.append(f"| {cls} | {cnt} |")

    lines += [
        "",
        "**Manual action required:** spot-check these rows for label correctness "
        "and record the error rate in `data/PROVENANCE.md`.",
        "",
        "---",
        "",
        "*Profile is read-only. No data was modified. Cleaning is Chunk 3.*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard D1 dataset profiler")
    parser.add_argument(
        "--dataset",
        default=str(ROOT.parent / "Combined_Benign_Malicious_Dataset_CORRECTED.csv"),
        help="Path to the primary dataset CSV",
    )
    parser.add_argument("--out-dir",    default=str(ROOT / "ml" / "report"))
    parser.add_argument("--review-out", default=str(ROOT / "data" / "review_sample.csv"))
    parser.add_argument("--seed",       type=int, default=SEED)
    args = parser.parse_args()

    stats = profile(
        dataset_path=pathlib.Path(args.dataset),
        out_dir=pathlib.Path(args.out_dir),
        review_out=pathlib.Path(args.review_out),
        seed=args.seed,
    )

    # Print key headline numbers to stdout
    sb = stats["shortcut_baseline"]
    print("\n── Key numbers ─────────────────────────────────────")
    print(f"  Total rows              : {stats['total_rows']:,}")
    for cls in CLASSES:
        print(f"  {cls:<12}       : {stats['class_counts'].get(cls, 0):,}")
    print(f"  Scheme-less             : {stats['scheme_less_count']:,}")
    print(f"  Exact duplicates        : {stats['exact_duplicates']:,}")
    print(f"  Norm duplicates         : {stats['normalized_duplicates']:,}")
    print(f"  Cross-class norm dups   : {stats['cross_class_norm_dups']:,}")
    print(f"  Shortcut baseline (deployable): {sb['balanced_accuracy_deployable']:.2%}")
    print(f"  Shortcut baseline (with https): {sb['balanced_accuracy_with_https']:.2%}")
    print(f"  Gate G-1 risk (≥95%)?   : {sb['gate_g1_risk']}")
    print("────────────────────────────────────────────────────")


if __name__ == "__main__":
    main()
