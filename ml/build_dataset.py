#!/usr/bin/env python3
"""
PhishGuard Chunk 3: deterministic D1 dataset preparation.

Implements PRD sections 7.2 and 7.3:
- N-01..N-13 URL normalization through ml.normalize
- exact and normalized duplicate removal
- per-class, per-registrable-domain cap
- 100-row-per-class manual review sample
- domain-grouped 80/20 hold-out and random-stratified comparison split
- three-seed, five-fold StratifiedGroupKFold definitions on the training partition
- cleaning, concentration, split and provenance manifests

This script does not fabricate E1/E2 data. Those sets require separately sourced,
dated and verified external records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.normalize import normalize

LABELS = ("Benign", "Malicious")
SEED = 42
CV_SEEDS = (42, 43, 44)
REQUIRED_COLUMNS = ("URL", "type")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_source(path: pathlib.Path) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError("Missing required CSV column(s): " + ", ".join(missing))
    frame = frame.loc[:, list(REQUIRED_COLUMNS)].copy()
    frame["URL"] = frame["URL"].astype(str).str.strip()
    frame["type"] = frame["type"].astype(str).str.strip()
    if (frame["URL"] == "").any():
        raise ValueError("Source contains empty URL values; resolve them before building D1.")
    unexpected = sorted(set(frame["type"]) - set(LABELS))
    if unexpected:
        raise ValueError(f"Unexpected labels {unexpected}; expected only {list(LABELS)}.")
    if frame["type"].eq("").any():
        raise ValueError("Source contains empty labels.")
    return frame


def add_normalization(frame: pd.DataFrame) -> pd.DataFrame:
    results = [normalize(value) for value in frame["URL"]]
    out = frame.copy()
    out["norm_url"] = [result.normalized for result in results]
    out["cache_key"] = [result.cache_key for result in results]
    out["norm_error"] = [result.error for result in results]
    out["registrable_domain"] = [result.registrable_domain for result in results]
    out["public_suffix"] = [result.public_suffix for result in results]
    out["scheme"] = [result.scheme for result in results]
    out["path"] = [result.path for result in results]
    out["is_ip_host"] = [bool(result.is_ip_host) for result in results]
    out["is_punycode"] = [bool(result.is_punycode) for result in results]
    out["raw_length"] = [int(result.raw_length) for result in results]
    return out


def deduplicate(frame: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int], pd.DataFrame]:
    """Drop exact duplicates, then same-label normalized duplicates.

    A normalized URL carrying conflicting labels is not silently resolved; it is
    returned separately and causes the build to stop.
    """
    before = len(frame)
    exact = frame.drop_duplicates(subset=["URL", "type"], keep="first").copy()
    exact_dropped = before - len(exact)

    conflicts = (
        exact.groupby("norm_url", dropna=False)["type"].nunique()
        .loc[lambda values: values > 1]
    )
    if not conflicts.empty:
        conflict_rows = exact[exact["norm_url"].isin(conflicts.index)].copy()
        return exact, {
            "exact_duplicates_dropped": int(exact_dropped),
            "normalized_duplicates_dropped": 0,
        }, conflict_rows

    normalized = exact.drop_duplicates(subset=["norm_url", "type"], keep="first").copy()
    normalized_dropped = len(exact) - len(normalized)
    return normalized, {
        "exact_duplicates_dropped": int(exact_dropped),
        "normalized_duplicates_dropped": int(normalized_dropped),
    }, pd.DataFrame(columns=frame.columns)


def apply_domain_cap(frame: pd.DataFrame, seed: int = SEED) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, dict]]:
    """Apply max(50, ceil(1% of class rows)) per registrable domain and class.

    Rows without a registrable domain are excluded to a separate review file,
    not grouped under a fabricated shared key.
    """
    valid = frame[frame["registrable_domain"].notna() & frame["registrable_domain"].ne("")].copy()
    no_domain = frame.loc[~frame.index.isin(valid.index)].copy()
    kept_parts: List[pd.DataFrame] = []
    details: Dict[str, dict] = {}

    for label in LABELS:
        subset = valid[valid["type"] == label].copy()
        cap = max(50, int(math.ceil(0.01 * len(subset))))
        # Stable hash ordering avoids source-order preference and is reproducible.
        subset["_selection_hash"] = subset["norm_url"].map(
            lambda value: sha256_text(f"{seed}|{label}|{value}")
        )
        subset = subset.sort_values(
            ["registrable_domain", "_selection_hash"], kind="mergesort"
        )
        subset["_domain_rank"] = subset.groupby("registrable_domain").cumcount() + 1
        kept = subset[subset["_domain_rank"] <= cap].copy()
        dropped = subset[subset["_domain_rank"] > cap].copy()
        details[label] = {
            "rows_before_cap": int(len(frame[frame["type"] == label])),
            "rows_with_domain": int(len(subset)),
            "cap_per_domain": int(cap),
            "domains": int(subset["registrable_domain"].nunique()),
            "domains_over_cap": int((subset.groupby("registrable_domain").size() > cap).sum()),
            "rows_dropped_by_cap": int(len(dropped)),
            "rows_without_domain": int((frame["type"] == label).sum() - len(subset)),
            "rows_after_cap": int(len(kept)),
        }
        kept_parts.append(kept.drop(columns=["_selection_hash", "_domain_rank"]))
    capped = pd.concat(kept_parts, ignore_index=True)
    capped = capped.sort_values(["type", "registrable_domain", "norm_url"], kind="mergesort").reset_index(drop=True)
    return capped, no_domain, details


def concentration_report(frame: pd.DataFrame) -> dict:
    report = {}
    for label in LABELS:
        subset = frame[frame["type"] == label]
        counts = subset["registrable_domain"].value_counts()
        bare_homepage = (
            subset["path"].fillna("").isin(["", "/"])
            & subset["norm_url"].fillna("").map(lambda value: "?" not in value)
        )
        report[label] = {
            "rows": int(len(subset)),
            "unique_registrable_domains": int(subset["registrable_domain"].nunique()),
            "top_20_domains": [
                {"domain": str(domain), "count": int(count)}
                for domain, count in counts.head(20).items()
            ],
            "bare_homepage_rows": int(bare_homepage.sum()),
            "bare_homepage_share": round(float(bare_homepage.mean()), 6) if len(subset) else 0.0,
        }
    return report


def grouped_holdout(frame: pd.DataFrame, seed: int = SEED) -> Tuple[pd.DataFrame, pd.DataFrame]:
    if frame["registrable_domain"].isna().any():
        raise ValueError("Grouped split requires a registrable_domain for every retained row.")
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    y = frame["type"].to_numpy()
    groups = frame["registrable_domain"].to_numpy()
    train_idx, test_idx = next(splitter.split(frame, y, groups))
    train = frame.iloc[train_idx].copy().reset_index(drop=True)
    test = frame.iloc[test_idx].copy().reset_index(drop=True)
    overlap = set(train["registrable_domain"]) & set(test["registrable_domain"])
    if overlap:
        raise AssertionError(f"Domain leakage detected in grouped holdout: {len(overlap)} domains.")
    return train, test


def random_stratified_holdout(frame: pd.DataFrame, seed: int = SEED) -> Tuple[pd.DataFrame, pd.DataFrame]:
    train, test = train_test_split(
        frame, test_size=0.20, random_state=seed, stratify=frame["type"]
    )
    return train.reset_index(drop=True), test.reset_index(drop=True)


def make_cv_manifest(train: pd.DataFrame) -> dict:
    folds = {}
    for seed in CV_SEEDS:
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        seed_folds = []
        for fold_number, (fit_idx, validation_idx) in enumerate(
            splitter.split(train, train["type"], train["registrable_domain"]), start=1
        ):
            fit_domains = set(train.iloc[fit_idx]["registrable_domain"])
            validation_domains = set(train.iloc[validation_idx]["registrable_domain"])
            overlap = fit_domains & validation_domains
            if overlap:
                raise AssertionError(f"CV domain leakage in seed {seed}, fold {fold_number}.")
            seed_folds.append({
                "fold": fold_number,
                "fit_row_indices": fit_idx.tolist(),
                "validation_row_indices": validation_idx.tolist(),
                "fit_rows": int(len(fit_idx)),
                "validation_rows": int(len(validation_idx)),
                "domain_overlap": 0,
            })
        folds[str(seed)] = seed_folds
    return {
        "method": "StratifiedGroupKFold",
        "n_splits": 5,
        "seeds": list(CV_SEEDS),
        "group_column": "registrable_domain",
        "index_basis": "data/splits/train.csv row positions (zero-based)",
        "folds": folds,
    }


def class_counts(frame: pd.DataFrame) -> dict:
    counts = frame["type"].value_counts().to_dict()
    return {label: int(counts.get(label, 0)) for label in LABELS}


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(source: pathlib.Path, root: pathlib.Path, seed: int = SEED) -> dict:
    source = source.resolve()
    root = root.resolve()
    data_dir = root / "data"
    raw_dir = data_dir / "raw"
    processed_dir = data_dir / "processed"
    splits_dir = data_dir / "splits"
    reports_dir = data_dir / "reports"
    for directory in (raw_dir, processed_dir, splits_dir, reports_dir):
        directory.mkdir(parents=True, exist_ok=True)

    original = load_source(source)
    normalized = add_normalization(original)
    normalization_errors = normalized[normalized["norm_error"].notna()].copy()
    if not normalization_errors.empty:
        (reports_dir / "normalization_errors.csv").parent.mkdir(parents=True, exist_ok=True)
        normalization_errors.to_csv(reports_dir / "normalization_errors.csv", index=False)
        raise ValueError(
            f"{len(normalization_errors)} URL(s) failed normalization. "
            "See data/reports/normalization_errors.csv; fix/review before proceeding."
        )

    deduped, dedupe_stats, conflicts = deduplicate(normalized)
    if not conflicts.empty:
        conflicts.to_csv(reports_dir / "label_conflicts.csv", index=False)
        raise ValueError(
            f"{conflicts['norm_url'].nunique()} normalized URL(s) have conflicting labels. "
            "See data/reports/label_conflicts.csv; resolve labels before proceeding."
        )

    capped, no_domain, cap_stats = apply_domain_cap(deduped, seed=seed)
    if capped.empty:
        raise ValueError("No rows remain after domain validation and capping.")

    # Save retained D1 with only stable source and normalized metadata.
    cleaned_path = processed_dir / "D1_cleaned.csv"
    capped.to_csv(cleaned_path, index=False)
    no_domain_path = reports_dir / "D1_without_registrable_domain.csv"
    no_domain.to_csv(no_domain_path, index=False)

    # Human label review sample, 100 per class (or all rows if fewer).
    review_parts = []
    for label in LABELS:
        group = capped[capped["type"] == label]
        review_parts.append(group.sample(n=min(100, len(group)), random_state=seed))
    review = pd.concat(review_parts, ignore_index=True).sort_values(
        ["type", "registrable_domain", "norm_url"]
    )
    review_path = data_dir / "review_sample_chunk3.csv"
    review[["URL", "type", "norm_url", "registrable_domain"]].to_csv(review_path, index=False)

    grouped_train, grouped_test = grouped_holdout(capped, seed=seed)
    grouped_train_path = splits_dir / "train.csv"
    grouped_test_path = splits_dir / "test.csv"
    grouped_train.to_csv(grouped_train_path, index=False)
    grouped_test.to_csv(grouped_test_path, index=False)

    random_train, random_test = random_stratified_holdout(capped, seed=seed)
    random_dir = splits_dir / "random_stratified"
    random_dir.mkdir(parents=True, exist_ok=True)
    random_train.to_csv(random_dir / "train.csv", index=False)
    random_test.to_csv(random_dir / "test.csv", index=False)

    cv_manifest = make_cv_manifest(grouped_train)
    cv_path = splits_dir / "cv_folds.json"
    write_json(cv_path, cv_manifest)

    grouped_overlap = sorted(set(grouped_train["registrable_domain"]) & set(grouped_test["registrable_domain"]))
    random_overlap = sorted(set(random_train["registrable_domain"]) & set(random_test["registrable_domain"]))
    cap_group_counts = capped.groupby(["type", "registrable_domain"]).size()
    cap_violations = int((cap_group_counts > cap_stats[LABELS[0]]["cap_per_domain"]).sum())
    # Validate each class against its own cap.
    cap_violations = sum(
        int((capped[capped["type"] == label].groupby("registrable_domain").size() > cap_stats[label]["cap_per_domain"]).sum())
        for label in LABELS
    )

    cleaning_report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "seed": int(seed),
        "source_file": source.name,
        "source_sha256": sha256_file(source),
        "rows": {
            "source": int(len(original)),
            "after_normalization": int(len(normalized)),
            "after_exact_and_normalized_deduplication": int(len(deduped)),
            "after_domain_validation_and_cap": int(len(capped)),
            "without_registrable_domain": int(len(no_domain)),
        },
        "class_counts_source": class_counts(original),
        "class_counts_cleaned": class_counts(capped),
        "deduplication": dedupe_stats,
        "domain_cap": cap_stats,
        "normalization_errors": int(len(normalization_errors)),
        "normalized_cross_label_conflicts": 0,
        "domain_cap_violations": int(cap_violations),
        "output_sha256": {
            "D1_cleaned.csv": sha256_file(cleaned_path),
            "train.csv": sha256_file(grouped_train_path),
            "test.csv": sha256_file(grouped_test_path),
        },
    }
    concentration = concentration_report(capped)
    split_report = {
        "seed": int(seed),
        "grouped_method": "StratifiedGroupKFold(n_splits=5, shuffle=True); first fold used as 20% hold-out",
        "group_column": "registrable_domain",
        "grouped": {
            "train_rows": int(len(grouped_train)),
            "test_rows": int(len(grouped_test)),
            "train_class_counts": class_counts(grouped_train),
            "test_class_counts": class_counts(grouped_test),
            "domain_overlap_count": len(grouped_overlap),
            "train_domains": int(grouped_train["registrable_domain"].nunique()),
            "test_domains": int(grouped_test["registrable_domain"].nunique()),
        },
        "random_stratified_comparison": {
            "train_rows": int(len(random_train)),
            "test_rows": int(len(random_test)),
            "train_class_counts": class_counts(random_train),
            "test_class_counts": class_counts(random_test),
            "domain_overlap_count": len(random_overlap),
        },
        "cv_manifest": str(cv_path.relative_to(root)).replace("\\", "/"),
    }
    write_json(reports_dir / "cleaning_report.json", cleaning_report)
    write_json(reports_dir / "concentration_report.json", concentration)
    write_json(splits_dir / "split_manifest.json", split_report)

    summary = [
        "# PhishGuard D1 build summary",
        "",
        f"- Source: `{source.name}`",
        f"- Source SHA-256: `{cleaning_report['source_sha256']}`",
        f"- Source rows: {len(original):,}",
        f"- Cleaned rows: {len(capped):,}",
        f"- Exact duplicates removed: {dedupe_stats['exact_duplicates_dropped']:,}",
        f"- Normalized duplicates removed: {dedupe_stats['normalized_duplicates_dropped']:,}",
        f"- Rows without registrable domain: {len(no_domain):,} (quarantined for review)",
        f"- Grouped train/test: {len(grouped_train):,}/{len(grouped_test):,}",
        f"- Grouped domain overlap: {len(grouped_overlap)}",
        "",
        "## Class counts after cleaning",
        "",
        "| Class | Rows |",
        "|---|---:|",
    ]
    summary.extend(f"| {label} | {count:,} |" for label, count in class_counts(capped).items())
    summary += [
        "",
        "## Outstanding external sets",
        "",
        "- E1 is not generated by this D1 build. It requires genuine benign inner-page URLs from a dated Tranco snapshot.",
        "- E2 is not generated by this D1 build. It requires a dated, licensed and verified phishing feed collected after D1.",
        "- Manual label review must be completed and its observed error rate recorded before the dataset is considered approved.",
        "- D1 source origin, license, collection date and labeling method remain provenance blockers until supplied by the dataset owner.",
    ]
    (reports_dir / "dataset_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")

    return {
        "cleaning_report": cleaning_report,
        "concentration_report": concentration,
        "split_report": split_report,
        "outputs": [
            str(cleaned_path), str(grouped_train_path), str(grouped_test_path),
            str(cv_path), str(review_path), str(reports_dir / "cleaning_report.json"),
            str(reports_dir / "concentration_report.json"), str(reports_dir / "dataset_summary.md"),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PhishGuard's cleaned D1 dataset and grouped splits.")
    parser.add_argument("--dataset", required=True, help="Path to the original D1 CSV.")
    parser.add_argument("--root", default=str(ROOT), help="PhishGuard repository root.")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    result = build(pathlib.Path(args.dataset), pathlib.Path(args.root), seed=args.seed)
    print(json.dumps({
        "rows_cleaned": result["cleaning_report"]["rows"]["after_domain_validation_and_cap"],
        "class_counts": result["cleaning_report"]["class_counts_cleaned"],
        "grouped_train_rows": result["split_report"]["grouped"]["train_rows"],
        "grouped_test_rows": result["split_report"]["grouped"]["test_rows"],
        "grouped_domain_overlap": result["split_report"]["grouped"]["domain_overlap_count"],
        "outputs": result["outputs"],
    }, indent=2))


if __name__ == "__main__":
    main()
