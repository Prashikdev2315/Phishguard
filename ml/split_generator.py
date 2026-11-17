"""Generate domain-disjoint experimental splits without touching data/splits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, Tuple

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from ml.normalize import normalize


def seed_buckets(seed_domains: Iterable[str]) -> Dict[str, set[str]]:
    """Deterministically assign 19/3/4 seed domains when seed rows exist."""
    domains = sorted(set(seed_domains))
    if len(domains) != 26:
        raise ValueError(f"Expected 26 seed domains, got {len(domains)}")
    return {
        "train": set(domains[:19]),
        "probe": set(domains[19:22]),
        "e1": set(domains[22:]),
    }


def _registrable(value: str) -> str:
    result = normalize(value)
    if result.error or not result.registrable_domain:
        raise ValueError(f"Cannot derive registrable domain from {value!r}")
    return result.registrable_domain


def make_splits(
    d1_path: Path,
    e1_path: Path,
    output_dir: Path,
    seed: int = 42,
) -> dict:
    """Write train, D1 test, and E1 holdout files under ``output_dir`` only."""
    d1 = pd.read_csv(d1_path, dtype=str, keep_default_na=False)
    e1 = pd.read_csv(e1_path, dtype=str, keep_default_na=False)
    d1["registrable_domain"] = d1["registrable_domain"].map(_registrable)
    e1["registrable_domain"] = e1["domain"].map(_registrable)
    e1["type"] = "Benign"
    e1["norm_error"] = ""

    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    train_idx, test_idx = next(splitter.split(d1, d1["type"], d1["registrable_domain"]))
    d1_train = d1.iloc[train_idx].copy()
    d1_test = d1.iloc[test_idx].copy()
    d1_test_domains = set(d1_test["registrable_domain"])

    e1_domains = sorted(set(e1["registrable_domain"]) - set(d1["registrable_domain"]))
    e1_cut = len(e1_domains) // 2
    e1_train_domains = set(e1_domains[:e1_cut])
    e1_holdout_domains = set(e1_domains[e1_cut:])
    e1_train = e1[e1["registrable_domain"].isin(e1_train_domains)].copy()
    e1_holdout = e1[e1["registrable_domain"].isin(e1_holdout_domains)].copy()
    train = pd.concat([d1_train, e1_train], ignore_index=True)

    overlaps = {
        "train_test": len(set(train["registrable_domain"]) & d1_test_domains),
        "train_e1_holdout": len(set(train["registrable_domain"]) & e1_holdout_domains),
        "test_e1_holdout": len(d1_test_domains & e1_holdout_domains),
    }
    if any(overlaps.values()):
        raise AssertionError(f"Domain leakage detected: {overlaps}")

    output_dir.mkdir(parents=True, exist_ok=True)
    train.to_csv(output_dir / "train.csv", index=False)
    d1_test.to_csv(output_dir / "d1_test.csv", index=False)
    e1_holdout.to_csv(output_dir / "e1_holdout.csv", index=False)
    report = {
        "seed": seed,
        "train_rows": len(train),
        "d1_test_rows": len(d1_test),
        "e1_holdout_rows": len(e1_holdout),
        "train_domains": train["registrable_domain"].nunique(),
        "d1_test_domains": len(d1_test_domains),
        "e1_holdout_domains": len(e1_holdout_domains),
        "overlaps": overlaps,
    }
    (output_dir / "split_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--d1", type=Path, required=True)
    parser.add_argument("--e1", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/splits_v2"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(make_splits(args.d1, args.e1, args.output, args.seed), indent=2))


if __name__ == "__main__":
    main()
