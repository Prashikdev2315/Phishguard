#!/usr/bin/env python3
"""Diagnose Chunk 6 adversarial failures and path-feature dependence."""
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.evaluate import (  # noqa: E402
    CALIBRATION_SEEDS,
    DEFAULT_BLOCK_THRESHOLD,
    _get_proba,
    _metric_at_threshold,
    _oof_predictions_by_seed,
    apply_calibrator,
    evaluate_adversarial,
    fit_calibrator,
    generate_adversarial_urls,
)
from ml.features import FEATURE_NAMES, extract_vector  # noqa: E402
from ml.train import build_pipeline, load_split  # noqa: E402


def _retrain_model(root: pathlib.Path):
    train_path = root / "data" / "splits" / "train.csv"
    test_path = root / "data" / "splits" / "test.csv"
    manifest = json.loads(
        (root / "ml" / "models" / "model.manifest.json").read_text(encoding="utf-8")
    )
    X_train, y_train, groups = load_split(train_path, cache_dir=root / "data" / "processed")
    X_test, y_test, _ = load_split(test_path, cache_dir=root / "data" / "processed")
    model = build_pipeline(manifest["selector"], manifest["classifier"], int(manifest["k"]), 42)
    model.fit(X_train, y_train)
    return manifest, X_train, y_train, groups, X_test, y_test, model


def _fit_reduced_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    groups: np.ndarray,
    X_test: np.ndarray,
    manifest: dict,
    dropped: Sequence[int],
):
    keep = [i for i in range(X_train.shape[1]) if i not in set(dropped)]
    per_seed = _oof_predictions_by_seed(
        X_train[:, keep], y_train, groups,
        manifest["selector"], manifest["classifier"], int(manifest["k"]),
    )
    raw_oof = np.mean([item[2] for item in per_seed], axis=0)
    calibration = fit_calibrator(raw_oof, y_train)
    model = build_pipeline(manifest["selector"], manifest["classifier"], int(manifest["k"]), 42)
    model.fit(X_train[:, keep], y_train)
    return model, calibration, keep, X_test[:, keep]


def _adversarial_arrays(urls: Sequence[str], labels: np.ndarray, dropped: Sequence[int]):
    malicious = [url for url, label in zip(urls, labels) if label == 1]
    variants = generate_adversarial_urls(malicious)
    clean = np.asarray([extract_vector(url) for url in malicious], dtype=float)
    transformed = np.asarray([extract_vector(item["url"]) for item in variants], dtype=float)
    keep = [i for i in range(clean.shape[1]) if i not in set(dropped)]
    return malicious, variants, clean[:, keep], transformed[:, keep], keep


def _score_importance(model, X: np.ndarray, label: str) -> dict:
    if len(X) == 0:
        return {"group": label, "n": 0, "features": []}

    def positive_score(estimator, values, _target):
        return float(np.mean(_get_proba(estimator, values)))

    result = permutation_importance(
        model, X, np.ones(len(X), dtype=int), scoring=positive_score,
        n_repeats=10, random_state=42, n_jobs=1,
    )
    ranked = np.argsort(result.importances_mean)[::-1][:10]
    return {
        "group": label,
        "n": int(len(X)),
        "features": [
            {
                "feature": FEATURE_NAMES[index],
                "mean_importance": round(float(result.importances_mean[index]), 8),
                "std": round(float(result.importances_std[index]), 8),
            }
            for index in ranked
        ],
    }


def _path_correlation(root: pathlib.Path) -> dict:
    frame = pd.read_csv(root / "data" / "processed" / "D1_cleaned.csv", dtype=str)
    empty = frame["path"].fillna("").eq("") | frame["path"].fillna("").eq("/")
    grouped = frame.assign(empty_path=empty).groupby("type")["empty_path"].agg(["count", "sum"])
    return {
        label: {
            "rows": int(values["count"]),
            "empty_path_rows": int(values["sum"]),
            "empty_path_fraction": round(float(values["sum"] / values["count"]), 6),
        }
        for label, values in grouped.iterrows()
    }


def run_diagnosis(root: pathlib.Path) -> dict:
    manifest, X_train, y_train, groups, X_test, y_test, model = _retrain_model(root)
    test_frame = pd.read_csv(root / "data" / "splits" / "test.csv", dtype=str, keep_default_na=False)
    test_urls = test_frame["URL"].tolist()
    calibration = fit_calibrator(
        np.mean([
            item[2] for item in _oof_predictions_by_seed(
                X_train, y_train, groups,
                manifest["selector"], manifest["classifier"], int(manifest["k"]),
            )
        ], axis=0),
        y_train,
    )
    clean_prob = apply_calibrator(calibration, _get_proba(model, X_test))
    malicious_urls = [url for url, label in zip(test_urls, y_test) if label == 1]
    variants = generate_adversarial_urls(malicious_urls)
    brand = [item for item in variants if item["variant"] == "brand_subdomain"]
    brand_X = np.asarray([extract_vector(item["url"]) for item in brand], dtype=float)
    brand_prob = apply_calibrator(calibration, _get_proba(model, brand_X))
    clean_malicious_prob = clean_prob[y_test == 1]
    flipped = (clean_malicious_prob >= DEFAULT_BLOCK_THRESHOLD) & (brand_prob < DEFAULT_BLOCK_THRESHOLD)
    unflipped = (clean_malicious_prob >= DEFAULT_BLOCK_THRESHOLD) & (brand_prob >= DEFAULT_BLOCK_THRESHOLD)
    flip_indexes = np.flatnonzero(flipped)
    unflip_indexes = np.flatnonzero(unflipped)
    importance = [
        _score_importance(model, brand_X[flip_indexes], "brand_subdomain_flipped"),
        _score_importance(model, brand_X[unflip_indexes], "brand_subdomain_unflipped"),
    ]

    dropped = [FEATURE_NAMES.index("path_length"), FEATURE_NAMES.index("path_entropy")]
    ablation_model, ablation_cal, keep, X_test_reduced = _fit_reduced_model(
        X_train, y_train, groups, X_test, manifest, dropped
    )
    ablation_prob = apply_calibrator(ablation_cal, _get_proba(ablation_model, X_test_reduced))
    ablation_metrics = _metric_at_threshold(y_test, ablation_prob, DEFAULT_BLOCK_THRESHOLD)
    ablation_clean, ablation_variants, ablation_clean_X, ablation_variant_X, _ = _adversarial_arrays(
        test_urls, y_test, dropped
    )
    clean_ablation_prob = apply_calibrator(
        ablation_cal, _get_proba(ablation_model, ablation_clean_X)
    )
    ablation_variant_prob = apply_calibrator(
        ablation_cal, _get_proba(ablation_model, ablation_variant_X)
    )
    ablation_drops = {}
    clean_recall = float(np.mean(clean_ablation_prob >= DEFAULT_BLOCK_THRESHOLD))
    for variant_type in sorted({item["variant"] for item in ablation_variants}):
        indexes = [i for i, item in enumerate(ablation_variants) if item["variant"] == variant_type]
        recall = float(np.mean(ablation_variant_prob[indexes] >= DEFAULT_BLOCK_THRESHOLD))
        ablation_drops[variant_type] = round(clean_recall - recall, 6)

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": {
            "selector": manifest["selector"],
            "classifier": manifest["classifier"],
            "k": manifest["k"],
            "threshold": DEFAULT_BLOCK_THRESHOLD,
        },
        "brand_subdomain": {
            "flipped_count": int(len(flip_indexes)),
            "unflipped_blocked_count": int(len(unflip_indexes)),
            "flip_fraction_of_clean_blocked": round(
                float(len(flip_indexes) / max(len(flip_indexes) + len(unflip_indexes), 1)), 6
            ),
            "permutation_importance": importance,
        },
        "path_ablation": {
            "dropped_features": ["path_length", "path_entropy"],
            "metrics": ablation_metrics,
            "adversarial_recall_drops": ablation_drops,
        },
        "empty_path_label_correlation": _path_correlation(root),
    }
    report_dir = root / "ml" / "report"
    (report_dir / "diagnosis_chunk6.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(run_diagnosis(ROOT), indent=2))
