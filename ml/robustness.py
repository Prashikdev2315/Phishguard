#!/usr/bin/env python3
"""Chunk 6 robustness experiment with train-fold-only augmentation."""
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.evaluate import (  # noqa: E402
    CALIBRATION_SEEDS,
    DEFAULT_BLOCK_THRESHOLD,
    _metric_at_threshold,
    apply_calibrator,
    ece,
    evaluate_adversarial,
    fit_calibrator,
)
from ml.features import extract_vector  # noqa: E402
from ml.train import (  # noqa: E402
    LABEL_MAP,
    build_pipeline,
    load_split,
    _get_proba,
)


def _transform_url(url: str, variant: str) -> str:
    parts = url.split("://", 1)
    prefix = (parts[0] + "://") if len(parts) == 2 else "http://"
    remainder = parts[1] if len(parts) == 2 else parts[0]
    host, separator, path = remainder.partition("/")
    path = "/" + path if separator else ""
    if variant == "benign_path_token":
        return prefix + host + "/about/news"
    if variant == "brand_subdomain":
        return prefix + "login." + host + path
    if variant == "hyphen_digit_host":
        return prefix + host.replace(".", "-1.", 1) + path
    if variant == "long_path":
        return prefix + host + "/home/" + ("about/" * 4)
    raise ValueError(f"Unknown augmentation variant: {variant}")


AUGMENTATION_VARIANTS = (
    "benign_path_token",
    "brand_subdomain",
    "hyphen_digit_host",
    "long_path",
)


def augment_training_rows(
    urls: Sequence[str],
    labels: Sequence[int],
    source_indices: Sequence[int],
) -> Tuple[List[str], np.ndarray, List[dict]]:
    """Augment only the supplied source rows; labels remain unchanged."""
    if len(urls) != len(labels):
        raise ValueError("urls and labels must have equal length")
    augmented_urls: List[str] = []
    augmented_labels: List[int] = []
    metadata: List[dict] = []
    for source_index in source_indices:
        url = urls[source_index]
        label = int(labels[source_index])
        augmented_urls.append(url)
        augmented_labels.append(label)
        metadata.append({"source_index": int(source_index), "variant": "original"})
        for variant in AUGMENTATION_VARIANTS:
            augmented_urls.append(_transform_url(url, variant))
            augmented_labels.append(label)
            metadata.append({"source_index": int(source_index), "variant": variant})
    return augmented_urls, np.asarray(augmented_labels, dtype=np.int32), metadata


def _features(urls: Sequence[str]) -> np.ndarray:
    return np.asarray([extract_vector(url) for url in urls], dtype=float)


def _fit_fold(
    urls: Sequence[str],
    labels: np.ndarray,
    fit_indices: np.ndarray,
    validation_indices: np.ndarray,
    seed: int,
    manifest: dict,
) -> Tuple[np.ndarray, np.ndarray]:
    augmented_urls, augmented_labels, _ = augment_training_rows(urls, labels, fit_indices)
    pipeline = build_pipeline(manifest["selector"], manifest["classifier"], int(manifest["k"]), seed)
    pipeline.fit(_features(augmented_urls), augmented_labels)
    return pipeline, validation_indices


def _oof_augmented(
    urls: Sequence[str],
    labels: np.ndarray,
    groups: np.ndarray,
    manifest: dict,
) -> Tuple[np.ndarray, List[dict]]:
    probabilities = []
    per_seed = []
    for seed in CALIBRATION_SEEDS:
        fold_probabilities = np.full(len(labels), np.nan, dtype=float)
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        for fit_indices, validation_indices in splitter.split(urls, labels, groups):
            pipeline, validation_indices = _fit_fold(
                urls, labels, fit_indices, validation_indices, seed, manifest
            )
            fold_probabilities[validation_indices] = _get_proba(
                pipeline, _features([urls[index] for index in validation_indices])
            )
        if np.isnan(fold_probabilities).any():
            raise AssertionError(f"Augmented OOF predictions incomplete for seed {seed}")
        probabilities.append(fold_probabilities)
        per_seed.append({"seed": seed, "raw_oof_ece": ece(labels, fold_probabilities)})
    return np.mean(probabilities, axis=0), per_seed


def _fit_final(
    urls: Sequence[str],
    labels: np.ndarray,
    manifest: dict,
):
    indices = np.arange(len(labels))
    augmented_urls, augmented_labels, metadata = augment_training_rows(urls, labels, indices)
    pipeline = build_pipeline(manifest["selector"], manifest["classifier"], int(manifest["k"]), 42)
    pipeline.fit(_features(augmented_urls), augmented_labels)
    return pipeline, metadata


def _adversarial_metrics(
    pipeline,
    calibration: dict,
    urls: Sequence[str],
    labels: np.ndarray,
    threshold: float,
) -> dict:
    malicious_urls = [url for url, label in zip(urls, labels) if label == 1]
    variants = []
    for url in malicious_urls:
        for variant in AUGMENTATION_VARIANTS:
            variants.append({"source_url": url, "variant": variant, "url": _transform_url(url, variant)})
    clean_probabilities = apply_calibrator(calibration, _get_proba(pipeline, _features(malicious_urls)))
    transformed_probabilities = apply_calibrator(
        calibration, _get_proba(pipeline, _features([item["url"] for item in variants]))
    )
    clean_recall = float(np.mean(clean_probabilities >= threshold))
    drops = {}
    for variant in AUGMENTATION_VARIANTS:
        indices = [index for index, item in enumerate(variants) if item["variant"] == variant]
        recall = float(np.mean(transformed_probabilities[indices] >= threshold))
        drops[variant] = round(clean_recall - recall, 6)
    return {
        "clean_recall": round(clean_recall, 6),
        "recall_drops": drops,
        "worst_recall_drop": round(max(drops.values()), 6),
        "status": "PASS" if max(drops.values()) <= 0.10 else "FAIL",
    }


def run_augmentation_experiment(root: pathlib.Path) -> dict:
    train_path = root / "data" / "splits" / "train.csv"
    test_path = root / "data" / "splits" / "test.csv"
    manifest = json.loads(
        (root / "ml" / "models" / "model.manifest.json").read_text(encoding="utf-8")
    )
    train_frame = pd.read_csv(train_path, dtype=str, keep_default_na=False)
    test_frame = pd.read_csv(test_path, dtype=str, keep_default_na=False)
    train_urls = train_frame["URL"].tolist()
    test_urls = test_frame["URL"].tolist()
    train_labels = train_frame["type"].map(LABEL_MAP).to_numpy(dtype=np.int32)
    test_labels = test_frame["type"].map(LABEL_MAP).to_numpy(dtype=np.int32)
    groups = train_frame["registrable_domain"].to_numpy()

    raw_oof, oof_details = _oof_augmented(train_urls, train_labels, groups, manifest)
    calibration = fit_calibrator(raw_oof, train_labels)
    pipeline, metadata = _fit_final(train_urls, train_labels, manifest)
    test_probabilities = apply_calibrator(calibration, _get_proba(pipeline, _features(test_urls)))
    test_metrics = _metric_at_threshold(test_labels, test_probabilities, DEFAULT_BLOCK_THRESHOLD)
    adversarial = _adversarial_metrics(
        pipeline, calibration, test_urls, test_labels, DEFAULT_BLOCK_THRESHOLD
    )

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "augmentation": {
            "variants": list(AUGMENTATION_VARIANTS),
            "classes_augmented": ["Benign", "Malicious"],
            "train_only": True,
            "original_training_rows": len(train_urls),
            "augmented_training_rows": len(metadata),
            "oof_seeds": oof_details,
        },
        "metrics_at_T_0.70": test_metrics,
        "adversarial": adversarial,
        "calibration": {
            "method": calibration["method"],
            "selected_ece": calibration["selected_ece"],
        },
    }
    report_dir = root / "ml" / "report"
    (report_dir / "robustness_augmentation_D1.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    print(json.dumps(run_augmentation_experiment(ROOT), indent=2))
