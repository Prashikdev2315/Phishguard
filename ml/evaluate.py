#!/usr/bin/env python3
"""Chunk 6 calibration and release-gate evaluation.

Calibration is fit only from grouped out-of-fold predictions on the training
partition.  The locked D1 test split is used once for final reporting.  E1/E2
are optional inputs; when they are absent the corresponding gates remain
explicitly not measurable rather than being inferred from D1.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("PHISHGUARD_ENV", "development")

# Joblib models produced by the benchmark resolve selector classes through the
# importing module when loaded; keep the classes available in this namespace.
from ml.train import _L1Selector, _RFImportanceSelector  # noqa: E402,F401
from ml.features import extract_vector  # noqa: E402
from ml.train import (  # noqa: E402
    LABEL_MAP,
    build_pipeline,
    compute_metrics,
    load_split,
    _get_proba,
)

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

CALIBRATION_SEEDS = (42, 43, 44)
N_SPLITS = 5
DEFAULT_BLOCK_THRESHOLD = 0.70
DEFAULT_WARN_THRESHOLD = 0.35


def ece(y_true: np.ndarray, probabilities: np.ndarray, n_bins: int = 10) -> float:
    """Return expected calibration error using equal-width probability bins."""
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    if len(y_true) != len(probabilities):
        raise ValueError("y_true and probabilities must have equal length")
    if len(y_true) == 0:
        return 0.0
    probabilities = np.clip(probabilities, 0.0, 1.0)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    total = 0.0
    for index in range(n_bins):
        mask = (probabilities >= edges[index]) & (
            (probabilities < edges[index + 1]) if index < n_bins - 1 else (probabilities <= 1.0)
        )
        if mask.any():
            total += mask.sum() * abs(y_true[mask].mean() - probabilities[mask].mean())
    return float(total / len(y_true))


def _validate_probability_inputs(raw_probabilities: Sequence[float], y_true: np.ndarray) -> np.ndarray:
    probabilities = np.asarray(raw_probabilities, dtype=float)
    if probabilities.ndim != 1 or len(probabilities) != len(y_true):
        raise ValueError("probabilities must be a one-dimensional array matching y_true")
    if not np.isfinite(probabilities).all():
        raise ValueError("probabilities must contain only finite values")
    return np.clip(probabilities, 0.0, 1.0)


def fit_calibrator(
    raw_probabilities: Sequence[float],
    y_true: np.ndarray,
    *,
    isotonic_minimum: int = 1000,
) -> dict:
    """Fit Platt scaling, optionally selecting isotonic when it lowers ECE."""
    y_true = np.asarray(y_true, dtype=int)
    raw = _validate_probability_inputs(raw_probabilities, y_true)
    if len(np.unique(y_true)) < 2:
        raise ValueError("calibration requires both classes")

    # Logistic regression on logit(p) is Platt scaling and preserves monotonicity.
    eps = np.finfo(float).eps
    logits = np.log(np.clip(raw, eps, 1.0 - eps) / np.clip(1.0 - raw, eps, 1.0))
    platt = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000)
    platt.fit(logits.reshape(-1, 1), y_true)
    platt_prob = platt.predict_proba(logits.reshape(-1, 1))[:, 1]

    selected = "platt"
    calibrator = platt
    isotonic_ece = None
    if len(raw) >= isotonic_minimum:
        isotonic = IsotonicRegression(out_of_bounds="clip")
        isotonic.fit(raw, y_true)
        isotonic_prob = isotonic.predict(raw)
        isotonic_ece = ece(y_true, isotonic_prob)
        if isotonic_ece < ece(y_true, platt_prob):
            selected = "isotonic"
            calibrator = isotonic

    return {
        "method": selected,
        "calibrator": calibrator,
        "raw_ece": ece(y_true, raw),
        "platt_ece": ece(y_true, platt_prob),
        "isotonic_ece": isotonic_ece,
        "selected_ece": isotonic_ece if selected == "isotonic" else ece(y_true, platt_prob),
        "sample_count": int(len(y_true)),
    }


def apply_calibrator(calibration: dict, raw_probabilities: Sequence[float]) -> np.ndarray:
    """Apply a calibrator returned by :func:`fit_calibrator`."""
    raw = np.asarray(raw_probabilities, dtype=float)
    if not np.isfinite(raw).all():
        raise ValueError("probabilities must contain only finite values")
    raw = np.clip(raw, 0.0, 1.0)
    if calibration["method"] == "isotonic":
        result = calibration["calibrator"].predict(raw)
    else:
        eps = np.finfo(float).eps
        logits = np.log(np.clip(raw, eps, 1.0 - eps) / np.clip(1.0 - raw, eps, 1.0))
        result = calibration["calibrator"].predict_proba(logits.reshape(-1, 1))[:, 1]
    return np.clip(np.asarray(result, dtype=float), 0.0, 1.0)


def _metric_at_threshold(y_true: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict:
    predicted = (probabilities >= threshold).astype(int)
    return compute_metrics(y_true, predicted, probabilities)


def choose_warn_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    *,
    minimum_recall: float = 0.90,
    maximum_fpr: float = 0.05,
) -> Optional[float]:
    """Choose the lowest threshold satisfying warning recall and FPR limits."""
    candidates = np.unique(np.concatenate(([0.0, 1.0], np.asarray(probabilities, dtype=float))))
    valid = [
        float(t) for t in candidates
        if _metric_at_threshold(y_true, probabilities, float(t))["recall"] >= minimum_recall
        and _metric_at_threshold(y_true, probabilities, float(t))["fpr"] <= maximum_fpr
    ]
    return min(valid) if valid else None


def choose_block_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    *,
    maximum_fpr: float = 0.005,
) -> Optional[float]:
    """Choose the lowest threshold satisfying the block FPR target."""
    candidates = np.unique(np.concatenate(([0.0, 1.0], np.asarray(probabilities, dtype=float))))
    valid = [
        float(t) for t in candidates
        if _metric_at_threshold(y_true, probabilities, float(t))["fpr"] <= maximum_fpr
    ]
    return min(valid) if valid else None


def generate_adversarial_urls(urls: Iterable[str]) -> List[dict]:
    """Create deterministic URL-only robustness variants for malicious URLs."""
    variants: List[dict] = []
    for url in urls:
        parsed = url.split("://", 1)
        prefix = (parsed[0] + "://") if len(parsed) == 2 else "http://"
        remainder = parsed[1] if len(parsed) == 2 else parsed[0]
        host, separator, path = remainder.partition("/")
        path = "/" + path if separator else ""
        variants.extend([
            {"source_url": url, "variant": "benign_path_token", "url": prefix + host + "/about/news"},
            {"source_url": url, "variant": "brand_subdomain", "url": prefix + "login." + host + path},
            {"source_url": url, "variant": "hyphen_digit_host", "url": prefix + host.replace(".", "-1.", 1) + path},
            {"source_url": url, "variant": "long_path", "url": prefix + host + "/home/" + ("about/" * 4)},
        ])
    return variants


def evaluate_adversarial(
    model: object,
    calibration: dict,
    clean_urls: Sequence[str],
    clean_labels: np.ndarray,
    threshold: float,
) -> dict:
    """Evaluate deterministic URL transformations against clean D1 rows."""
    malicious_urls = [url for url, label in zip(clean_urls, clean_labels) if label == 1]
    variants = generate_adversarial_urls(malicious_urls)
    if not variants:
        return {"status": "NOT_MEASURABLE", "reason": "No malicious URLs available"}
    variant_X = np.asarray([extract_vector(item["url"]) for item in variants], dtype=float)
    variant_probabilities = apply_calibrator(calibration, _get_proba(model, variant_X))
    clean_X = np.asarray([extract_vector(url) for url in malicious_urls], dtype=float)
    clean_probabilities = apply_calibrator(calibration, _get_proba(model, clean_X))
    clean_recall = float(np.mean(clean_probabilities >= threshold))
    variants_by_type: Dict[str, dict] = {}
    for variant_type in sorted({item["variant"] for item in variants}):
        indexes = [i for i, item in enumerate(variants) if item["variant"] == variant_type]
        recall = float(np.mean(variant_probabilities[indexes] >= threshold))
        variants_by_type[variant_type] = {
            "count": len(indexes),
            "recall": round(recall, 6),
            "drop": round(clean_recall - recall, 6),
        }
    worst_drop = max(item["drop"] for item in variants_by_type.values())
    return {
        "status": "PASS" if worst_drop <= 0.10 else "FAIL",
        "threshold": threshold,
        "clean_recall": round(clean_recall, 6),
        "worst_recall_drop": round(worst_drop, 6),
        "variants": variants_by_type,
    }


def _oof_predictions(
    X_train: np.ndarray,
    y_train: np.ndarray,
    groups_train: np.ndarray,
    selector: str,
    classifier: str,
    k: int,
) -> Tuple[np.ndarray, np.ndarray]:
    """Generate grouped OOF probabilities without fitting on validation rows."""
    probabilities = np.full(len(y_train), np.nan, dtype=float)
    for seed in CALIBRATION_SEEDS:
        fold_predictions = np.full(len(y_train), np.nan, dtype=float)
        splitter = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
        for fit_idx, validation_idx in splitter.split(X_train, y_train, groups_train):
            pipeline = build_pipeline(selector, classifier, k, seed)
            pipeline.fit(X_train[fit_idx], y_train[fit_idx])
            fold_predictions[validation_idx] = _get_proba(pipeline, X_train[validation_idx])
        if np.isnan(fold_predictions).any():
            raise AssertionError("OOF calibration predictions are incomplete")
        probabilities = np.nanmean(
            np.vstack([probabilities, fold_predictions]), axis=0
        ) if not np.isnan(probabilities).all() else fold_predictions
    return y_train.copy(), probabilities


def _oof_predictions_by_seed(
    X_train: np.ndarray,
    y_train: np.ndarray,
    groups_train: np.ndarray,
    selector: str,
    classifier: str,
    k: int,
) -> List[Tuple[int, np.ndarray, np.ndarray]]:
    """Return one complete grouped OOF prediction vector per calibration seed."""
    results = []
    for seed in CALIBRATION_SEEDS:
        fold_predictions = np.full(len(y_train), np.nan, dtype=float)
        splitter = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
        for fit_idx, validation_idx in splitter.split(X_train, y_train, groups_train):
            pipeline = build_pipeline(selector, classifier, k, seed)
            pipeline.fit(X_train[fit_idx], y_train[fit_idx])
            fold_predictions[validation_idx] = _get_proba(pipeline, X_train[validation_idx])
        if np.isnan(fold_predictions).any():
            raise AssertionError(f"OOF calibration predictions are incomplete for seed {seed}")
        results.append((seed, y_train.copy(), fold_predictions))
    return results


def _summary(values: Sequence[float]) -> dict:
    """Summarize multi-seed values using a normal-approximation 95% CI."""
    array = np.asarray(values, dtype=float)
    mean = float(np.mean(array))
    std = float(np.std(array, ddof=1)) if len(array) > 1 else 0.0
    margin = 1.96 * std / np.sqrt(len(array)) if len(array) > 1 else 0.0
    return {
        "mean": round(mean, 6),
        "std": round(std, 6),
        "ci95": [round(max(0.0, mean - margin), 6), round(min(1.0, mean + margin), 6)],
        "n_seeds": int(len(array)),
    }


def _load_optional_labels(path: pathlib.Path, expected_label: Optional[str] = None) -> Tuple[np.ndarray, np.ndarray]:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "URL" not in frame.columns:
        raise ValueError(f"{path} is missing URL")
    if "type" in frame.columns:
        labels = frame["type"].map(LABEL_MAP)
        if labels.isna().any():
            raise ValueError(f"{path} contains unknown labels")
        y = labels.to_numpy(dtype=int)
    elif expected_label is not None:
        y = np.full(len(frame), LABEL_MAP[expected_label], dtype=int)
    else:
        raise ValueError(f"{path} requires a type column")
    X = np.asarray([extract_vector(url) for url in frame["URL"]], dtype=float)
    return X, y


def _gate_status(name: str, result: str, rule: str, **details: object) -> dict:
    return {"gate": name, "result": result, "rule": rule, **details}


def run_evaluation(root: pathlib.Path) -> dict:
    """Run calibration and all gates that have the required evidence."""
    report_dir = root / "ml" / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    train_path = root / "data" / "splits" / "train.csv"
    test_path = root / "data" / "splits" / "test.csv"
    model_path = root / "ml" / "models" / "best_model.joblib"
    benchmark_path = report_dir / "benchmark_D1.json"
    if not all(path.exists() for path in (train_path, test_path, model_path, benchmark_path)):
        missing = [str(path) for path in (train_path, test_path, model_path, benchmark_path) if not path.exists()]
        raise FileNotFoundError("Required Chunk 5 artifacts are missing: " + ", ".join(missing))

    X_train, y_train, groups_train = load_split(train_path, cache_dir=root / "data" / "processed")
    X_test, y_test, _ = load_split(test_path, cache_dir=root / "data" / "processed")
    test_frame = pd.read_csv(test_path, dtype=str, keep_default_na=False)
    manifest = json.loads((root / "ml" / "models" / "model.manifest.json").read_text(encoding="utf-8"))

    selector = manifest["selector"]
    classifier = manifest["classifier"]
    k = int(manifest["k"])
    model = joblib.load(model_path)
    try:
        raw_test = _get_proba(model, X_test)
    except AttributeError as exc:
        if "monotonic_cst" not in str(exc):
            raise
        LOGGER.warning(
            "Persisted model was created with an older scikit-learn version; "
            "retraining the locked finalist for this evaluation environment."
        )
        model = build_pipeline(selector, classifier, k, int(manifest["seed"]))
        model.fit(X_train, y_train)
        raw_test = _get_proba(model, X_test)

    per_seed_oof = _oof_predictions_by_seed(
        X_train, y_train, groups_train, selector, classifier, k
    )
    oof_y = per_seed_oof[0][1]
    oof_raw = np.mean([item[2] for item in per_seed_oof], axis=0)
    calibration = fit_calibrator(oof_raw, oof_y)
    calibrated_test = apply_calibrator(calibration, raw_test)
    test_metrics = _metric_at_threshold(y_test, calibrated_test, DEFAULT_BLOCK_THRESHOLD)
    per_seed_results = []
    for seed, seed_y, seed_raw in per_seed_oof:
        seed_calibration = fit_calibrator(seed_raw, seed_y)
        seed_test_probabilities = apply_calibrator(seed_calibration, raw_test)
        seed_adversarial = evaluate_adversarial(
            model, seed_calibration, test_frame["URL"].tolist(), y_test, DEFAULT_BLOCK_THRESHOLD
        )
        per_seed_results.append({
            "seed": seed,
            "g2_recall": _metric_at_threshold(
                y_test, seed_test_probabilities, DEFAULT_BLOCK_THRESHOLD
            )["recall"],
            "g8_recall_drop": seed_adversarial.get("worst_recall_drop"),
        })
    adversarial = evaluate_adversarial(
        model, calibration, test_frame["URL"].tolist(), y_test, DEFAULT_BLOCK_THRESHOLD
    )

    warn_threshold = choose_warn_threshold(oof_y, apply_calibrator(calibration, oof_raw))
    calibrated_oof = apply_calibrator(calibration, oof_raw)

    # Choose T_block on E1 validation part (out-of-fold predictions on E1 rows in training)
    # Do not tune on hold-outs!
    e1_sources = {"homepage_link", "sitemap", "login_page", "one_level_link", "seed_list"}
    if "source" in train_frame.columns and train_frame["source"].isin(e1_sources).any():
        e1_mask = train_frame["source"].isin(e1_sources).to_numpy()
        block_threshold = choose_block_threshold(oof_y[e1_mask], calibrated_oof[e1_mask], maximum_fpr=0.005)
    else:
        benign_mask = (oof_y == 0)
        block_threshold = choose_block_threshold(oof_y[benign_mask], calibrated_oof[benign_mask], maximum_fpr=0.005)

    if block_threshold is None:
        block_threshold = DEFAULT_BLOCK_THRESHOLD
    if warn_threshold is None:
        warn_threshold = DEFAULT_WARN_THRESHOLD

    # Evaluate hold-outs ONCE (strictly locked)
    e1_path = root / "data" / "splits" / "e1_holdout.csv"
    e1_status = "NOT_MEASURABLE"
    e1_fpr = None
    e1_ci = None
    if e1_path.exists():
        e1_X, e1_y = _load_optional_labels(e1_path, expected_label="Benign")
        e1_raw = _get_proba(model, e1_X)
        e1_prob = apply_calibrator(calibration, e1_raw)
        e1_metrics = _metric_at_threshold(e1_y, e1_prob, block_threshold)
        e1_fpr = e1_metrics["fpr"]
        from ml.evaluate_e1 import wilson_interval
        n_e1 = len(e1_y)
        fp_e1 = int(np.sum((e1_prob >= block_threshold) & (e1_y == 0)))
        e1_ci = wilson_interval(fp_e1, n_e1)
        e1_status = "PASS" if e1_fpr <= 0.005 else "FAIL"

    e2_path = root / "data" / "splits" / "e2_holdout.csv"
    e2_status = "NOT_MEASURABLE (E2 missing)"
    e2_recall = None
    if e2_path.exists():
        e2_X, e2_y = _load_optional_labels(e2_path, expected_label="Malicious")
        e2_raw = _get_proba(model, e2_X)
        e2_prob = apply_calibrator(calibration, e2_raw)
        e2_metrics = _metric_at_threshold(e2_y, e2_prob, block_threshold)
        e2_recall = e2_metrics["recall"]
        e2_status = "PASS" if e2_recall >= 0.80 else "FAIL"

    # G-2 requires both D1 recall >= 90% and E2 recall >= 80%.
    # When E2 is missing, G-2 must be reported as not measurable (E2 missing), never pass or fail.
    if e2_path.exists():
        g2_overall_status = "PASS" if (test_metrics["recall"] >= 0.90 and e2_recall is not None and e2_recall >= 0.80) else "FAIL"
    else:
        g2_overall_status = "NOT_MEASURABLE (E2 missing)"

    # Default enforcement mode: keep warn_only unless G-3 passes
    default_enforcement = "block" if e1_status == "PASS" else "warn_only"

    thresholds = json.loads((root / "thresholds.json").read_text(encoding="utf-8"))
    threshold_source = "calibration" if block_threshold is not None and warn_threshold is not None else "default"
    if threshold_source == "calibration":
        thresholds.update({
            "T_block": round(block_threshold, 6),
            "T_warn": round(warn_threshold, 6),
            "T_suspicious_min": round(warn_threshold * 100),
            "T_safe_max": max(0, round(warn_threshold * 100) - 1),
            "T_high_risk_min": round(block_threshold * 100),
            "default_enforcement": default_enforcement,
            "set_by": "chunk-e-calibration",
            "set_at": datetime.now(timezone.utc).isoformat(),
        })
        (root / "thresholds.json").write_text(json.dumps(thresholds, indent=2) + "\n", encoding="utf-8")

    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    best = benchmark.get("best", {})
    gates = [
        _gate_status("G-1", "PASS" if best.get("holdout_balanced_acc", 0) - benchmark["shortcut_baseline_balanced_acc"] >= 0.05 else "FAIL",
                     "grouped-test balanced accuracy exceeds shortcut baseline by at least 5 pp",
                     margin=round(best.get("holdout_balanced_acc", 0) - benchmark["shortcut_baseline_balanced_acc"], 6)),
        _gate_status("G-2", g2_overall_status,
                     "recall >= 90% on D1 grouped hold-out and >= 80% on E2",
                     d1_recall=test_metrics["recall"],
                     d1_status="PASS" if test_metrics["recall"] >= 0.90 else "FAIL",
                     e2=e2_recall if e2_recall is not None else "NOT_MEASURABLE (E2 missing)",
                     e2_status=e2_status),
        _gate_status("G-3", e1_status,
                     "FPR <= 0.5% on E1 hold-out with 95% Wilson interval",
                     e1_available=e1_path.exists(), empirical_fpr=e1_fpr, wilson_95_ci=e1_ci),
        _gate_status("G-4", "PASS" if all(r.get("gates", {}).get("G4_pass", False) for r in benchmark["runs"] if r.get("status") == "ok") else "FAIL",
                     "random-split minus grouped-split balanced accuracy <= 5 pp"),
        _gate_status("G-5", "NOT_MEASURABLE", "Python/TypeScript risk differs by at most 1 point"),
        _gate_status("G-6", "NOT_MEASURABLE", "Inference p95 < 15 ms and end-to-end p95 < 30 ms"),
        _gate_status("G-7", "PASS" if calibration["selected_ece"] <= 0.05 else "FAIL",
                     "ECE <= 0.05 with Brier score reported",
                     method=calibration["method"], ece=round(calibration["selected_ece"], 6)),
        _gate_status("G-8", adversarial["status"], "Adversarial recall drop <= 10 pp",
                     worst_recall_drop=adversarial.get("worst_recall_drop")),
    ]
    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "schema": manifest["schema"],
        "model": {"selector": selector, "classifier": classifier, "k": k},
        "calibration": {
            key: value for key, value in calibration.items() if key != "calibrator"
        },
        "test_metrics_calibrated": test_metrics,
        "adversarial": adversarial,
        "multi_seed": {
            "seeds": per_seed_results,
            "G-2_recall": _summary([item["g2_recall"] for item in per_seed_results]),
            "G-8_recall_drop": _summary([item["g8_recall_drop"] for item in per_seed_results]),
        },
        "thresholds": thresholds,
        "threshold_source": threshold_source,
        "gates": gates,
        "evidence": {
            "e1_available": e1_path.exists(),
            "e2_available": e2_path.exists(),
            "e2_temporal_split": "NOT_MEASURABLE (E2 missing)" if not e2_path.exists() else "computed",
            "e2_holdout": "NOT_MEASURABLE (E2 missing)" if not e2_path.exists() else str(e2_path),
            "typescript_parity_available": False,
            "browser_performance_available": False,
        },
    }
    (report_dir / "calibration_D1.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    _write_markdown(result, report_dir / "calibration_D1.md")
    return result


def _write_markdown(result: dict, path: pathlib.Path) -> None:
    lines = [
        "# PhishGuard — Chunk 6 Calibration and Gates",
        "",
        f"Generated: {result['generated_at_utc']}",
        "",
        f"- Calibration method: **{result['calibration']['method']}**",
        f"- Calibrated ECE: **{result['calibration']['selected_ece']:.6f}**",
        f"- Threshold source: **{result['threshold_source']}**",
        "",
        "| Gate | Result |",
        "|------|--------|",
    ]
    lines.extend(f"| {gate['gate']} | {gate['result']} |" for gate in result["gates"])
    lines.extend([
        "",
        "Gates requiring E1/E2, TypeScript, or browser evidence remain explicitly "
        "not measurable until those artifacts are available.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Chunk 6 calibration and gate evaluation.")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args()
    result = run_evaluation(pathlib.Path(args.root))
    print(json.dumps({
        "calibration": result["calibration"]["method"],
        "threshold_source": result["threshold_source"],
        "gates": {gate["gate"]: gate["result"] for gate in result["gates"]},
    }, indent=2))


if __name__ == "__main__":
    main()
