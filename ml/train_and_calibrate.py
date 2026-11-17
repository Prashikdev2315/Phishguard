"""Train a gated gradient-boosted URL classifier with grouped OOF calibration."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, brier_score_loss, confusion_matrix, recall_score
from sklearn.model_selection import StratifiedGroupKFold

from ml.feature_extraction import FEATURE_NAMES, extract_vector
from ml.gated_classifier import GatedURLClassifier, ROOT_RISK_CAP, TOP_DOMAIN_RANK

T_BLOCK = 0.70
T_WARN = 0.35
TOP_DOMAIN_RANK = 10_000
ROOT_RISK_CAP = 0.149


def _ece(y_true: np.ndarray, probability: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        mask = (probability >= low) & (probability < high)
        if mask.any():
            total += mask.sum() * abs(y_true[mask].mean() - probability[mask].mean())
    return float(total / max(len(y_true), 1))


def _rank(row: pd.Series) -> int | None:
    value = row.get("rank", "")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _feature_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray]:
    valid: list[int] = []
    vectors: list[list[float]] = []
    for index, row in frame.iterrows():
        try:
            vectors.append(extract_vector(row["URL"], tranco_rank=_rank(row)))
            valid.append(index)
        except ValueError:
            continue
    return frame.loc[valid].reset_index(drop=True), np.asarray(vectors, dtype=np.float64)


def _fit_calibrator(oof: np.ndarray, y: np.ndarray) -> tuple[Any, str, np.ndarray]:
    isotonic = IsotonicRegression(out_of_bounds="clip").fit(oof, y)
    platt = LogisticRegression(random_state=42).fit(oof.reshape(-1, 1), y)
    iso_probability = isotonic.predict(oof)
    platt_probability = platt.predict_proba(oof.reshape(-1, 1))[:, 1]
    if brier_score_loss(y, iso_probability) <= brier_score_loss(y, platt_probability):
        return isotonic, "isotonic", iso_probability
    return platt, "platt", platt_probability


def _calibrated_probability(calibrator: Any, model: GatedURLClassifier, x: np.ndarray) -> np.ndarray:
    probability = calibrator.predict(model.predict_proba(x)[:, 1])
    trusted_root = (
        (x[:, FEATURE_NAMES.index("is_root_domain")] == 1)
        & (x[:, FEATURE_NAMES.index("log_tranco_rank")] <= np.log10(TOP_DOMAIN_RANK))
    )
    return np.where(trusted_root, np.minimum(probability, ROOT_RISK_CAP), probability)


def train(args: argparse.Namespace) -> dict[str, Any]:
    train_df = pd.read_csv(args.train, dtype=str, keep_default_na=False)
    d1_test = pd.read_csv(args.d1_test, dtype=str, keep_default_na=False)
    e1_holdout = pd.read_csv(args.e1_holdout, dtype=str, keep_default_na=False)
    original_rows = {"train": len(train_df), "d1_test": len(d1_test), "e1_holdout": len(e1_holdout)}
    train_df, x = _feature_frame(train_df)
    d1_test, x_test = _feature_frame(d1_test)
    e1_holdout, x_e1 = _feature_frame(e1_holdout)
    dropped = {key: original_rows[key] - len(value) for key, value in {
        "train": train_df, "d1_test": d1_test, "e1_holdout": e1_holdout
    }.items()}
    y = (train_df["type"] == "Malicious").astype(int).to_numpy()
    groups = train_df["registrable_domain"].to_numpy()
    y_test = (d1_test["type"] == "Malicious").astype(int).to_numpy()

    oof = np.full(len(y), np.nan)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
    for fit_idx, validation_idx in splitter.split(x, y, groups):
        fold_model = GatedURLClassifier(random_state=args.seed)
        fold_model.fit(x[fit_idx], y[fit_idx])
        oof[validation_idx] = fold_model.predict_proba(x[validation_idx])[:, 1]

    calibrator, calibration_method, calibrated_oof = _fit_calibrator(oof, y)
    model = GatedURLClassifier(random_state=args.seed)
    model.fit(x, y)
    test_probability = _calibrated_probability(calibrator, model, x_test)
    e1_probability = _calibrated_probability(calibrator, model, x_e1)
    test_prediction = (test_probability >= T_BLOCK).astype(int)
    e1_prediction = (e1_probability >= T_BLOCK).astype(int)
    tn, fp, _, _ = confusion_matrix(
        np.zeros(len(e1_prediction), dtype=int), e1_prediction, labels=[0, 1]
    ).ravel()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "best_model_v2.joblib"
    calibrator_path = args.output_dir / "calibrator_v2.joblib"
    joblib.dump(model, model_path)
    joblib.dump(calibrator, calibrator_path)
    metadata = {
        "schema": "url-experimental-v2",
        "model_version": args.version,
        "status": "experimental-not-release-ready",
        "classifier": "HistGradientBoostingClassifier",
        "architecture": "GatedURLClassifier",
        "calibration_method": calibration_method,
        "calibration_protocol": "5-fold StratifiedGroupKFold OOF probabilities",
        "risk_mapping": "probability * 100",
        "thresholds": {"T_block": T_BLOCK, "T_warn": T_WARN},
        "root_risk_cap": ROOT_RISK_CAP,
        "top_domain_rank": TOP_DOMAIN_RANK,
        "train_rows": len(train_df),
        "dropped_invalid_urls": dropped,
        "class_counts": train_df["type"].value_counts().to_dict(),
        "oof_brier": brier_score_loss(y, calibrated_oof),
        "oof_ece": _ece(y, calibrated_oof),
        "d1_test_bacc_at_070": balanced_accuracy_score(y_test, test_prediction),
        "d1_test_recall_at_070": recall_score(y_test, test_prediction, zero_division=0),
        "e1_holdout_fpr_at_070": float(fp / max(tn + fp, 1)),
        "test_probability_sha256": hashlib.sha256(test_probability.tobytes()).hexdigest(),
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "calibrator_sha256": hashlib.sha256(calibrator_path.read_bytes()).hexdigest(),
    }
    (args.output_dir / "model_v2.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=Path, default=Path("data/splits_v2/train.csv"))
    parser.add_argument("--d1-test", type=Path, default=Path("data/splits_v2/d1_test.csv"))
    parser.add_argument("--e1-holdout", type=Path, default=Path("data/splits_v2/e1_holdout.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("ml/models"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--version", default="url-experimental-v2")
    print(json.dumps(train(parser.parse_args()), indent=2))


if __name__ == "__main__":
    main()
