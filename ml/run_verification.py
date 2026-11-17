"""Strategy-aware verification CLI for production and experimental pipelines."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import balanced_accuracy_score, recall_score

from ml.pipeline_adapter import HybridURLClassifier, T_BLOCK
from ml.normalize import normalize
from ml.threshold_analysis import optimize_threshold
from ml.tfidf_model import train_tfidf_model


def _metrics(frame: pd.DataFrame, probabilities: np.ndarray) -> dict[str, float]:
    labels = (frame["type"] == "Malicious").astype(int).to_numpy()
    predictions = (probabilities >= T_BLOCK).astype(int)
    benign = labels == 0
    return {
        "bacc_at_070": float(balanced_accuracy_score(labels, predictions)),
        "recall_at_070": float(recall_score(labels, predictions, zero_division=0)),
        "fpr_at_070": float(predictions[benign].mean()) if benign.any() else 0.0,
    }


def _valid_frame(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "URL" not in frame or "type" not in frame:
        raise ValueError(f"{path} must contain URL and type columns")
    return frame


def _scorecard(
    classifier: HybridURLClassifier,
    d1_test: pd.DataFrame,
    e1_holdout: pd.DataFrame,
) -> dict[str, Any]:
    d1_test = _scorable_frame(d1_test)
    e1_holdout = _scorable_frame(e1_holdout)
    d1_probability = classifier.predict_proba(d1_test["URL"].tolist())
    e1_probability = classifier.predict_proba(e1_holdout["URL"].tolist())
    return {
        "d1": _metrics(d1_test, d1_probability),
        "e1": _metrics(e1_holdout, e1_probability),
    }


def _scorable_frame(frame: pd.DataFrame) -> pd.DataFrame:
    valid = []
    for index, url in frame["URL"].items():
        if not normalize(url).error:
            valid.append(index)
    return frame.loc[valid].reset_index(drop=True)


def run_pipeline(args: argparse.Namespace) -> dict[str, Any]:
    d1_test = _valid_frame(args.d1_test)
    e1_holdout = _valid_frame(args.e1_holdout)
    try:
        production_model = joblib.load(args.production_model)
        baseline = HybridURLClassifier(mode="production", production_model=production_model)
        baseline_metrics = _scorecard(baseline, d1_test, e1_holdout)
    except (AttributeError, ValueError, OSError) as error:
        baseline_metrics = {
            "status": "UNAVAILABLE",
            "error": f"{type(error).__name__}: {error}",
            "model": str(args.production_model),
        }

    if args.strategy == "production":
        return {
            "strategy": "production",
            "thresholds": {"T_block": 0.70, "T_warn": 0.35},
            "enforcement": "warn_only",
            "baseline": baseline_metrics,
        }

    if args.strategy == "experimental-analysis":
        if args.probabilities is None or args.labels is None:
            raise ValueError("--probabilities and --labels are required for experimental-analysis")
        result = optimize_threshold(np.load(args.probabilities), np.load(args.labels))
        result["baseline"] = baseline_metrics
        return {"strategy": "experimental-analysis", "threshold_analysis": result}

    train_frame = _valid_frame(args.train)
    tfidf_model = train_tfidf_model(train_frame)
    allowlist = [value.strip() for value in args.allowlist.split(",") if value.strip()]
    brands = [value.strip() for value in args.brands.split(",") if value.strip()]
    experimental = HybridURLClassifier(
        mode="experimental",
        experimental_model=tfidf_model,
        allowlist_domains=allowlist,
        brand_keywords=brands,
    )
    experimental_metrics = _scorecard(experimental, d1_test, e1_holdout)
    return {
        "strategy": "experimental-hybrid",
        "thresholds": {"T_block": 0.70, "T_warn": 0.35},
        "enforcement": "warn_only",
        "baseline": baseline_metrics,
        "experimental_hybrid": experimental_metrics,
        "allowlist_domains": allowlist,
        "brand_keywords": brands,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strategy",
        choices=("production", "experimental-hybrid", "experimental-analysis"),
        default="production",
    )
    parser.add_argument("--production-model", type=Path, default=Path("ml/models/best_model.joblib"))
    parser.add_argument("--train", type=Path, default=Path("data/splits_v2/experimental/train.csv"))
    parser.add_argument("--d1-test", type=Path, default=Path("data/splits_v2/experimental/d1_test.csv"))
    parser.add_argument("--e1-holdout", type=Path, default=Path("data/splits_v2/experimental/e1_holdout.csv"))
    parser.add_argument("--probabilities", type=Path)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--allowlist", default="facebook.com,google.com,github.com")
    parser.add_argument("--brands", default="facebook,google,paypal")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or (
        Path("ml/report/experimental_scorecard.json")
        if args.strategy == "experimental-hybrid"
        else Path("ml/report/production_scorecard.json")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    result = run_pipeline(args)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
