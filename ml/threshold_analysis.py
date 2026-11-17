"""Experimental threshold search; never changes the frozen default threshold."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import balanced_accuracy_score


def optimize_threshold(
    probabilities: np.ndarray,
    labels: np.ndarray,
    start: float = 0.05,
    stop: float = 0.95,
    steps: int = 191,
) -> dict[str, float]:
    if probabilities.shape != labels.shape:
        raise ValueError("probabilities and labels must have the same shape")
    best_threshold = start
    best_bacc = -1.0
    for threshold in np.linspace(start, stop, steps):
        score = balanced_accuracy_score(labels, probabilities >= threshold)
        if score > best_bacc:
            best_bacc = float(score)
            best_threshold = float(threshold)
    return {
        "recommended_threshold": best_threshold,
        "validation_bacc": best_bacc,
        "frozen_default_threshold": 0.70,
        "status": "experimental-recommendation-only",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probabilities", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("ml/report/threshold_analysis.json"))
    args = parser.parse_args()
    result = optimize_threshold(
        np.load(args.probabilities),
        np.load(args.labels),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
