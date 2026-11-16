
#!/usr/bin/env python3
"""Provisional E1 benign FPR evaluation for PhishGuard.

Threshold selection:
    E1_training.csv only.

Final evaluation:
    E1_holdout.csv only.

Model and calibration:
    D1 training data only.

E1 labels are provisionally assumed benign. This script does not independently
verify benign labels or source provenance.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import numpy as np
import pandas as pd

from sklearn.model_selection import StratifiedGroupKFold

ROOT = pathlib.Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.features import extract_many, derive_suspicious_tlds
from ml.train import (
    _fit_candidate,
    _pipeline,
    _PlattCalibrator,
    _IsotonicCalibrator,
    _expected_calibration_error,
    choose_block_threshold,
)


def wilson_interval(errors, total, z=1.959963984540054):
    """95% Wilson confidence interval for a binomial proportion."""
    if total <= 0:
        raise ValueError("Total observations must be positive")

    p = errors / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    centre = (p + z2 / (2.0 * total)) / denominator
    margin = (
        z
        * np.sqrt(
            p * (1.0 - p) / total
            + z2 / (4.0 * total * total)
        )
        / denominator
    )

    return max(0.0, centre - margin), min(1.0, centre + margin)


def make_oof_predictions(frame, selector, classifier, seed, k,
                         folds, tune, inner_folds):
    """Generate grouped out-of-fold probabilities using D1 training only."""
    y = (
        frame["type"].str.lower() == "malicious"
    ).astype(int).to_numpy()

    groups = frame["registrable_domain"].astype(str).to_numpy()
    urls = frame["URL"].astype(str).tolist()

    n_splits = min(folds, len(set(groups)))

    if n_splits < 2:
        raise ValueError("At least two distinct domains are required")

    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=seed,
    )

    raw_oof = np.zeros(len(frame), dtype=float)

    for fold, (tr, va) in enumerate(
        splitter.split(np.zeros(len(y)), y, groups), 1
    ):
        if set(groups[tr]).intersection(set(groups[va])):
            raise AssertionError("Domain leakage detected")

        suspicious = derive_suspicious_tlds(
            [urls[i] for i in tr],
            frame.iloc[tr]["type"].tolist(),
        )

        Xtr = extract_many(
            [urls[i] for i in tr], suspicious
        )
        Xva = extract_many(
            [urls[i] for i in va], suspicious
        )

        model, _ = _fit_candidate(
            selector,
            classifier,
            seed,
            k,
            Xtr,
            y[tr],
            groups[tr],
            tune=tune,
            inner_folds=inner_folds,
        )

        raw_oof[va] = model.predict_proba(Xva)[:, 1]

        print(
            "OOF fold {}/{} complete".format(fold, n_splits),
            flush=True,
        )

    return y, groups, urls, raw_oof


def fit_calibrator(y, raw_oof, groups, seed, folds):
    """Choose calibration using grouped cross-fitting, then fit on all OOF rows."""
    from ml.calibrate import _crossfit_calibration

    _, metadata = _crossfit_calibration(
        y,
        raw_oof,
        groups,
        seed=seed + 100,
        folds=folds,
    )

    if metadata["method"] == "isotonic":
        calibrator = _IsotonicCalibrator()
    else:
        calibrator = _PlattCalibrator()

    calibrator.fit(raw_oof, y)

    metadata["final_fit_rows"] = int(len(y))
    metadata["selection_basis"] = "grouped cross-fitted OOF ECE"

    return calibrator, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--selector", default="l1")
    parser.add_argument("--classifier", default="svm")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--k", type=int, default=20)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--inner-folds", type=int, default=3)
    parser.add_argument(
        "--no-tune",
        action="store_true",
        help="Disable grouped inner hyperparameter tuning",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    report_dir = root / "data" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    d1_path = root / "data" / "splits" / "train.csv"
    e1_train_path = root / "data" / "external" / "E1_training.csv"
    e1_holdout_path = root / "data" / "external" / "E1_holdout.csv"

    for path in (d1_path, e1_train_path, e1_holdout_path):
        if not path.exists():
            raise FileNotFoundError(str(path))

    d1 = pd.read_csv(d1_path)
    e1_train = pd.read_csv(e1_train_path)
    e1_holdout = pd.read_csv(e1_holdout_path)

    required_d1 = {"URL", "type", "registrable_domain"}
    required_e1 = {"URL", "registrable_domain"}

    if not required_d1.issubset(d1.columns):
        raise ValueError("D1 training schema is incomplete")

    if not required_e1.issubset(e1_train.columns):
        raise ValueError("E1 training schema is incomplete")

    if not required_e1.issubset(e1_holdout.columns):
        raise ValueError("E1 holdout schema is incomplete")

    d1 = d1.dropna(
        subset=["URL", "type", "registrable_domain"]
    ).reset_index(drop=True)

    if set(e1_train["registrable_domain"]) & set(
        e1_holdout["registrable_domain"]
    ):
        raise AssertionError("E1 train/holdout domain overlap")

    if set(d1["registrable_domain"]) & set(
        e1_train["registrable_domain"]
    ):
        raise AssertionError("D1/E1 training domain overlap")

    if set(d1["registrable_domain"]) & set(
        e1_holdout["registrable_domain"]
    ):
        raise AssertionError("D1/E1 holdout domain overlap")

    tune = not args.no_tune

    print("Generating D1 grouped OOF predictions...", flush=True)

    y, groups, d1_urls, raw_oof = make_oof_predictions(
        d1,
        args.selector,
        args.classifier,
        args.seed,
        args.k,
        args.folds,
        tune,
        args.inner_folds,
    )

    calibrator, calibration_meta = fit_calibrator(
        y,
        raw_oof,
        groups,
        args.seed,
        args.folds,
    )

    print("Fitting final model on D1 training data...", flush=True)

    suspicious = derive_suspicious_tlds(
        d1_urls,
        d1["type"].tolist(),
    )

    X_d1 = extract_many(d1_urls, suspicious)

    final_model, final_params = _fit_candidate(
        args.selector,
        args.classifier,
        args.seed,
        args.k,
        X_d1,
        y,
        groups,
        tune=tune,
        inner_folds=args.inner_folds,
    )

    print("Scoring E1 training data...", flush=True)

    X_e1_train = extract_many(
        e1_train["URL"].astype(str).tolist(),
        suspicious,
    )

    train_raw = final_model.predict_proba(X_e1_train)[:, 1]
    train_calibrated = calibrator.predict(train_raw)

    block = choose_block_threshold(
    train_calibrated,
    max_fpr=0.005,
)
    np.zeros(len(train_calibrated), dtype=float)
    + train_calibrated,
    max_fpr=0.005,


    threshold = block["threshold"]

    print("Scoring E1 holdout data...", flush=True)

    X_e1_holdout = extract_many(
        e1_holdout["URL"].astype(str).tolist(),
        suspicious,
    )

    holdout_raw = final_model.predict_proba(X_e1_holdout)[:, 1]
    holdout_calibrated = calibrator.predict(holdout_raw)

    false_positives = int(np.sum(holdout_calibrated >= threshold))
    total = int(len(holdout_calibrated))
    fpr = false_positives / total

    ci_low, ci_high = wilson_interval(
        false_positives,
        total,
    )

    report = {
        "dataset": "E1",
        "status": "PROVISIONAL",
        "label_assumption": "All E1 URLs treated as benign; independent verification pending",
        "model": {
            "selector": args.selector,
            "classifier": args.classifier,
            "seed": args.seed,
            "top_k": args.k,
            "tuning": tune,
            "best_parameters": final_params,
        },
        "calibration": calibration_meta,
        "threshold_selection": {
            "source": "E1_training.csv",
            "rows": int(len(e1_train)),
            "threshold": float(threshold),
            "training_fpr": float(
                np.mean(train_calibrated >= threshold)
            ),
            "maximum_allowed_fpr": 0.005,
        },
        "holdout_evaluation": {
            "source": "E1_holdout.csv",
            "rows": total,
            "false_positives": false_positives,
            "fpr": float(fpr),
            "fpr_percent": float(fpr * 100),
            "wilson_95_ci": [
                float(ci_low),
                float(ci_high),
            ],
            "wilson_95_ci_percent": [
                float(ci_low * 100),
                float(ci_high * 100),
            ],
        },
        "acceptance": {
            "target_fpr": 0.005,
            "empirical_fpr_pass": bool(fpr <= 0.005),
            "confidence_interval_upper_bound_pass": bool(
                ci_high <= 0.005
            ),
            "g3_verified": False,
            "reason": "E1 benign labels and provenance require independent verification",
        },
        "data_boundary": (
            "D1 train used for fitting; E1 training used for threshold selection; "
            "E1 holdout used only for final evaluation; D1 test and E2 not read"
        ),
    }

    output = report_dir / "E1_evaluation_l1_svm.json"

    output.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print("\nReport saved:", output)


if __name__ == "__main__":
    main()
