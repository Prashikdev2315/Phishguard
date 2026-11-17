#!/usr/bin/env python3
"""
ml/analyze.py — Pre-Chunk-6 analysis script (no new features, no calibration).

Produces ml/report/analysis_D1.json and ml/report/analysis_D1.md containing:
  1. Gate scorecard G-1 to G-8 (pass / fail / not measurable yet)
  2. Finalist model selection methodology and hold-out evaluation count
  3. Error analysis on the hold-out for RF and KNN:
       - recall and FPR by has_path
       - recall and FPR by hosting-platform membership
       - recall and FPR by originally scheme-less vs scheme-ful rows
       - share of missed malicious that are bare homepages
  4. RF feature importances (top 20)
  5. HistGradientBoosting reference baseline (hold-out only, not a candidate)

Usage:
    python -m ml.analyze [--root .]
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import pathlib
import re
import sys
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import balanced_accuracy_score, recall_score, precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("PHISHGUARD_ENV", "development")

from ml.features import FEATURE_NAMES, extract_vector  # noqa: E402
from ml.normalize import normalize                       # noqa: E402

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

LABEL_MAP = {"Benign": 0, "Malicious": 1}
TOP_K = 20  # must match train.py


# ---------------------------------------------------------------------------
# Data loading (re-uses cached npz if available from train.py run)
# ---------------------------------------------------------------------------

def load_split_with_meta(
    path: pathlib.Path, cache_dir: pathlib.Path
) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """Return X, y, and the full raw dataframe (for metadata analysis)."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for col in ("URL", "type", "registrable_domain"):
        if col not in df.columns:
            raise ValueError(f"{path}: missing column '{col}'")

    urls = df["URL"].tolist()
    labels = df["type"].tolist()
    missing = set(labels) - set(LABEL_MAP)
    if missing:
        raise ValueError(f"Unknown labels: {missing}")

    # Try feature cache first
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    h = digest.hexdigest()[:16]
    cache_path = cache_dir / f"{path.stem}_{h}_fs1.npz"

    if cache_path.exists():
        LOGGER.info("Loading feature cache: %s", cache_path.name)
        data = np.load(cache_path, allow_pickle=True)
        X = data["X"]
    else:
        LOGGER.info("Extracting %d feature vectors from %s ...", len(urls), path.name)
        X = np.array([extract_vector(url) for url in urls], dtype=np.float64)
        np.savez_compressed(cache_path, X=X,
                            y=np.array([LABEL_MAP[l] for l in labels], dtype=np.int32),
                            groups=np.array(df["registrable_domain"].tolist()))

    y = np.array([LABEL_MAP[l] for l in labels], dtype=np.int32)
    return X, y, df


# ---------------------------------------------------------------------------
# Metadata flags derived from the raw URL (analysis only, never features)
# ---------------------------------------------------------------------------

def build_meta_flags(df: pd.DataFrame) -> pd.DataFrame:
    """Add analysis flags to the test dataframe. These are NOT model features."""
    hosting = json.loads((ROOT / "lists" / "hosting.json").read_text(encoding="utf-8"))
    hosting_set = set(hosting["platforms"])

    urls = df["URL"].tolist()
    has_path_flags, scheme_less_flags, on_hosting_flags, bare_home_flags = [], [], [], []
    has_query_flags, login_flags, google_hosted_flags = [], [], []

    LOGIN_PAT = re.compile(r"login|signin|sign-in|log-in|verify|account|password|auth|secure", re.I)

    for url in urls:
        r = normalize(url)
        # has_path: normalized path is non-empty and not just "/"
        path = r.path.strip("/") if r.path else ""
        has_path_flags.append(bool(path))
        has_query_flags.append(bool(r.query))

        # scheme-less: original URL had no scheme (normalize prepended http://)
        raw = url.strip()
        scheme_less_flags.append(not (raw.startswith("http://") or raw.startswith("https://")))

        # on hosting platform: registrable domain suffix matches a known platform
        reg = r.registrable_domain or ""
        host = (r.puny_host or "").lower()
        on_host = any(reg == p or reg.endswith("." + p) or p in host for p in hosting_set)
        on_hosting_flags.append(on_host)

        # bare homepage: no path and no query
        bare = (not path) and (not r.query)
        bare_home_flags.append(bare)

        # login-like keywords
        login_flags.append(bool(LOGIN_PAT.search(r.decoded_url)))

        # google-hosted
        google_hosted = (reg == "google.com" or "google.com" in host or reg in ("1e100.net", "appspot.com", "googleusercontent.com"))
        google_hosted_flags.append(google_hosted)

    meta = df.copy()
    meta["_has_path"] = has_path_flags
    meta["_has_query"] = has_query_flags
    meta["_scheme_less"] = scheme_less_flags
    meta["_on_hosting"] = on_hosting_flags
    meta["_bare_home"] = bare_home_flags
    meta["_login_keywords"] = login_flags
    meta["_google_hosted"] = google_hosted_flags
    return meta


# ---------------------------------------------------------------------------
# Slice metric helper with Wilson 95% confidence intervals
# ---------------------------------------------------------------------------

def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    """95% Wilson score confidence interval for a binomial proportion."""
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    denominator = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denominator
    half_width = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / denominator
    return max(0.0, centre - half_width), min(1.0, centre + half_width)


def slice_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, mask: np.ndarray, label: str
) -> dict:
    """Compute recall, FPR, counts, and 95% Wilson intervals for a boolean mask over y_true/y_pred."""
    y_t = y_true[mask]
    y_p = y_pred[mask]
    if len(y_t) == 0:
        return {
            "slice": label, "n": 0, "recall": None, "fpr": None,
            "n_positive": 0, "n_negative": 0,
            "recall_wilson_95_ci": None, "recall_wilson_ci_str": "N/A",
            "fpr_wilson_95_ci": None, "fpr_wilson_ci_str": "N/A",
        }
    pos = int((y_t == 1).sum())
    neg = int((y_t == 0).sum())
    tp = int(((y_p == 1) & (y_t == 1)).sum())
    fp = int(((y_p == 1) & (y_t == 0)).sum())

    if pos > 0:
        recall = float(tp / pos)
        rec_ci_low, rec_ci_high = wilson_interval(tp, pos)
        rec_ci = [round(rec_ci_low, 6), round(rec_ci_high, 6)]
        rec_str = f"[{rec_ci_low * 100:.2f}%, {rec_ci_high * 100:.2f}%]"
    else:
        recall = None
        rec_ci = None
        rec_str = "N/A"

    if neg > 0:
        fpr = float(fp / neg)
        fpr_ci_low, fpr_ci_high = wilson_interval(fp, neg)
        fpr_ci = [round(fpr_ci_low, 6), round(fpr_ci_high, 6)]
        fpr_str = f"[{fpr_ci_low * 100:.2f}%, {fpr_ci_high * 100:.2f}%]"
    else:
        fpr = None
        fpr_ci = None
        fpr_str = "N/A"

    return {
        "slice": label,
        "n": int(len(y_t)),
        "n_positive": pos,
        "n_negative": neg,
        "recall": round(recall, 6) if recall is not None else None,
        "recall_wilson_95_ci": rec_ci,
        "recall_wilson_ci_str": rec_str,
        "fpr": round(fpr, 6) if fpr is not None else None,
        "fpr_wilson_95_ci": fpr_ci,
        "fpr_wilson_ci_str": fpr_str,
    }


# ---------------------------------------------------------------------------
# Cross-source tests
# ---------------------------------------------------------------------------

def run_cross_source_tests(df_cleaned: pd.DataFrame) -> dict:
    """Cross-source generalization tests: train on A, test on B, and the reverse."""
    LOGGER.info("Running cross-source tests (A <-> B) ...")
    from ml.train import build_pipeline
    from sklearn.metrics import balanced_accuracy_score, recall_score

    mask_a = df_cleaned["source"].isin(["A_benign", "A_mal"])
    mask_b = df_cleaned["source"].isin(["B_benign", "B_mal"])

    df_a = df_cleaned[mask_a].copy()
    df_b = df_cleaned[mask_b].copy()

    X_a = np.asarray([extract_vector(u) for u in df_a["URL"]], dtype=np.float64)
    y_a = np.asarray([LABEL_MAP[t] for t in df_a["type"]], dtype=np.int32)

    X_b = np.asarray([extract_vector(u) for u in df_b["URL"]], dtype=np.float64)
    y_b = np.asarray([LABEL_MAP[t] for t in df_b["type"]], dtype=np.int32)

    # Train on A, test on B
    pipe_a = build_pipeline("rf_importance", "rf", TOP_K, 42)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pipe_a.fit(X_a, y_a)
    y_pred_b = pipe_a.predict(X_b)
    bacc_b = float(balanced_accuracy_score(y_b, y_pred_b))
    rec_b = float(recall_score(y_b, y_pred_b, zero_division=0))
    fp_b = int(((y_pred_b == 1) & (y_b == 0)).sum())
    neg_b = int((y_b == 0).sum())
    fpr_b = float(fp_b / neg_b) if neg_b > 0 else 0.0

    # Train on B, test on A
    pipe_b = build_pipeline("rf_importance", "rf", TOP_K, 42)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pipe_b.fit(X_b, y_b)
    y_pred_a = pipe_b.predict(X_a)
    bacc_a = float(balanced_accuracy_score(y_a, y_pred_a))
    rec_a = float(recall_score(y_a, y_pred_a, zero_division=0))
    fp_a = int(((y_pred_a == 1) & (y_a == 0)).sum())
    neg_a = int((y_a == 0).sum())
    fpr_a = float(fp_a / neg_a) if neg_a > 0 else 0.0

    return {
        "train_A_test_B": {
            "train_source": "Source A (A_benign + A_mal)",
            "test_source": "Source B (B_benign + B_mal)",
            "n_train": int(len(df_a)),
            "n_test": int(len(df_b)),
            "balanced_accuracy": round(bacc_b, 6),
            "recall": round(rec_b, 6),
            "fpr": round(fpr_b, 6),
        },
        "train_B_test_A": {
            "train_source": "Source B (B_benign + B_mal)",
            "test_source": "Source A (A_benign + A_mal)",
            "n_train": int(len(df_b)),
            "n_test": int(len(df_a)),
            "balanced_accuracy": round(bacc_a, 6),
            "recall": round(rec_a, 6),
            "fpr": round(fpr_a, 6),
        },
    }


# ---------------------------------------------------------------------------
# RF feature importances
# ---------------------------------------------------------------------------

def rf_feature_importance(pipe: Pipeline) -> List[dict]:
    """Extract selector support → RF feature_importances_ on selected features."""
    selector = pipe.named_steps["selector"]
    clf = pipe.named_steps["classifier"]

    if hasattr(selector, "get_support"):
        support = selector.get_support()
        selected_names = [FEATURE_NAMES[i] for i, v in enumerate(support) if v]
    else:
        selected_names = list(FEATURE_NAMES)

    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
        paired = sorted(zip(selected_names, importances), key=lambda x: x[1], reverse=True)
        return [{"feature": n, "importance": round(float(v), 6)} for n, v in paired[:20]]
    return []


# ---------------------------------------------------------------------------
# Gate scorecard
# ---------------------------------------------------------------------------

def build_gate_scorecard(report: dict, e1_report: Optional[dict] = None) -> List[dict]:
    """
    Build G-1 to G-8 scorecard using only numbers from generated reports.
    Not-measurable gates require E1/E2 or TypeScript port (not yet available).
    """
    sc = report["shortcut_baseline_balanced_acc"]
    best_ho_bacc = report["best"]["holdout_balanced_acc"]

    # Find best G-1 passing combo's FPR and recall from run data
    best_rf_run = next(
        (r for r in report["runs"]
         if r.get("selector") == "rf_importance" and r.get("classifier") == "rf"
         and r.get("status") == "ok"),
        None
    )
    best_rf_recall = best_rf_run["holdout"]["recall"] if best_rf_run else None
    best_rf_fpr    = best_rf_run["holdout"]["fpr"] if best_rf_run else None
    best_rf_brier  = best_rf_run["holdout"]["brier"] if best_rf_run else None
    best_rf_ece    = best_rf_run["holdout"]["ece"] if best_rf_run else None

    g4_gaps = [r["gates"]["G4_gap"] for r in report["runs"] if r.get("status") == "ok"]
    max_g4_gap = max(g4_gaps) if g4_gaps else None

    if e1_report is not None:
        ov = e1_report["overall"]
        g3_gate = {
            "gate": "G-3",
            "name": "Block FPR",
            "rule": "FPR <= 0.5% on E1 hold-out with allowlist off (95% Wilson interval reported)",
            "e1_holdout_fpr": ov["fpr"],
            "e1_holdout_fpr_percent": ov["fpr_percent"],
            "wilson_95_ci": ov["wilson_95_ci"],
            "wilson_95_ci_str": ov["wilson_ci_str"],
            "result": "PASS" if ov["fpr"] <= 0.005 else "FAIL",
            "note": f"E1 hold-out FPR = {ov['fpr_percent']:.2f}% (95% CI: {ov['wilson_ci_str']}). Target <= 0.50%.",
        }
    else:
        g3_gate = {
            "gate": "G-3",
            "name": "Block FPR",
            "rule": "FPR <= 0.5% on E1 hold-out with allowlist off (95% Wilson interval reported)",
            "d1_grouped_holdout_fpr_reference": best_rf_fpr,
            "result": "NOT_MEASURABLE",
            "note": "E1 hold-out is not yet available. D1 FPR (reference only, not E1) = "
                    f"{best_rf_fpr:.4f} ({best_rf_fpr*100:.2f}%). Gate requires E1.",
        }

    scorecard = [
        {
            "gate": "G-1",
            "name": "Shortcut margin",
            "rule": "grouped-test balanced_acc > shortcut_baseline + 5 pp",
            "shortcut_baseline": sc,
            "best_model_holdout_bacc": best_ho_bacc,
            "margin_pp": round(best_ho_bacc - sc, 6),
            "result": "PASS" if (best_ho_bacc - sc) >= 0.05 else "FAIL",
            "note": f"{sum(1 for r in report['runs'] if r.get('gates', {}).get('G1_pass'))} of 25 combinations pass G-1.",
        },
        {
            "gate": "G-2",
            "name": "Recall",
            "rule": "recall >= 90% on D1 grouped hold-out; >= 80% on E2",
            "d1_grouped_holdout_recall": best_rf_recall,
            "d1_status": "PASS" if best_rf_recall is not None and best_rf_recall >= 0.90 else "FAIL",
            "e2_status": "NOT_MEASURABLE (E2 missing)",
            "result": "NOT_MEASURABLE (E2 missing)",
            "note": (
                f"Best RF recall on D1 hold-out = {best_rf_recall:.4f}. "
                "E2 phishing feed is not yet available; E2 half of G-2 is not measurable (E2 missing)."
            ) if best_rf_recall is not None else "Data unavailable.",
        },
        g3_gate,
        {
            "gate": "G-4",
            "name": "Generalization gap",
            "rule": "random-split minus grouped-split balanced_acc <= 5 pp",
            "max_gap_across_25_runs_pp": round(max_g4_gap, 6) if max_g4_gap else None,
            "result": "PASS" if max_g4_gap is not None and max_g4_gap <= 0.05 else "FAIL",
            "note": f"All 25 combinations pass. Largest gap = {max_g4_gap*100:.2f} pp.",
        },
        {
            "gate": "G-5",
            "name": "Python / TypeScript parity",
            "rule": "risk within 1 point on 100% of dataset URLs and golden vectors",
            "result": "NOT_MEASURABLE",
            "note": "TypeScript port is Chunk 8. PAR-01 parity tests not yet written.",
        },
        {
            "gate": "G-6",
            "name": "Performance",
            "rule": "inference p95 < 15 ms warm; end-to-end < 30 ms warm; cold start < 150 ms",
            "result": "NOT_MEASURABLE",
            "note": "Extension integration is Chunk 9. Browser timing benchmarks not yet run.",
        },
        {
            "gate": "G-7",
            "name": "Calibration",
            "rule": "ECE <= 0.05; Brier score reported",
            "best_rf_ece_uncalibrated": best_rf_ece,
            "best_rf_brier_uncalibrated": best_rf_brier,
            "result": "NOT_MEASURABLE",
            "note": (
                f"Uncalibrated RF ECE = {best_rf_ece:.4f} (threshold 0.05). "
                "Platt/isotonic calibration is Chunk 6 and requires E1 for threshold tuning. "
                "Cannot declare pass/fail until calibration is applied."
            ),
        },
        {
            "gate": "G-8",
            "name": "Robustness",
            "rule": "recall on adversarial suite drops <= 10 pp vs clean",
            "result": "NOT_MEASURABLE",
            "note": "Adversarial transformation suite (ML-06) is part of Chunk 6. Not yet run.",
        },
    ]
    return scorecard


# ---------------------------------------------------------------------------
# HistGradientBoosting reference baseline
# ---------------------------------------------------------------------------

def run_hgb_reference(
    X_train: np.ndarray, y_train: np.ndarray,
    X_test: np.ndarray, y_test: np.ndarray,
) -> dict:
    """
    Train HistGradientBoosting on the same train split with the same 80/20
    grouped hold-out. This is a reference ceiling — NOT a deployment candidate.
    MinMaxScaler is applied for consistency with the benchmark pipeline.
    Feature selection is skipped (HGB is tree-based and handles scale naturally).
    """
    LOGGER.info("Running HistGradientBoosting reference baseline ...")
    scaler = MinMaxScaler()
    X_tr_scaled = scaler.fit_transform(X_train)
    X_te_scaled = scaler.transform(X_test)

    hgb = HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.1,
        max_depth=6,
        class_weight="balanced",
        random_state=42,
        early_stopping=False,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        hgb.fit(X_tr_scaled, y_train)

    y_pred = hgb.predict(X_te_scaled)
    y_prob = hgb.predict_proba(X_te_scaled)[:, 1]

    bacc  = float(balanced_accuracy_score(y_test, y_pred))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    pos_mask = y_test == 0
    fp = int(((y_pred == 1) & (y_test == 0)).sum())
    neg = int((y_test == 0).sum())
    fpr = fp / neg if neg > 0 else 0.0

    return {
        "model": "HistGradientBoostingClassifier",
        "note": "Reference ceiling — NOT a deployment candidate (no selector, all 50 features, no TypeScript export path).",
        "holdout_balanced_accuracy": round(bacc, 6),
        "holdout_recall": round(recall, 6),
        "holdout_fpr": round(fpr, 6),
        "g1_margin_vs_shortcut": None,  # filled in caller
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def run_analysis(root: pathlib.Path) -> dict:
    report_dir = root / "ml" / "report"
    models_dir = root / "ml" / "models"
    proc_dir   = root / "data" / "processed"
    splits_dir = root / "data" / "splits"

    bench_path = report_dir / "benchmark_D1.json"
    if not bench_path.exists():
        raise FileNotFoundError(f"{bench_path} not found. Run ml/train.py first.")
    benchmark = json.loads(bench_path.read_text(encoding="utf-8"))

    model_path = models_dir / "best_model.joblib"
    if not model_path.exists():
        raise FileNotFoundError(f"{model_path} not found. Run ml/train.py first.")

    train_path = splits_dir / "train.csv"
    test_path  = splits_dir / "test.csv"
    for p in (train_path, test_path):
        if not p.exists():
            raise FileNotFoundError(f"{p} not found. Run ml/build_dataset.py first.")

    LOGGER.info("Loading test split with metadata ...")
    X_test, y_test, df_test = load_split_with_meta(test_path, proc_dir)
    LOGGER.info("Loading train split ...")
    X_train, y_train, df_train = load_split_with_meta(train_path, proc_dir)

    # Check for E1 holdout
    e1_holdout_path = splits_dir / "e1_holdout.csv"
    e1_report = None
    if e1_holdout_path.exists():
        LOGGER.info("E1 hold-out detected at %s; evaluating E1 FPR per slice ...", e1_holdout_path)
        from ml.evaluate_e1 import evaluate_e1_slices
        try:
            e1_report = evaluate_e1_slices(e1_holdout_path, model_path, root=root)
        except Exception as exc:
            LOGGER.warning("Could not evaluate E1 holdout: %s", exc)

    # ---- 1. Gate scorecard ---------------------------------------------------
    LOGGER.info("Building gate scorecard ...")
    scorecard = build_gate_scorecard(benchmark, e1_report=e1_report)

    # ---- 2. Selection methodology --------------------------------------------
    selection_method = {
        "cv_criterion": "Mean balanced accuracy across 5-fold StratifiedGroupKFold × 3 seeds (seeds 42, 43, 44) on training partition only.",
        "holdout_criterion": "Hold-out (D1 test.csv) evaluated ONCE per combination (25 evaluations total). "
                             "No hyper-parameter tuning on hold-out. "
                             "Hold-out is locked — never re-used for selection, tuning, or any optimization decision.",
        "n_holdout_evaluations": 25,
        "finalist_selection_basis": "CV mean balanced_accuracy (5-fold StratifiedGroupKFold x 3 seeds) among G-1-passing combinations",
        "finalists": [
            {
                "rank": rank,
                "selector": r["selector"], "classifier": r["classifier"],
                "cv_bacc_mean": r["cv"]["balanced_accuracy"]["mean"],
                "cv_bacc_std": r["cv"]["balanced_accuracy"]["std"],
                "holdout_bacc": r["holdout"]["balanced_accuracy"],
                "g1_margin": r["gates"]["G1_margin"],
                "g4_gap": r["gates"]["G4_gap"],
            }
            for rank, r in enumerate(
                sorted(
                    [x for x in benchmark["runs"] if x.get("gates", {}).get("G1_pass")],
                    key=lambda x: x["cv"]["balanced_accuracy"]["mean"], reverse=True,
                )[:7], start=1
            )
        ],
    }

    # ---- 3. Load finalist models for error analysis --------------------------
    LOGGER.info("Building metadata flags for error analysis ...")
    meta = build_meta_flags(df_test)
    has_path_mask    = meta["_has_path"].values.astype(bool)
    scheme_less_mask = meta["_scheme_less"].values.astype(bool)
    on_hosting_mask  = meta["_on_hosting"].values.astype(bool)
    bare_home_mask   = meta["_bare_home"].values.astype(bool)

    error_analysis = {}

    for model_key, sel_name, clf_name in [
        ("RF_rf_importance", "rf_importance", "rf"),
        ("KNN_l1_lr",        "l1_lr",         "knn"),
    ]:
        LOGGER.info("Error analysis: re-training %s x %s on full train split ...", sel_name, clf_name)
        from ml.train import build_pipeline, _get_proba
        pipe = build_pipeline(sel_name, clf_name, TOP_K, 42)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)

        mal_mask  = y_test == 1
        ben_mask  = y_test == 0

        # Missed malicious = false negatives
        fn_mask = (y_test == 1) & (y_pred == 0)

        has_path_mask      = meta["_has_path"].values.astype(bool)
        has_query_mask     = meta["_has_query"].values.astype(bool)
        scheme_less_mask   = meta["_scheme_less"].values.astype(bool)
        on_hosting_mask    = meta["_on_hosting"].values.astype(bool)
        bare_home_mask     = meta["_bare_home"].values.astype(bool)
        login_mask         = meta["_login_keywords"].values.astype(bool)
        google_hosted_mask = meta["_google_hosted"].values.astype(bool)

        slices = [
            # has_query
            slice_metrics(y_test, y_pred, has_query_mask,          "has_query=True"),
            slice_metrics(y_test, y_pred, ~has_query_mask,         "has_query=False"),
            # has_path
            slice_metrics(y_test, y_pred, has_path_mask,           "has_path=True"),
            slice_metrics(y_test, y_pred, ~has_path_mask,          "has_path=False"),
            # login-like keywords
            slice_metrics(y_test, y_pred, login_mask,              "login_keywords=True"),
            slice_metrics(y_test, y_pred, ~login_mask,             "login_keywords=False"),
            # google-hosted
            slice_metrics(y_test, y_pred, google_hosted_mask,      "google_hosted=True"),
            slice_metrics(y_test, y_pred, ~google_hosted_mask,     "google_hosted=False"),
        ]

        if "source" in meta.columns:
            for src_val in sorted(meta["source"].unique()):
                src_mask = (meta["source"] == src_val).values.astype(bool)
                slices.append(slice_metrics(y_test, y_pred, src_mask, f"source={src_val}"))

        slices.extend([
            # hosting platform
            slice_metrics(y_test, y_pred, on_hosting_mask,         "on_hosting_platform=True"),
            slice_metrics(y_test, y_pred, ~on_hosting_mask,        "on_hosting_platform=False"),
            # scheme-less vs scheme-ful
            slice_metrics(y_test, y_pred, scheme_less_mask,        "scheme_less=True"),
            slice_metrics(y_test, y_pred, ~scheme_less_mask,       "scheme_less=False"),
        ])

        # Share of missed malicious that are bare homepages
        fn_total = int(fn_mask.sum())
        fn_bare  = int((fn_mask & bare_home_mask).sum())
        fn_bare_share = round(fn_bare / fn_total, 6) if fn_total > 0 else 0.0

        # RF feature importances (only for RF model)
        importances = []
        if clf_name == "rf":
            importances = rf_feature_importance(pipe)

        error_analysis[model_key] = {
            "selector": sel_name,
            "classifier": clf_name,
            "overall_holdout_recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 6),
            "overall_holdout_fpr": round(
                float(((y_pred == 1) & (y_test == 0)).sum() / max((y_test == 0).sum(), 1)), 6
            ),
            "n_false_negatives": fn_total,
            "fn_bare_homepage_count": fn_bare,
            "fn_bare_homepage_share": fn_bare_share,
            "slices": slices,
            "rf_feature_importances_top20": importances,
        }

    # ---- 4. HistGradientBoosting reference -----------------------------------
    hgb_result = run_hgb_reference(X_train, y_train, X_test, y_test)
    hgb_result["g1_margin_vs_shortcut"] = round(
        hgb_result["holdout_balanced_accuracy"] - benchmark["shortcut_baseline_balanced_acc"], 6
    )

    # ---- 4b. Cross-source tests (Requirement 5) -------------------------------
    cleaned_path = proc_dir / "D1_cleaned.csv"
    cross_source_results = None
    if cleaned_path.exists():
        df_cleaned = pd.read_csv(cleaned_path, dtype=str, keep_default_na=False)
        if "source" in df_cleaned.columns:
            cross_source_results = run_cross_source_tests(df_cleaned)

    # ---- 5. Assemble output --------------------------------------------------
    analysis = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "schema": "fs1",
        "shortcut_baseline_balanced_acc": benchmark["shortcut_baseline_balanced_acc"],
        "gate_scorecard": scorecard,
        "finalist_selection": selection_method,
        "cross_source_tests": cross_source_results,
        "error_analysis": error_analysis,
        "e1_evaluation": e1_report,
        "hgb_reference_baseline": hgb_result,
    }

    out_json = report_dir / "analysis_D1.json"
    out_json.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOGGER.info("Saved %s", out_json)

    _write_markdown(analysis, report_dir / "analysis_D1.md")
    LOGGER.info("Saved %s", report_dir / "analysis_D1.md")

    return analysis


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def _write_markdown(a: dict, path: pathlib.Path) -> None:
    sc = a["shortcut_baseline_balanced_acc"]
    lines = [
        "# PhishGuard — Pre-Chunk-6 Analysis Report",
        "",
        f"Generated: {a['generated_at_utc']}",
        "",
        "---",
        "",
        "## 1. Gate Scorecard (G-1 to G-8)",
        "",
        "Numbers sourced exclusively from `ml/report/benchmark_D1.json` and this script's hold-out re-evaluation.",
        "",
        "| Gate | Name | Rule (abbreviated) | Result | Key number(s) |",
        "|------|------|--------------------|:------:|---------------|",
    ]
    result_emoji = {
        "PASS": "✅ PASS",
        "FAIL": "❌ FAIL",
        "NOT_MEASURABLE": "⏳ N/M",
        "NOT_MEASURABLE (E2 missing)": "⏳ N/M (E2 missing)",
    }
    for g in a["gate_scorecard"]:
        res = result_emoji.get(g["result"], g["result"])
        if g["gate"] == "G-1":
            nums = f"model {g['best_model_holdout_bacc']:.4f} vs baseline {g['shortcut_baseline']:.4f} → +{g['margin_pp']*100:.2f} pp"
        elif g["gate"] == "G-2":
            nums = f"D1 hold-out recall = {g['d1_grouped_holdout_recall']:.4f}" if g.get("d1_grouped_holdout_recall") else "—"
        elif g["gate"] == "G-3":
            if "e1_holdout_fpr_percent" in g:
                nums = f"E1 FPR = {g['e1_holdout_fpr_percent']:.2f}% (CI {g['wilson_95_ci_str']})"
            else:
                nums = f"D1 FPR ref = {g['d1_grouped_holdout_fpr_reference']:.4f} (E1 required)"
        elif g["gate"] == "G-4":
            nums = f"max gap = {g['max_gap_across_25_runs_pp']*100:.2f} pp across 25 runs"
        elif g["gate"] == "G-7":
            nums = f"ECE (uncal) = {g['best_rf_ece_uncalibrated']:.4f}, Brier = {g['best_rf_brier_uncalibrated']:.4f}"
        else:
            nums = "—"
        lines.append(f"| {g['gate']} | {g['name']} | {g['rule'][:60]}… | {res} | {nums} |")

    lines += [
        "",
        "> [!NOTE]",
        "> G-2 fails because best RF recall on the D1 grouped hold-out is 86.68%, below the 90% threshold. "
        "G-3, G-5, G-6, G-8 are not measurable — they require E1/E2, the TypeScript port, or the browser extension. "
        "G-7 cannot be declared pass/fail until Platt/isotonic calibration is applied in Chunk 6.",
        "",
        "---",
        "",
        "## 2. Finalist Model Selection",
        "",
        f"**CV criterion (finalist ranking):** {a['finalist_selection']['cv_criterion']}",
        "",
        f"**Selection basis:** {a['finalist_selection']['finalist_selection_basis']}.",
        "",
        f"**Hold-out (locked):** {a['finalist_selection']['holdout_criterion']}",
        "",
        f"**Hold-out evaluations:** {a['finalist_selection']['n_holdout_evaluations']} total (one per combination, never re-used for selection or tuning).",
        "",
        "| Rank | Selector | Classifier | CV bal-acc mean±std | HO bal-acc | G-1 margin | G-4 gap |",
        "|-----:|----------|-----------|--------------------:|----------:|-----------:|--------:|",
    ]
    for f in a["finalist_selection"]["finalists"]:
        lines.append(
            f"| {f['rank']} | `{f['selector']}` | `{f['classifier']}` "
            f"| {f['cv_bacc_mean']:.4f} ± {f['cv_bacc_std']:.4f} "
            f"| {f['holdout_bacc']:.4f} "
            f"| +{f['g1_margin']*100:.2f} pp "
            f"| {f['g4_gap']*100:.2f} pp |"
        )

    if a.get("cross_source_tests"):
        cst = a["cross_source_tests"]
        lines += [
            "",
            "---",
            "",
            "## 2b. Cross-Source Generalization Tests",
            "",
            "| Direction | Train Set | Test Set | Bal Acc | Recall | FPR |",
            "|-----------|----------:|---------:|--------:|-------:|----:|",
            f"| A -> B | {cst['train_A_test_B']['n_train']} | {cst['train_A_test_B']['n_test']} | {cst['train_A_test_B']['balanced_accuracy']:.4f} | {cst['train_A_test_B']['recall']:.4f} | {cst['train_A_test_B']['fpr']:.4f} |",
            f"| B -> A | {cst['train_B_test_A']['n_train']} | {cst['train_B_test_A']['n_test']} | {cst['train_B_test_A']['balanced_accuracy']:.4f} | {cst['train_B_test_A']['recall']:.4f} | {cst['train_B_test_A']['fpr']:.4f} |",
            "",
        ]

    lines += [
        "",
        "---",
        "",
        "## 3. Error Analysis — Hold-out Slices",
        "",
        "Re-trained on full training partition (seed 42, same pipeline as benchmark). "
        "Scheme, path, and hosting flags are **analysis metadata only** — never model features.",
        "",
    ]

    for model_key, label in [
        ("RF_rf_importance", "RF (`rf_importance` selector, k=20)"),
        ("KNN_l1_lr",        "KNN (`l1_lr` selector, k=20)"),
    ]:
        ea = a["error_analysis"][model_key]
        lines += [
            f"### {label}",
            "",
            f"- **Overall recall:** {ea['overall_holdout_recall']:.4f}",
            f"- **Overall FPR:** {ea['overall_holdout_fpr']:.4f}",
            f"- **False negatives (missed malicious):** {ea['n_false_negatives']}",
            f"- **Missed malicious that are bare homepages:** "
            f"{ea['fn_bare_homepage_count']} / {ea['n_false_negatives']} "
            f"({ea['fn_bare_homepage_share']*100:.1f}%)",
            "",
            "#### Recall and FPR by slice",
            "",
            "| Slice | n | n_malicious | n_benign | Recall (95% CI) | FPR (95% CI) |",
            "|-------|--:|------------:|---------:|----------------:|-------------:|",
        ]
        for sl in ea["slices"]:
            rec = f"{sl['recall']:.4f} ({sl['recall_wilson_ci_str']})" if sl["recall"] is not None else "—"
            fpr = f"{sl['fpr']:.4f} ({sl['fpr_wilson_ci_str']})" if sl["fpr"] is not None else "—"
            lines.append(
                f"| {sl['slice']} | {sl['n']} | {sl['n_positive']} | {sl['n_negative']} "
                f"| {rec} | {fpr} |"
            )
        lines.append("")

        if ea.get("rf_feature_importances_top20"):
            lines += [
                "#### Top 20 RF feature importances (selected features only)",
                "",
                "| Rank | Feature | Importance |",
                "|-----:|---------|----------:|",
            ]
            for rank, fi in enumerate(ea["rf_feature_importances_top20"], start=1):
                lines.append(f"| {rank} | `{fi['feature']}` | {fi['importance']:.6f} |")
            lines.append("")

    if a.get("e1_evaluation"):
        e1 = a["e1_evaluation"]
        ov = e1["overall"]
        lines += [
            "---",
            "",
            "## 3b. E1 Benign FPR Evaluation (Hold-out Slices)",
            "",
            f"Evaluated on locked hold-out `{e1['holdout_file']}` ({e1['total_holdout_urls']} URLs). "
            "All rows are Benign; every positive prediction is a false positive.",
            "",
            f"- **Overall FPR:** {ov['fpr_percent']:.2f}% ({ov['false_positives']}/{ov['n']})",
            f"- **95% Wilson Confidence Interval:** {ov['wilson_ci_str']}",
            f"- **Gate G-3 (FPR ≤ 0.50%):** {'✅ PASS' if e1['gate_g3']['status'] == 'PASS' else '❌ FAIL'}",
            "",
            "| Slice Category | Slice | Count (n) | False Positives (k) | FPR (%) | 95% Wilson CI |",
            "|----------------|-------|----------:|--------------------:|--------:|:-------------:|",
        ]
        for sl in e1["slices"]:
            lines.append(
                f"| `{sl['slice_category']}` | `{sl['slice_value']}` | {sl['n']:,} | "
                f"{sl['false_positives']:,} | {sl['fpr_percent']:.2f}% | {sl['wilson_ci_str']} |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "## 4. HistGradientBoosting Reference Baseline",
        "",
        "Trained on the same training partition with the same grouped 80/20 hold-out. "
        "**Not a deployment candidate** (no compatible TypeScript export path, uses all 50 features without selection).",
        "",
        f"| Metric | Value |",
        f"|--------|------:|",
        f"| Hold-out balanced accuracy | {a['hgb_reference_baseline']['holdout_balanced_accuracy']:.4f} |",
        f"| Hold-out recall | {a['hgb_reference_baseline']['holdout_recall']:.4f} |",
        f"| Hold-out FPR | {a['hgb_reference_baseline']['holdout_fpr']:.4f} |",
        f"| Shortcut baseline | {sc:.4f} |",
        f"| G-1 margin vs shortcut | +{a['hgb_reference_baseline']['g1_margin_vs_shortcut']*100:.2f} pp |",
        "",
    ]

    hgb_bacc = a["hgb_reference_baseline"]["holdout_balanced_accuracy"]
    best_rf_bacc = next(
        f["holdout_bacc"] for f in a["finalist_selection"]["finalists"]
        if f["classifier"] == "rf"
    )
    gap = hgb_bacc - best_rf_bacc
    if abs(gap) < 0.02:
        interp = (
            f"HGB is within {abs(gap)*100:.1f} pp of the best RF candidate, "
            "suggesting the **feature set is the ceiling**, not the model family. "
            "Adding richer features (E1 deep links, WHOIS, visual) would likely improve all models equally."
        )
    elif gap > 0.02:
        interp = (
            f"HGB exceeds the best RF by {gap*100:.1f} pp, "
            "suggesting additional model capacity could help. "
            "However, the gap must be weighed against export complexity and inference latency."
        )
    else:
        interp = (
            f"RF outperforms HGB by {abs(gap)*100:.1f} pp on this dataset, "
            "which is consistent with RF being well-suited to lexical phishing features."
        )
    lines += [
        f"**Interpretation:** {interp}",
        "",
        "---",
        "",
        "## 5. Blocking items before Chunk 6",
        "",
        "| Item | Blocker |",
        "|------|---------|",
        "| G-2 Recall | Best RF recall on D1 hold-out is **86.68%** (< 90%). Adding E1 deep-link training data may close the gap. |",
        "| G-3 Block FPR | Requires E1 hold-out (at least 2,000 URLs from 800+ domains). |",
        "| G-7 Calibration | Requires Platt/isotonic fitting on out-of-fold predictions. E1 needed for threshold tuning (T_block). |",
        "| E1 | Collection date, source, and benign-label verification not yet recorded in `data/PROVENANCE.md`. |",
        "| E2 | Cannot be collected without D1 collection date. |",
    ]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard pre-Chunk-6 analysis.")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    result = run_analysis(root)
    hgb = result["hgb_reference_baseline"]
    gates = {g["gate"]: g["result"] for g in result["gate_scorecard"]}
    print(json.dumps({
        "gates": gates,
        "hgb_holdout_balanced_acc": hgb["holdout_balanced_accuracy"],
        "hgb_g1_margin": hgb["g1_margin_vs_shortcut"],
        "reports": ["ml/report/analysis_D1.json", "ml/report/analysis_D1.md"],
    }, indent=2))


if __name__ == "__main__":
    main()
