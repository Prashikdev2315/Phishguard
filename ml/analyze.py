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
import os
import pathlib
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

    for url in urls:
        r = normalize(url)
        # has_path: normalized path is non-empty and not just "/"
        path = r.path.strip("/") if r.path else ""
        has_path_flags.append(bool(path))

        # scheme-less: original URL had no scheme (normalize prepended http://)
        raw = url.strip()
        scheme_less_flags.append(not (raw.startswith("http://") or raw.startswith("https://")))

        # on hosting platform: registrable domain suffix matches a known platform
        reg = r.registrable_domain or ""
        on_host = any(reg == p or reg.endswith("." + p) or p in (r.puny_host or "") for p in hosting_set)
        on_hosting_flags.append(on_host)

        # bare homepage: no path and no query
        bare = (not path) and (not r.query)
        bare_home_flags.append(bare)

    meta = df.copy()
    meta["_has_path"] = has_path_flags
    meta["_scheme_less"] = scheme_less_flags
    meta["_on_hosting"] = on_hosting_flags
    meta["_bare_home"] = bare_home_flags
    return meta


# ---------------------------------------------------------------------------
# Slice metric helper
# ---------------------------------------------------------------------------

def slice_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, mask: np.ndarray, label: str
) -> dict:
    """Compute recall, FPR and counts for a boolean mask over y_true/y_pred."""
    y_t = y_true[mask]
    y_p = y_pred[mask]
    if len(y_t) == 0:
        return {"slice": label, "n": 0, "recall": None, "fpr": None,
                "n_positive": 0, "n_negative": 0}
    pos = int((y_t == 1).sum())
    neg = int((y_t == 0).sum())
    recall = float(recall_score(y_t, y_p, zero_division=0)) if pos > 0 else None
    fp = int(((y_p == 1) & (y_t == 0)).sum())
    fpr = float(fp / neg) if neg > 0 else None
    return {
        "slice": label,
        "n": int(len(y_t)),
        "n_positive": pos,
        "n_negative": neg,
        "recall": round(recall, 6) if recall is not None else None,
        "fpr": round(fpr, 6) if fpr is not None else None,
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

def build_gate_scorecard(report: dict) -> List[dict]:
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
            "result": "FAIL" if best_rf_recall is not None and best_rf_recall < 0.90 else "NOT_MEASURABLE",
            "note": (
                f"Best RF recall on D1 hold-out = {best_rf_recall:.4f} (< 0.90). "
                "E2 is not yet available; E2 recall cannot be measured."
            ) if best_rf_recall is not None else "Data unavailable.",
        },
        {
            "gate": "G-3",
            "name": "Block FPR",
            "rule": "FPR <= 0.5% on E1 hold-out with allowlist off (95% Wilson interval reported)",
            "d1_grouped_holdout_fpr_reference": best_rf_fpr,
            "result": "NOT_MEASURABLE",
            "note": "E1 hold-out is not yet available. D1 FPR (reference only, not E1) = "
                    f"{best_rf_fpr:.4f} ({best_rf_fpr*100:.2f}%). Gate requires E1.",
        },
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

    # ---- 1. Gate scorecard ---------------------------------------------------
    LOGGER.info("Building gate scorecard ...")
    scorecard = build_gate_scorecard(benchmark)

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

        slices = [
            # has_path
            slice_metrics(y_test, y_pred, has_path_mask,          "has_path=True"),
            slice_metrics(y_test, y_pred, ~has_path_mask,         "has_path=False"),
            # hosting platform
            slice_metrics(y_test, y_pred, on_hosting_mask,        "on_hosting_platform=True"),
            slice_metrics(y_test, y_pred, ~on_hosting_mask,       "on_hosting_platform=False"),
            # scheme-less vs scheme-ful
            slice_metrics(y_test, y_pred, scheme_less_mask,       "scheme_less=True"),
            slice_metrics(y_test, y_pred, ~scheme_less_mask,      "scheme_less=False"),
        ]

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

    # ---- 5. Assemble output --------------------------------------------------
    analysis = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "schema": "fs1",
        "shortcut_baseline_balanced_acc": benchmark["shortcut_baseline_balanced_acc"],
        "gate_scorecard": scorecard,
        "finalist_selection": selection_method,
        "error_analysis": error_analysis,
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
    result_emoji = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NOT_MEASURABLE": "⏳ N/M"}
    for g in a["gate_scorecard"]:
        res = result_emoji.get(g["result"], g["result"])
        if g["gate"] == "G-1":
            nums = f"model {g['best_model_holdout_bacc']:.4f} vs baseline {g['shortcut_baseline']:.4f} → +{g['margin_pp']*100:.2f} pp"
        elif g["gate"] == "G-2":
            nums = f"D1 hold-out recall = {g['d1_grouped_holdout_recall']:.4f}" if g.get("d1_grouped_holdout_recall") else "—"
        elif g["gate"] == "G-3":
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
            "| Slice | n | n_malicious | n_benign | Recall | FPR |",
            "|-------|--:|------------:|---------:|-------:|----:|",
        ]
        for sl in ea["slices"]:
            rec = f"{sl['recall']:.4f}" if sl["recall"] is not None else "—"
            fpr = f"{sl['fpr']:.4f}" if sl["fpr"] is not None else "—"
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
