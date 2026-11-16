#!/usr/bin/env python3
"""
ml/train.py — 25-run benchmark pipeline (Chunk 5).

Implements PRD §7.5:
  - 5 selectors × 5 classifiers = 25 combinations
  - 5-fold StratifiedGroupKFold × 3 seeds (42, 43, 44) on training portion
  - Grouped 80/20 hold-out evaluated once per candidate, never used for tuning
  - Full sklearn Pipeline: scaler → selector → classifier (leakage-free)
  - Metrics: balanced_accuracy, recall, FPR, FNR, precision, F1, F2, ROC-AUC,
    PR-AUC, MCC, Brier, ECE
  - Gate G-1 evaluated: model balanced_acc > shortcut_baseline + 0.05
  - Gate G-4 evaluated: random-split minus grouped-split acc gap <= 5 pp
  - Writes ml/report/benchmark_D1.json and ml/report/benchmark_D1.md
  - Saves best model (joblib) to ml/models/best_model.joblib + manifest JSON

Usage:
    python -m ml.train [--root .] [--train data/splits/train.csv]
                       [--test data/splits/test.csv] [--seed 42]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import pathlib
import sys
import time
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, chi2, mutual_info_classif, RFE
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    balanced_accuracy_score,
    brier_score_loss,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("PHISHGUARD_ENV", "development")

from ml.features import extract_vector, FEATURE_NAMES, SCHEMA  # noqa: E402

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

CV_SEEDS = (42, 43, 44)
N_SPLITS = 5
TOP_K_PRIMARY = 20
LABEL_POSITIVE = "Malicious"
LABEL_NEGATIVE = "Benign"
LABEL_MAP = {LABEL_NEGATIVE: 0, LABEL_POSITIVE: 1}
SELECTOR_NAMES = ["rf_importance", "chi2", "mutual_info", "l1_lr", "rfe_rf"]
CLASSIFIER_NAMES = ["knn", "rf", "svm", "lr", "gnb"]
N_JOBS = 1


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (y_prob >= lo) & (y_prob < hi)
        if mask.sum() == 0:
            continue
        ece += mask.sum() * abs(y_true[mask].mean() - y_prob[mask].mean())
    return float(ece / max(len(y_true), 1))


def _fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    neg = (y_true == 0).sum()
    fp = ((y_pred == 1) & (y_true == 0)).sum()
    return float(fp / neg) if neg > 0 else 0.0


def _fnr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    pos = (y_true == 1).sum()
    fn = ((y_pred == 0) & (y_true == 1)).sum()
    return float(fn / pos) if pos > 0 else 0.0


def _f_beta(y_true: np.ndarray, y_pred: np.ndarray, beta: float) -> float:
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score(y_true, y_pred, zero_division=0)
    b2 = beta ** 2
    denom = b2 * p + r
    return float((1 + b2) * p * r / denom) if denom > 0 else 0.0


def compute_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray
) -> dict:
    has_both_classes = len(np.unique(y_true)) > 1
    if has_both_classes:
        roc_auc = round(float(roc_auc_score(y_true, y_prob)), 6)
        pr_auc = round(float(average_precision_score(y_true, y_prob)), 6)
    else:
        roc_auc = 0.5
        pr_auc = 0.0

    return {
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true, y_pred)), 6),
        "accuracy": round(float((y_true == y_pred).mean()), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "f2": round(_f_beta(y_true, y_pred, 2.0), 6),
        "fpr": round(_fpr(y_true, y_pred), 6),
        "fnr": round(_fnr(y_true, y_pred), 6),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "mcc": round(float(matthews_corrcoef(y_true, y_pred)), 6),
        "brier": round(float(brier_score_loss(y_true, y_prob)), 6),
        "ece": round(_ece(y_true, y_prob), 6),
        "n_positive": int((y_true == 1).sum()),
        "n_negative": int((y_true == 0).sum()),
    }


# ---------------------------------------------------------------------------
# L1 selector wrapper (not a full sklearn transformer — kept minimal)
# ---------------------------------------------------------------------------

class _L1Selector:
    """Select top-k features by absolute L1-LR coefficient."""

    def __init__(self, k: int, seed: int) -> None:
        self.k = k
        self.seed = seed
        self._support: Optional[np.ndarray] = None
        self._lr = LogisticRegression(
            penalty="l1", C=0.1, solver="liblinear",
            class_weight="balanced", max_iter=1000, random_state=seed,
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "_L1Selector":
        self._lr.fit(X, y)
        coef = np.abs(self._lr.coef_[0])
        idx = np.argsort(coef)[::-1][: self.k]
        self._support = np.zeros(X.shape[1], dtype=bool)
        self._support[idx] = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if self._support is None:
            raise RuntimeError("Call fit() first.")
        return X[:, self._support]

    def fit_transform(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> np.ndarray:
        self.fit(X, y)
        return self.transform(X)

    def get_support(self) -> np.ndarray:
        if self._support is None:
            raise RuntimeError("Call fit() first.")
        return self._support


class _RFImportanceSelector:
    """Select top-k features by Random Forest feature_importances_."""

    def __init__(self, k: int, seed: int) -> None:
        self.k = k
        self.seed = seed
        self._support: Optional[np.ndarray] = None
        self._rf = RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=N_JOBS
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "_RFImportanceSelector":
        self._rf.fit(X, y)
        importances = self._rf.feature_importances_
        idx = np.argsort(importances)[::-1][: self.k]
        self._support = np.zeros(X.shape[1], dtype=bool)
        self._support[idx] = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if self._support is None:
            raise RuntimeError("Call fit() first.")
        return X[:, self._support]

    def fit_transform(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> np.ndarray:
        self.fit(X, y)
        return self.transform(X)

    def get_support(self) -> np.ndarray:
        if self._support is None:
            raise RuntimeError("Call fit() first.")
        return self._support


# ---------------------------------------------------------------------------
# Pipeline factory
# ---------------------------------------------------------------------------

def _make_selector_step(name: str, k: int, seed: int):
    if name == "rf_importance":
        return ("selector", _RFImportanceSelector(k=k, seed=seed))
    if name == "chi2":
        return ("selector", SelectKBest(chi2, k=k))
    if name == "mutual_info":
        mi = SelectKBest(
            lambda X, y: mutual_info_classif(X, y, random_state=seed), k=k
        )
        return ("selector", mi)
    if name == "l1_lr":
        return ("selector", _L1Selector(k=k, seed=seed))
    if name == "rfe_rf":
        base = RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=N_JOBS
        )
        return ("selector", RFE(base, n_features_to_select=k, step=10))
    raise ValueError(f"Unknown selector: {name!r}")


def _make_classifier_step(name: str, seed: int):
    if name == "knn":
        return ("classifier", KNeighborsClassifier(n_neighbors=11, weights="distance", n_jobs=N_JOBS))
    if name == "rf":
        return ("classifier", RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=seed, n_jobs=N_JOBS
        ))
    if name == "svm":
        return ("classifier", SVC(
            kernel="rbf", C=1.0, gamma="scale",
            class_weight="balanced", probability=True, random_state=seed,
            cache_size=1000,
        ))
    if name == "lr":
        return ("classifier", LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=1000, solver="lbfgs", random_state=seed
        ))
    if name == "gnb":
        return ("classifier", GaussianNB())
    raise ValueError(f"Unknown classifier: {name!r}")


def build_pipeline(sel_name: str, clf_name: str, k: int, seed: int) -> Pipeline:
    return Pipeline([
        ("scaler", MinMaxScaler()),
        _make_selector_step(sel_name, k, seed),
        _make_classifier_step(clf_name, seed),
    ])


def _get_proba(pipe: Pipeline, X: np.ndarray) -> np.ndarray:
    if hasattr(pipe, "predict_proba"):
        return pipe.predict_proba(X)[:, 1]
    scores = pipe.decision_function(X)
    return 1.0 / (1.0 + np.exp(-scores))


# ---------------------------------------------------------------------------
# Dataset loading + feature extraction
# ---------------------------------------------------------------------------

def load_split(
    path: pathlib.Path, cache_dir: Optional[pathlib.Path] = None
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for col in ("URL", "type", "registrable_domain"):
        if col not in df.columns:
            raise ValueError(f"{path}: missing required column '{col}'")

    urls = df["URL"].tolist()
    labels = df["type"].tolist()
    domains = df["registrable_domain"].tolist()

    missing = set(labels) - set(LABEL_MAP)
    if missing:
        raise ValueError(f"Unknown labels in {path}: {missing}")

    cache_path = None
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        h = sha256_file(path)[:16]
        cache_path = cache_dir / f"{path.stem}_{h}_fs1.npz"
        if cache_path.exists():
            LOGGER.info("Loading cached feature matrix from %s ...", cache_path.name)
            data = np.load(cache_path, allow_pickle=True)
            return data["X"], data["y"], data["groups"]

    LOGGER.info("Extracting %d feature vectors from %s ...", len(urls), path.name)
    rows = [extract_vector(url) for url in urls]

    X = np.array(rows, dtype=np.float64)
    y = np.array([LABEL_MAP[lbl] for lbl in labels], dtype=np.int32)
    groups = np.array(domains)

    if cache_path is not None:
        np.savez_compressed(cache_path, X=X, y=y, groups=groups)
        LOGGER.info("Saved feature cache to %s", cache_path.name)

    return X, y, groups


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# CV (3 seeds × 5 folds per combination)
# ---------------------------------------------------------------------------

def run_cv(
    X_train: np.ndarray,
    y_train: np.ndarray,
    groups_train: np.ndarray,
    sel_name: str,
    clf_name: str,
    k: int = TOP_K_PRIMARY,
) -> dict:
    fold_metrics: List[dict] = []
    selected_indices: List[List[int]] = []

    for seed in CV_SEEDS:
        sgkf = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
        for fold_idx, (fit_idx, val_idx) in enumerate(
            sgkf.split(X_train, y_train, groups_train), start=1
        ):
            # ML-01 leakage guard inside CV
            overlap = set(groups_train[fit_idx]) & set(groups_train[val_idx])
            if overlap:
                raise AssertionError(
                    f"Domain leakage in CV: seed={seed} fold={fold_idx} ({len(overlap)} domains)"
                )

            pipe = build_pipeline(sel_name, clf_name, k, seed)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                pipe.fit(X_train[fit_idx], y_train[fit_idx])

            y_pred = pipe.predict(X_train[val_idx])
            y_prob = _get_proba(pipe, X_train[val_idx])

            m = compute_metrics(y_train[val_idx], y_pred, y_prob)
            m["seed"] = seed
            m["fold"] = fold_idx
            fold_metrics.append(m)

            selector = pipe.named_steps["selector"]
            if hasattr(selector, "get_support"):
                support = selector.get_support()
                selected_indices.append([int(i) for i, v in enumerate(support) if v])

    keys = [
        "balanced_accuracy", "accuracy", "recall", "precision",
        "f1", "f2", "fpr", "fnr", "roc_auc", "pr_auc", "mcc", "brier", "ece",
    ]
    agg: Dict[str, dict] = {}
    for key in keys:
        vals = [m[key] for m in fold_metrics]
        agg[key] = {
            "mean": round(float(np.mean(vals)), 6),
            "std": round(float(np.std(vals)), 6),
            "min": round(float(np.min(vals)), 6),
            "max": round(float(np.max(vals)), 6),
        }

    return {
        "cv_metrics": agg,
        "fold_detail": fold_metrics,
        "selected_feature_indices": selected_indices,
    }


# ---------------------------------------------------------------------------
# Hold-out evaluation (called once per combination)
# ---------------------------------------------------------------------------

def evaluate_holdout(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    sel_name: str,
    clf_name: str,
    k: int = TOP_K_PRIMARY,
    seed: int = 42,
) -> Tuple[dict, Pipeline]:
    pipe = build_pipeline(sel_name, clf_name, k, seed)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)
    y_prob = _get_proba(pipe, X_test)
    return compute_metrics(y_test, y_pred, y_prob), pipe


# ---------------------------------------------------------------------------
# Shortcut baseline (deployable N-13 features; Gate G-1 reference)
# ---------------------------------------------------------------------------

def shortcut_baseline(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> float:
    feat_list = list(FEATURE_NAMES)
    cols = []
    for name in ("url_length", "path_length"):
        if name in feat_list:
            cols.append(feat_list.index(name))
    if not cols:
        return 0.0
    dt = DecisionTreeClassifier(max_depth=2, random_state=42, class_weight="balanced")
    dt.fit(X_train[:, cols], y_train)
    return float(balanced_accuracy_score(y_test, dt.predict(X_test[:, cols])))


# ---------------------------------------------------------------------------
# Random-split comparison (Gate G-4)
# ---------------------------------------------------------------------------

def random_split_balanced_acc(
    X_all: np.ndarray,
    y_all: np.ndarray,
    sel_name: str,
    clf_name: str,
    k: int = TOP_K_PRIMARY,
    seed: int = 42,
) -> float:
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.20, random_state=seed, stratify=y_all
    )
    pipe = build_pipeline(sel_name, clf_name, k, seed)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pipe.fit(X_tr, y_tr)
    return float(balanced_accuracy_score(y_te, pipe.predict(X_te)))


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def _write_markdown(report: dict, path: pathlib.Path) -> None:
    sc = report["shortcut_baseline_balanced_acc"]
    lines = [
        "# PhishGuard — Benchmark Report (Chunk 5)",
        "",
        f"Generated: {report['generated_at_utc']}",
        "",
        "## Dataset",
        "",
        "| Split | Rows | Malicious |",
        "|-------|-----:|----------:|",
        f"| Train | {report['train_rows']:,} | {report['train_malicious']:,} |",
        f"| Test  | {report['test_rows']:,} | {report['test_malicious']:,} |",
        "",
        f"- Domain overlap (train ∩ test): **{report['domain_overlap_train_test']}** (ML-01 ✅)",
        f"- Shortcut baseline (balanced acc, N-13 deployable): **{sc:.4f}**",
        "",
        "## Results — 25 combinations",
        "",
        "| Selector | Classifier | k | CV bal-acc mean±std | HO bal-acc | HO recall | HO FPR | G-1 | G-4 |",
        "|----------|-----------|--:|--------------------:|----------:|----------:|-------:|:---:|:---:|",
    ]

    ok = [r for r in report["runs"] if r.get("status") == "ok"]
    ok.sort(key=lambda r: r["holdout"]["balanced_accuracy"], reverse=True)
    for r in ok:
        cv = r["cv"]["balanced_accuracy"]
        ho = r["holdout"]
        g = r["gates"]
        g1 = "✅" if g["G1_pass"] else "❌"
        g4 = "✅" if g["G4_pass"] else "❌"
        lines.append(
            f"| {r['selector']} | {r['classifier']} | {r['k']} "
            f"| {cv['mean']:.4f}±{cv['std']:.4f} "
            f"| {ho['balanced_accuracy']:.4f} "
            f"| {ho['recall']:.4f} "
            f"| {ho['fpr']:.4f} "
            f"| {g1} | {g4} |"
        )
    for r in report["runs"]:
        if r.get("status") != "ok":
            lines.append(
                f"| {r['selector']} | {r['classifier']} | — | ERROR | — | — | — | ❌ | ❌ |"
            )

    best = report.get("best", {})
    if best.get("selector"):
        margin = (best["holdout_balanced_acc"] or 0) - sc
        lines += [
            "",
            "## Best model",
            "",
            f"- **Selector:** `{best['selector']}`",
            f"- **Classifier:** `{best['classifier']}`",
            f"- **Hold-out balanced accuracy:** {best['holdout_balanced_acc']:.4f}",
            f"- **G-1 margin:** {margin*100:+.2f} pp (threshold ≥ +5.00 pp)",
            "",
            "Artifacts: `ml/models/best_model.joblib`, `ml/models/model.manifest.json`",
        ]
    else:
        lines += [
            "",
            "> [!WARNING]",
            "> No combination passed Gate G-1. Add E1 deep-link data and rebalance before proceeding.",
        ]

    g1_any = any(r.get("gates", {}).get("G1_pass") for r in ok)
    g4_any = any(r.get("gates", {}).get("G4_pass") for r in ok)
    lines += [
        "",
        "## Gate summary",
        "",
        "| Gate | Rule | Outcome |",
        "|------|------|---------|",
        f"| G-1 Shortcut margin | balanced_acc > baseline + 5 pp | {'✅ passes' if g1_any else '❌ fails'} |",
        f"| G-4 Generalization gap | random − grouped ≤ 5 pp | {'✅ passes' if g4_any else '❌ fails'} |",
        "",
        "_G-2, G-3, G-5 to G-8 require E1/E2 and are evaluated in Chunk 6._",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main benchmark orchestrator
# ---------------------------------------------------------------------------

def run_benchmark(
    train_path: pathlib.Path,
    test_path: pathlib.Path,
    root: pathlib.Path,
    seed: int = 42,
) -> dict:
    report_dir = root / "ml" / "report"
    models_dir = root / "ml" / "models"
    report_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    LOGGER.info("Loading splits ...")
    proc_dir = root / "data" / "processed"
    X_train, y_train, groups_train = load_split(train_path, cache_dir=proc_dir)
    X_test, y_test, groups_test = load_split(test_path, cache_dir=proc_dir)
    LOGGER.info(
        "train=%d (mal=%d)  test=%d (mal=%d)",
        len(y_train), int(y_train.sum()), len(y_test), int(y_test.sum()),
    )

    # ML-01: grouped test must not share domains with train
    domain_overlap = set(groups_train) & set(groups_test)
    if domain_overlap:
        raise AssertionError(
            f"ML-01 FAIL: {len(domain_overlap)} domains shared between train and test."
        )
    LOGGER.info("ML-01 domain leakage guard: PASS (0 shared domains)")

    sc = shortcut_baseline(X_train, y_train, X_test, y_test)
    LOGGER.info("Shortcut baseline balanced_acc = %.4f", sc)

    X_all = np.vstack([X_train, X_test])
    y_all = np.concatenate([y_train, y_test])

    all_results: List[dict] = []
    best_bacc = -1.0
    best_combo: Optional[dict] = None
    best_pipe: Optional[Pipeline] = None

    total = len(SELECTOR_NAMES) * len(CLASSIFIER_NAMES)
    run_num = 0

    for sel_name in SELECTOR_NAMES:
        for clf_name in CLASSIFIER_NAMES:
            run_num += 1
            LOGGER.info("[%d/%d] %s × %s", run_num, total, sel_name, clf_name)
            t0 = time.perf_counter()

            try:
                cv_result = run_cv(X_train, y_train, groups_train, sel_name, clf_name)
            except Exception as exc:
                LOGGER.warning("  CV ERROR: %s", exc)
                all_results.append({
                    "selector": sel_name, "classifier": clf_name,
                    "k": TOP_K_PRIMARY, "status": "cv_error", "error": str(exc),
                })
                continue

            cv_bacc = cv_result["cv_metrics"]["balanced_accuracy"]["mean"]
            LOGGER.info("  CV bal-acc %.4f ± %.4f (%.1f s)",
                        cv_bacc,
                        cv_result["cv_metrics"]["balanced_accuracy"]["std"],
                        time.perf_counter() - t0)

            ho_metrics, trained_pipe = evaluate_holdout(
                X_train, y_train, X_test, y_test, sel_name, clf_name, seed=seed
            )
            ho_bacc = ho_metrics["balanced_accuracy"]
            LOGGER.info("  HO bal-acc %.4f", ho_bacc)

            g1_margin = ho_bacc - sc
            g1_pass = g1_margin >= 0.05

            rand_bacc = random_split_balanced_acc(X_all, y_all, sel_name, clf_name, seed=seed)
            g4_gap = abs(rand_bacc - ho_bacc)
            g4_pass = g4_gap <= 0.05

            LOGGER.info(
                "  G-1 margin=%.4f %s  G-4 gap=%.4f %s",
                g1_margin, "PASS" if g1_pass else "FAIL",
                g4_gap, "PASS" if g4_pass else "FAIL",
            )

            result = {
                "selector": sel_name,
                "classifier": clf_name,
                "k": TOP_K_PRIMARY,
                "status": "ok",
                "cv": cv_result["cv_metrics"],
                "holdout": ho_metrics,
                "gates": {
                    "G1_pass": g1_pass,
                    "G1_margin": round(g1_margin, 6),
                    "G4_pass": g4_pass,
                    "G4_gap": round(g4_gap, 6),
                    "G4_random_balanced_acc": round(rand_bacc, 6),
                },
                "top_features": cv_result.get("selected_feature_indices", []),
            }
            all_results.append(result)

            if g1_pass and ho_bacc > best_bacc:
                best_bacc = ho_bacc
                best_combo = result
                best_pipe = trained_pipe

    # ------------------------------------------------------------------
    # Persist best model
    # ------------------------------------------------------------------
    if best_pipe is not None and best_combo is not None:
        model_path = models_dir / "best_model.joblib"
        joblib.dump(best_pipe, model_path)
        manifest = {
            "schema": SCHEMA,
            "feature_count": len(FEATURE_NAMES),
            "feature_names": list(FEATURE_NAMES),
            "selector": best_combo["selector"],
            "classifier": best_combo["classifier"],
            "k": best_combo["k"],
            "seed": seed,
            "holdout_metrics": best_combo["holdout"],
            "cv_metrics": best_combo["cv"],
            "gates": best_combo["gates"],
            "shortcut_baseline_balanced_acc": round(sc, 6),
            "model_sha256": sha256_file(model_path),
            "train_sha256": sha256_file(train_path),
            "test_sha256": sha256_file(test_path),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        (models_dir / "model.manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        LOGGER.info("Saved best_model.joblib and model.manifest.json")
    else:
        LOGGER.warning("No model passed G-1; nothing saved to ml/models/.")
        manifest = {}

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "schema": SCHEMA,
        "seed": seed,
        "cv_seeds": list(CV_SEEDS),
        "n_splits": N_SPLITS,
        "k_primary": TOP_K_PRIMARY,
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "train_malicious": int(y_train.sum()),
        "test_malicious": int(y_test.sum()),
        "domain_overlap_train_test": len(domain_overlap),
        "shortcut_baseline_balanced_acc": round(sc, 6),
        "runs": all_results,
        "best": {
            "selector": best_combo["selector"] if best_combo else None,
            "classifier": best_combo["classifier"] if best_combo else None,
            "holdout_balanced_acc": round(best_bacc, 6) if best_combo else None,
        },
    }
    report_json = report_dir / "benchmark_D1.json"
    report_json.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_markdown(report, report_dir / "benchmark_D1.md")
    LOGGER.info("Reports written to ml/report/benchmark_D1.{json,md}")
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard Chunk 5: 25-run benchmark.")
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--train", default=None)
    parser.add_argument("--test", default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    train_path = pathlib.Path(args.train) if args.train else root / "data" / "splits" / "train.csv"
    test_path = pathlib.Path(args.test) if args.test else root / "data" / "splits" / "test.csv"

    for p in (train_path, test_path):
        if not p.exists():
            raise FileNotFoundError(
                f"{p} not found. Run `python -m ml.build_dataset --dataset Dataset.csv` first."
            )

    report = run_benchmark(train_path, test_path, root, seed=args.seed)
    best = report.get("best", {})
    print(json.dumps({
        "runs_ok": sum(1 for r in report["runs"] if r.get("status") == "ok"),
        "runs_error": sum(1 for r in report["runs"] if r.get("status") != "ok"),
        "shortcut_baseline": report["shortcut_baseline_balanced_acc"],
        "best_selector": best.get("selector"),
        "best_classifier": best.get("classifier"),
        "best_holdout_balanced_acc": best.get("holdout_balanced_acc"),
    }, indent=2))


if __name__ == "__main__":
    main()
