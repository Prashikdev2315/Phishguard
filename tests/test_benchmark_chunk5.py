"""
tests/test_benchmark_chunk5.py — ML-01 to ML-04 guard tests for Chunk 5.

These tests use a small synthetic dataset so they run fast.
They verify the benchmark pipeline contracts without running the full 25 runs.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pathlib
import tempfile
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

import os
os.environ.setdefault("PHISHGUARD_ENV", "development")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tiny_csvs(tmp: pathlib.Path):
    """Write minimal train.csv and test.csv with non-overlapping domains."""
    benign_domains = [f"good{i}.com" for i in range(15)]
    malicious_domains = [f"evil{i}.com" for i in range(15)]

    rows_train = []
    rows_test = []

    for i, domain in enumerate(benign_domains):
        urls = [
            f"http://{domain}/page{'x' * (i * 3)}",
            f"http://{domain}/about?val={i}",
        ]
        target = rows_train if i < 12 else rows_test
        for u in urls:
            target.append({"URL": u, "type": "Benign", "registrable_domain": domain})

    for i, domain in enumerate(malicious_domains):
        urls = [
            f"http://{domain}/login?steal={i}&token={'y' * (i * 2)}",
            f"http://{domain}/verify/{i}",
        ]
        target = rows_train if i < 12 else rows_test
        for u in urls:
            target.append({"URL": u, "type": "Malicious", "registrable_domain": domain})

    train_path = tmp / "train.csv"
    test_path = tmp / "test.csv"
    pd.DataFrame(rows_train).to_csv(train_path, index=False)
    pd.DataFrame(rows_test).to_csv(test_path, index=False)
    return train_path, test_path


# ---------------------------------------------------------------------------
# ML-01: No domain overlap between train and test
# ---------------------------------------------------------------------------

class TestML01DomainLeakage:
    def test_load_split_produces_correct_groups(self, tmp_path):
        """Groups returned by load_split match the registrable_domain column."""
        from ml.train import load_split
        train_path, _ = _make_tiny_csvs(tmp_path)
        X, y, groups = load_split(train_path)
        df = pd.read_csv(train_path)
        assert list(groups) == list(df["registrable_domain"].values)

    def test_no_domain_overlap_in_synthetic_splits(self, tmp_path):
        """The synthetic CSVs we build have zero domain overlap."""
        from ml.train import load_split
        train_path, test_path = _make_tiny_csvs(tmp_path)
        _, _, g_train = load_split(train_path)
        _, _, g_test = load_split(test_path)
        overlap = set(g_train) & set(g_test)
        assert len(overlap) == 0, f"Domain overlap detected: {overlap}"

    def test_domain_overlap_raises(self, tmp_path):
        """run_benchmark must raise AssertionError if domains overlap."""
        from ml.train import run_benchmark
        # Create leaky splits (same domain in both)
        rows = [
            {"URL": "http://leaky.com/", "type": "Benign", "registrable_domain": "leaky.com"},
            {"URL": "http://leaky.com/evil", "type": "Malicious", "registrable_domain": "leaky.com"},
        ]
        train_path = tmp_path / "train_leak.csv"
        test_path = tmp_path / "test_leak.csv"
        pd.DataFrame(rows[:1] * 20 + rows[1:] * 20).to_csv(train_path, index=False)
        pd.DataFrame(rows[:1] * 5 + rows[1:] * 5).to_csv(test_path, index=False)
        with pytest.raises(AssertionError, match="ML-01"):
            run_benchmark(train_path, test_path, tmp_path, seed=42)


# ---------------------------------------------------------------------------
# ML-02: Pipeline is leakage-free (scaler fit inside each fold)
# ---------------------------------------------------------------------------

class TestML02PipelineLeakage:
    def test_fitted_scaler_differs_across_folds(self, tmp_path):
        """Scaler means must differ between folds — proving it's fit on fold data only."""
        from ml.train import build_pipeline, CV_SEEDS, N_SPLITS
        from sklearn.model_selection import StratifiedGroupKFold
        from ml.train import load_split

        train_path, _ = _make_tiny_csvs(tmp_path)
        X, y, groups = load_split(train_path)

        scaler_params = []
        sgkf = StratifiedGroupKFold(n_splits=min(N_SPLITS, 3), shuffle=True, random_state=42)
        for fit_idx, _ in sgkf.split(X, y, groups):
            pipe = build_pipeline("chi2", "lr", k=5, seed=42)
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                pipe.fit(X[fit_idx], y[fit_idx])
            scaler_params.append(pipe.named_steps["scaler"].scale_.copy())

        # At least one pair of folds must have different scaler parameters
        assert not np.allclose(scaler_params[0], scaler_params[-1]), (
            "Scaler scales are identical across folds — possible leakage."
        )

    def test_cv_fold_domain_guard(self, tmp_path):
        """run_cv must not raise on a clean (non-overlapping) dataset."""
        from ml.train import run_cv, load_split
        train_path, _ = _make_tiny_csvs(tmp_path)
        X, y, groups = load_split(train_path)
        # Should complete without AssertionError
        result = run_cv(X, y, groups, "chi2", "lr", k=5)
        assert "cv_metrics" in result
        assert "balanced_accuracy" in result["cv_metrics"]


# ---------------------------------------------------------------------------
# ML-03: 25-run benchmark completes and writes its report
# ---------------------------------------------------------------------------

class TestML03BenchmarkCompletes:
    def test_benchmark_writes_json_and_md(self, tmp_path):
        """run_benchmark must produce benchmark_D1.json and benchmark_D1.md."""
        from ml.train import run_benchmark, SELECTOR_NAMES, CLASSIFIER_NAMES
        train_path, test_path = _make_tiny_csvs(tmp_path)

        # Patch to run only 1 combo (chi2 × lr) to keep tests fast
        import ml.train as train_mod
        orig_sel = train_mod.SELECTOR_NAMES
        orig_clf = train_mod.CLASSIFIER_NAMES
        train_mod.SELECTOR_NAMES = ["chi2"]
        train_mod.CLASSIFIER_NAMES = ["lr"]
        try:
            report = run_benchmark(train_path, test_path, tmp_path, seed=42)
        finally:
            train_mod.SELECTOR_NAMES = orig_sel
            train_mod.CLASSIFIER_NAMES = orig_clf

        assert (tmp_path / "ml" / "report" / "benchmark_D1.json").exists()
        assert (tmp_path / "ml" / "report" / "benchmark_D1.md").exists()
        assert report["domain_overlap_train_test"] == 0
        assert len(report["runs"]) == 1

    def test_shortcut_baseline_in_report(self, tmp_path):
        """Report must include a numeric shortcut_baseline_balanced_acc."""
        from ml.train import run_benchmark
        import ml.train as train_mod
        orig_sel, orig_clf = train_mod.SELECTOR_NAMES, train_mod.CLASSIFIER_NAMES
        train_mod.SELECTOR_NAMES = ["chi2"]
        train_mod.CLASSIFIER_NAMES = ["lr"]
        train_path, test_path = _make_tiny_csvs(tmp_path)
        try:
            report = run_benchmark(train_path, test_path, tmp_path, seed=42)
        finally:
            train_mod.SELECTOR_NAMES = orig_sel
            train_mod.CLASSIFIER_NAMES = orig_clf
        sc = report["shortcut_baseline_balanced_acc"]
        assert isinstance(sc, float), "shortcut_baseline_balanced_acc must be a float"
        assert 0.0 <= sc <= 1.0


# ---------------------------------------------------------------------------
# ML-04: Gate G-1 logic is correct
# ---------------------------------------------------------------------------

class TestML04GateG1:
    def test_g1_margin_computed_correctly(self, tmp_path):
        """G1_margin must equal holdout_balanced_acc minus shortcut_baseline."""
        from ml.train import run_benchmark
        import ml.train as train_mod
        orig_sel, orig_clf = train_mod.SELECTOR_NAMES, train_mod.CLASSIFIER_NAMES
        train_mod.SELECTOR_NAMES = ["chi2"]
        train_mod.CLASSIFIER_NAMES = ["lr"]
        train_path, test_path = _make_tiny_csvs(tmp_path)
        try:
            report = run_benchmark(train_path, test_path, tmp_path, seed=42)
        finally:
            train_mod.SELECTOR_NAMES = orig_sel
            train_mod.CLASSIFIER_NAMES = orig_clf

        for run in report["runs"]:
            if run.get("status") != "ok":
                continue
            sc = report["shortcut_baseline_balanced_acc"]
            ho_bacc = run["holdout"]["balanced_accuracy"]
            expected_margin = round(ho_bacc - sc, 6)
            assert abs(run["gates"]["G1_margin"] - expected_margin) < 1e-5, (
                f"G1_margin mismatch: got {run['gates']['G1_margin']}, "
                f"expected {expected_margin}"
            )
            if run["gates"]["G1_margin"] >= 0.05:
                assert run["gates"]["G1_pass"] is True
            else:
                assert run["gates"]["G1_pass"] is False

    def test_metrics_all_present(self, tmp_path):
        """All required metrics must be present in holdout results."""
        from ml.train import run_benchmark
        import ml.train as train_mod
        orig_sel, orig_clf = train_mod.SELECTOR_NAMES, train_mod.CLASSIFIER_NAMES
        train_mod.SELECTOR_NAMES = ["chi2"]
        train_mod.CLASSIFIER_NAMES = ["lr"]
        train_path, test_path = _make_tiny_csvs(tmp_path)
        try:
            report = run_benchmark(train_path, test_path, tmp_path, seed=42)
        finally:
            train_mod.SELECTOR_NAMES = orig_sel
            train_mod.CLASSIFIER_NAMES = orig_clf

        required = {
            "balanced_accuracy", "accuracy", "recall", "precision",
            "f1", "f2", "fpr", "fnr", "roc_auc", "pr_auc", "mcc", "brier", "ece",
        }
        for run in report["runs"]:
            if run.get("status") != "ok":
                continue
            missing = required - set(run["holdout"].keys())
            assert not missing, f"Missing holdout metrics: {missing}"


# ---------------------------------------------------------------------------
# Selector / pipeline unit tests
# ---------------------------------------------------------------------------

class TestPipelineComponents:
    def test_all_selectors_produce_k_features(self):
        """Each selector must select exactly k features on a small array."""
        import warnings
        from ml.train import build_pipeline
        rng = np.random.default_rng(0)
        X = np.abs(rng.standard_normal((60, 20)))
        y = np.array([0] * 30 + [1] * 30)

        for sel_name in ["chi2", "mutual_info", "l1_lr", "rf_importance", "rfe_rf"]:
            pipe = build_pipeline(sel_name, "lr", k=5, seed=42)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                pipe.fit(X, y)
            selector = pipe.named_steps["selector"]
            if hasattr(selector, "get_support"):
                n_sel = int(selector.get_support().sum())
                assert n_sel == 5, f"{sel_name}: expected 5 features, got {n_sel}"

    def test_all_classifiers_produce_probabilities(self):
        """Every classifier must expose predict_proba or decision_function."""
        import warnings
        from ml.train import build_pipeline, _get_proba
        rng = np.random.default_rng(1)
        X = np.abs(rng.standard_normal((60, 10)))
        y = np.array([0] * 30 + [1] * 30)

        for clf_name in ["knn", "rf", "svm", "lr", "gnb"]:
            pipe = build_pipeline("chi2", clf_name, k=5, seed=42)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                pipe.fit(X, y)
            proba = _get_proba(pipe, X[:10])
            assert proba.shape == (10,), f"{clf_name}: wrong proba shape"
            assert np.all((proba >= 0) & (proba <= 1)), f"{clf_name}: probabilities out of [0,1]"
