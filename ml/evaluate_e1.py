#!/usr/bin/env python3
"""
ml/evaluate_e1.py — E1 benign FPR slice evaluation for PhishGuard (Chunk 5c).

Evaluates the trained model (ml/models/best_model.joblib) on the locked
E1 hold-out set (data/splits/e1_holdout.csv).

All E1 URLs are Benign (y = 0); any positive prediction is a False Positive.
Computes FPR and 95% Wilson confidence intervals across all required slices:
  1. Overall hold-out
  2. Rank band (1-1k, 1k-10k, 10k-100k, other)
  3. Source (homepage_link, sitemap, login_page)
  4. Has query (True / False)
  5. Path length quartile (Q1, Q2, Q3, Q4)
  6. Login-like (True / False)

Outputs:
  data/reports/e1_fpr_evaluation.json
  data/reports/e1_fpr_evaluation.md
  ml/report/e1_fpr_evaluation.json
  ml/report/e1_fpr_evaluation.md

Usage:
    python -m ml.evaluate_e1 [--holdout data/splits/e1_holdout.csv]
                             [--model ml/models/best_model.joblib]
                             [--threshold 0.5]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("PHISHGUARD_ENV", "development")

from ml.features import extract_vector  # noqa: E402

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

LOGIN_KEYWORDS = (
    "login", "signin", "sign-in", "log-in", "account",
    "auth", "portal", "session", "myaccount", "my-account",
    "user/login", "admin/login", "oauth", "sso"
)


# ---------------------------------------------------------------------------
# Wilson confidence interval
# ---------------------------------------------------------------------------

def wilson_interval(errors: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    """95% Wilson score confidence interval for a binomial proportion."""
    if total <= 0:
        return 0.0, 0.0
    if errors <= 0:
        z2 = z * z
        denom = 1.0 + z2 / total
        high = (z2 / total) / denom
        return 0.0, float(min(1.0, high))
    if errors >= total:
        z2 = z * z
        denom = 1.0 + z2 / total
        low = 1.0 / denom
        return float(max(0.0, low)), 1.0

    p = errors / total
    z2 = z * z
    denom = 1.0 + z2 / total
    centre = (p + z2 / (2.0 * total)) / denom
    margin = (z / denom) * np.sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total))
    return float(max(0.0, centre - margin)), float(min(1.0, centre + margin))


def is_login_like(url: str) -> bool:
    """Return True if path or query has login/account keywords."""
    p = urllib.parse.urlparse(url)
    path = p.path.lower()
    query = p.query.lower()
    return any(k in path or k in query for k in LOGIN_KEYWORDS)


# ---------------------------------------------------------------------------
# Slice definition helper
# ---------------------------------------------------------------------------

def compute_slice_metrics(
    mask: np.ndarray,
    y_pred: np.ndarray,
    category: str,
    value: str,
) -> dict:
    """Compute count, false positives, FPR, and 95% Wilson interval for a slice."""
    sub_pred = y_pred[mask]
    n = int(len(sub_pred))
    fp = int(np.sum(sub_pred == 1))
    fpr = float(fp / n) if n > 0 else 0.0
    ci_low, ci_high = wilson_interval(fp, n)

    return {
        "slice_category": category,
        "slice_value": value,
        "n": n,
        "false_positives": fp,
        "fpr": round(fpr, 6),
        "fpr_percent": round(fpr * 100, 4),
        "wilson_95_ci": [round(ci_low, 6), round(ci_high, 6)],
        "wilson_95_ci_percent": [round(ci_low * 100, 2), round(ci_high * 100, 2)],
        "wilson_ci_str": f"[{ci_low * 100:.2f}%, {ci_high * 100:.2f}%]",
    }


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------

def evaluate_e1_slices(
    holdout_path: pathlib.Path,
    model_path: pathlib.Path,
    threshold: float = 0.5,
    root: Optional[pathlib.Path] = None,
) -> dict:
    if root is None:
        root = ROOT

    if not holdout_path.exists():
        raise FileNotFoundError(
            f"E1 hold-out CSV not found at {holdout_path}. "
            "Build dataset with --e1 first."
        )

    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found at {model_path}. Train model first (ml/train.py)."
        )

    LOGGER.info("Loading E1 hold-out from %s ...", holdout_path)
    df = pd.read_csv(holdout_path, dtype=str, keep_default_na=False)
    if "URL" not in df.columns:
        raise ValueError(f"{holdout_path} missing 'URL' column")

    urls = df["URL"].tolist()
    total_urls = len(urls)
    LOGGER.info("Extracting features for %d E1 hold-out URLs ...", total_urls)
    X = np.array([extract_vector(u) for u in urls], dtype=np.float64)

    LOGGER.info("Loading model from %s ...", model_path)
    model = joblib.load(model_path)

    # Predict probabilities if available, else predict
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[:, 1]
        y_pred = (probs >= threshold).astype(int)
    else:
        probs = None
        y_pred = model.predict(X).astype(int)

    # ---- Derive slicing attributes ----
    # 1. Rank band
    rank_bands = []
    for r_str in df.get("rank", pd.Series([""] * total_urls)):
        try:
            r = int(str(r_str).strip())
            if 1 <= r <= 1000:
                rank_bands.append("1-1k")
            elif 1001 <= r <= 10000:
                rank_bands.append("1k-10k")
            elif 10001 <= r <= 100000:
                rank_bands.append("10k-100k")
            else:
                rank_bands.append(">100k")
        except (ValueError, TypeError):
            rank_bands.append("unknown")

    # 2. Source
    sources = df.get("source", pd.Series(["unknown"] * total_urls)).fillna("unknown").tolist()
    sources = [s if s.strip() else "unknown" for s in sources]

    # 3. Has query
    has_query_list = []
    path_lengths = []
    login_like_list = []

    for u in urls:
        p = urllib.parse.urlparse(u)
        has_query_list.append(bool(p.query))
        path_lengths.append(len(p.path))
        login_like_list.append(is_login_like(u))

    # 4. Path length quartiles
    pl_arr = np.array(path_lengths)
    q25, q50, q75 = np.percentile(pl_arr, [25, 50, 75])
    q_labels = []
    for pl in path_lengths:
        if pl <= q25:
            q_labels.append(f"Q1 (<={int(q25)} chars)")
        elif pl <= q50:
            q_labels.append(f"Q2 ({int(q25)+1}-{int(q50)} chars)")
        elif pl <= q75:
            q_labels.append(f"Q3 ({int(q50)+1}-{int(q75)} chars)")
        else:
            q_labels.append(f"Q4 (>{int(q75)} chars)")

    # ---- Build slice metrics ----
    slices: List[dict] = []

    # Overall
    overall_mask = np.ones(total_urls, dtype=bool)
    overall = compute_slice_metrics(overall_mask, y_pred, "overall", "all_e1_holdout")
    slices.append(overall)

    # Rank bands
    rank_series = pd.Series(rank_bands)
    for band_val in ("1-1k", "1k-10k", "10k-100k", ">100k", "unknown"):
        mask = (rank_series == band_val).values
        if mask.any():
            slices.append(compute_slice_metrics(mask, y_pred, "rank_band", band_val))

    # Source
    src_series = pd.Series(sources)
    for src_val in sorted(set(sources)):
        mask = (src_series == src_val).values
        slices.append(compute_slice_metrics(mask, y_pred, "source", src_val))

    # Has query
    hq_arr = np.array(has_query_list)
    slices.append(compute_slice_metrics(hq_arr, y_pred, "has_query", "has_query=True"))
    slices.append(compute_slice_metrics(~hq_arr, y_pred, "has_query", "has_query=False"))

    # Path length quartiles
    ql_series = pd.Series(q_labels)
    for q_val in sorted(set(q_labels)):
        mask = (ql_series == q_val).values
        slices.append(compute_slice_metrics(mask, y_pred, "path_length_quartile", q_val))

    # Login-like
    ll_arr = np.array(login_like_list)
    slices.append(compute_slice_metrics(ll_arr, y_pred, "login_like", "login_like=True"))
    slices.append(compute_slice_metrics(~ll_arr, y_pred, "login_like", "login_like=False"))

    # Acceptance check (G-3: FPR <= 0.5% point estimate, 95% Wilson interval reported)
    g3_pass = overall["fpr"] <= 0.005
    ci_pass = overall["wilson_95_ci"][1] <= 0.005

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "holdout_file": str(holdout_path),
        "model_file": str(model_path),
        "decision_threshold": threshold,
        "total_holdout_urls": total_urls,
        "overall": overall,
        "gate_g3": {
            "name": "G-3 Block FPR",
            "rule": "FPR <= 0.5% on E1 hold-out with allowlist off (95% Wilson interval reported)",
            "empirical_fpr": overall["fpr"],
            "empirical_fpr_percent": overall["fpr_percent"],
            "wilson_95_ci": overall["wilson_95_ci"],
            "wilson_95_ci_percent": overall["wilson_95_ci_percent"],
            "empirical_fpr_pass": g3_pass,
            "ci_upper_bound_pass": ci_pass,
            "status": "PASS" if g3_pass else "FAIL",
        },
        "slices": slices,
    }

    # Write JSON and Markdown reports
    _write_reports(report, root)
    return report


def _write_reports(report: dict, root: pathlib.Path) -> None:
    rep_dirs = [
        root / "data" / "reports",
        root / "ml" / "report",
    ]

    for d in rep_dirs:
        d.mkdir(parents=True, exist_ok=True)
        json_path = d / "e1_fpr_evaluation.json"
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        md_path = d / "e1_fpr_evaluation.md"
        _write_markdown(report, md_path)

    LOGGER.info("Saved E1 FPR evaluation reports to data/reports/ and ml/report/")


def _write_markdown(rep: dict, path: pathlib.Path) -> None:
    ov = rep["overall"]
    g3 = rep["gate_g3"]
    g3_status = "✅ PASS" if g3["status"] == "PASS" else "❌ FAIL"

    lines = [
        "# PhishGuard — E1 Benign FPR Slice Evaluation Report",
        "",
        f"Generated: {rep['generated_at_utc']}",
        "",
        "## Summary",
        "",
        f"- **Hold-out File:** `{rep['holdout_file']}`",
        f"- **Model Evaluated:** `{rep['model_file']}`",
        f"- **Decision Threshold:** {rep['decision_threshold']}",
        f"- **Total E1 Hold-out URLs:** {rep['total_holdout_urls']:,}",
        f"- **False Positives:** {ov['false_positives']} / {ov['n']}",
        f"- **Overall FPR:** {ov['fpr_percent']:.2f}%",
        f"- **95% Wilson Confidence Interval:** {ov['wilson_ci_str']}",
        f"- **Gate G-3 Status:** {g3_status} (threshold ≤ 0.50%)",
        "",
        "---",
        "",
        "## Slices Evaluation",
        "",
        "All E1 rows are Benign; every positive model prediction is a false positive.",
        "",
        "| Slice Category | Slice | Count (n) | False Positives (k) | FPR (%) | 95% Wilson CI |",
        "|----------------|-------|----------:|--------------------:|--------:|:-------------:|",
    ]

    for sl in rep["slices"]:
        lines.append(
            f"| `{sl['slice_category']}` | `{sl['slice_value']}` | {sl['n']:,} | "
            f"{sl['false_positives']:,} | {sl['fpr_percent']:.2f}% | {sl['wilson_ci_str']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Gate G-3 Verdict",
        "",
        f"- **Empirical FPR Pass (≤ 0.5%):** {'✅ Yes' if g3['empirical_fpr_pass'] else '❌ No'}",
        f"- **CI Upper Bound Pass (≤ 0.5%):** {'✅ Yes' if g3['ci_upper_bound_pass'] else '❌ No'}",
    ]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate E1 benign FPR per slice.")
    parser.add_argument(
        "--holdout",
        default=str(ROOT / "data" / "splits" / "e1_holdout.csv"),
        help="Path to E1 holdout CSV. Default: data/splits/e1_holdout.csv",
    )
    parser.add_argument(
        "--model",
        default=str(ROOT / "ml" / "models" / "best_model.joblib"),
        help="Path to trained model. Default: ml/models/best_model.joblib",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Binary decision threshold. Default: 0.5",
    )
    parser.add_argument(
        "--root",
        default=str(ROOT),
        help="PhishGuard repository root.",
    )
    args = parser.parse_args()

    holdout = pathlib.Path(args.holdout)
    if not holdout.exists():
        print(f"E1 hold-out set not found at {holdout}. Run collection and dataset build first.")
        sys.exit(0)

    rep = evaluate_e1_slices(
        holdout_path=holdout,
        model_path=pathlib.Path(args.model),
        threshold=args.threshold,
        root=pathlib.Path(args.root),
    )
    print(json.dumps({
        "overall_fpr_percent": rep["overall"]["fpr_percent"],
        "wilson_95_ci": rep["overall"]["wilson_ci_str"],
        "g3_status": rep["gate_g3"]["status"],
        "slices_evaluated": len(rep["slices"]),
    }, indent=2))


if __name__ == "__main__":
    main()
