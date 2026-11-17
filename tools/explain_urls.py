#!/usr/bin/env python3
"""URL Risk and Feature Contribution Explainer (tools/explain_urls.py).

Prints normalized form, calibrated risk, risk band, reason codes,
and the top 10 contributing features along the Random Forest decision path.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Dict, List, Sequence, Tuple

import numpy as np

# Ensure repository root is on sys.path
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.export import _load_joblib
from ml.features import extract_features, extract_vector, FEATURE_NAMES
from ml.normalize import normalize, NormalizeResult


def get_reason_codes(
    risk: int,
    features: Dict[str, float],
    norm: NormalizeResult,
    percentile_url: float = 58.0,
    percentile_host_entropy: float = 3.32,
) -> List[str]:
    reasons: List[str] = []
    if features.get("has_ip_host", 0) == 1:
        reasons.append("R-01")
    if features.get("brand_in_subdomain_or_path", 0) == 1 and norm.registrable_domain is not None:
        reasons.append("R-02")
    if features.get("sensitive_word_count", 0) >= 2:
        reasons.append("R-03")
    if features.get("url_length", 0) >= percentile_url:
        reasons.append("R-04")
    if features.get("subdomain_count", 0) >= 4 or features.get("longest_subdomain_label", 0) >= 25:
        reasons.append("R-05")
    if features.get("suspicious_tld", 0) == 1:
        reasons.append("R-06")
    if features.get("is_punycode", 0) == 1 or features.get("mixed_script_host", 0) == 1:
        reasons.append("R-07")
    if features.get("is_free_hosting", 0) == 1:
        reasons.append("R-08")
    if features.get("at_symbol_count", 0) > 0 or features.get("embedded_url_in_path_or_query", 0) == 1:
        reasons.append("R-09")
    if norm.scheme == "http" and features.get("sensitive_word_count", 0) >= 1:
        reasons.append("R-10")
    if features.get("host_entropy", 0) >= percentile_host_entropy:
        reasons.append("R-11")
    if risk >= 35 and len(reasons) == 0:
        reasons.append("R-00")
    return reasons[:3]


def get_band(risk: int) -> str:
    if risk < 35:
        return "Safe"
    elif risk < 70:
        return "Suspicious"
    else:
        return "High-Risk"


def explain_url(
    url: str,
    model,
    calibration: dict,
) -> dict:
    norm = normalize(url)
    feat_dict = extract_features(url)
    vec = np.asarray([feat_dict[name] for name in FEATURE_NAMES], dtype=np.float64).reshape(1, -1)

    scaler = model.named_steps["scaler"]
    selector = model.named_steps["selector"]
    clf = model.named_steps["classifier"]

    selected_indices = np.flatnonzero(selector.get_support())
    selected_feature_names = [FEATURE_NAMES[i] for i in selected_indices]

    X_scaled = scaler.transform(vec)
    X_sel = selector.transform(X_scaled)

    raw_prob = float(clf.predict_proba(X_sel)[0, 1])

    # Calibrate probability to risk
    if calibration.get("method") == "isotonic":
        x_thresh = np.asarray(calibration["x_thresholds"], dtype=float)
        y_thresh = np.asarray(calibration["y_thresholds"], dtype=float)
        cal_prob = float(np.interp(raw_prob, x_thresh, y_thresh))
    else:
        cal_prob = raw_prob
    cal_prob = max(0.0, min(1.0, cal_prob))
    risk = int(round(100.0 * cal_prob))
    band = get_band(risk)
    reasons = get_reason_codes(risk, feat_dict, norm)

    # Compute tree contributions along decision paths
    n_estimators = len(clf.estimators_)
    contributions = np.zeros(len(selected_indices), dtype=np.float64)
    base_prob = 0.0

    for tree in clf.estimators_:
        indicator = tree.decision_path(X_sel)
        nodes = indicator.indices
        node_values = tree.tree_.value[nodes, 0]
        node_probs = node_values[:, 1] / node_values.sum(axis=1)
        base_prob += node_probs[0]
        for i in range(len(nodes) - 1):
            feat = tree.tree_.feature[nodes[i]]
            delta = node_probs[i + 1] - node_probs[i]
            contributions[feat] += delta

    base_prob /= n_estimators
    contributions /= n_estimators

    # Top 10 largest-contributing features (by absolute contribution magnitude)
    top_indices = np.argsort(-np.abs(contributions))[:10]
    top_features = []
    for idx in top_indices:
        fname = selected_feature_names[idx]
        orig_idx = selected_indices[idx]
        val = float(vec[0, orig_idx])
        contrib = float(contributions[idx])
        top_features.append({
            "feature": fname,
            "value": val,
            "contribution": contrib,
        })

    return {
        "url": url,
        "normalized": norm.normalized,
        "raw_prob": raw_prob,
        "calibrated_prob": cal_prob,
        "risk": risk,
        "band": band,
        "reasons": reasons,
        "base_prob": base_prob,
        "top_features": top_features,
    }


def main():
    parser = argparse.ArgumentParser(description="Explain URL predictions and feature contributions.")
    parser.add_argument("urls", nargs="*", help="URLs to explain. Defaults to YouTube and Flipkart diagnostic set.")
    parser.add_argument("--model", default=str(ROOT / "ml" / "models" / "best_model.joblib"), help="Path to joblib model.")
    parser.add_argument("--manifest", default=str(ROOT / "ml" / "models" / "model.manifest.json"), help="Path to model manifest.")
    args = parser.parse_args()

    default_urls = [
        "youtube.com",
        "youtube.com/",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "flipkart.com",
        "flipkart.com/",
        "https://www.flipkart.com/apple-iphone-13-starlight-128-gb/p/itm6b840f862804f",
    ]
    urls = args.urls if args.urls else default_urls

    model = _load_joblib(pathlib.Path(args.model))
    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    calibration = manifest.get("calibration", {})

    print("=" * 80)
    print("PHISHGUARD URL EXPLANATION & FEATURE CONTRIBUTIONS")
    print("=" * 80)

    for url in urls:
        res = explain_url(url, model, calibration)
        print(f"\nURL: {res['url']}")
        print(f"  Normalized:  {res['normalized']}")
        print(f"  Risk:        {res['risk']}/100  (Raw Prob: {res['raw_prob']:.4f}, Calibrated Prob: {res['calibrated_prob']:.4f})")
        print(f"  Band:        {res['band']}")
        print(f"  Reasons:     {res['reasons']}")
        print(f"  Base Prob:   {res['base_prob']:.4f}")
        print("  Top 10 Feature Contributions (relative to base):")
        for i, item in enumerate(res["top_features"], 1):
            sign = "+" if item["contribution"] >= 0 else ""
            print(f"    {i:2d}. {item['feature']:<30s} = {item['value']:<10.4f} (contrib: {sign}{item['contribution']:.4f})")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
