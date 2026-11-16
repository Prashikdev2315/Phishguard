#!/usr/bin/env python3
"""Export the trained PhishGuard model to the compact ``PGM1`` wire format.

The payload is a versioned JSON header followed by zlib-compressed typed
arrays.  Random-forest trees are stored as compact node arrays so the browser
runtime does not need Python or pickle.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import struct
import sys
import warnings
import zlib
from datetime import datetime, timezone
from typing import Optional, Tuple

import joblib
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("PHISHGUARD_ENV", "development")

import ml.train as train  # noqa: E402
from ml.evaluate import _oof_predictions, fit_calibrator  # noqa: E402

MAGIC = b"PGM1"
FORMAT_VERSION = 1
MODEL_VERSION = "pg-model-1.0.0"
HEADER = struct.Struct("<4sBI")
U32 = struct.Struct("<I")
U16 = struct.Struct("<H")


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_model(path: pathlib.Path):
    """Load an oracle, retraining when an old sklearn pickle is incompatible."""
    import __main__

    __main__._RFImportanceSelector = train._RFImportanceSelector
    __main__._L1Selector = train._L1Selector
    try:
        return joblib.load(path)
    except (AttributeError, ModuleNotFoundError) as exc:
        if "monotonic_cst" not in str(exc) and "RFImportanceSelector" not in str(exc):
            raise
        raise RuntimeError(
            "The joblib oracle needs the original pinned scikit-learn environment; "
            "run `python -m ml.train` with requirements.lock before exporting."
        ) from exc


def _append_array(payload: bytearray, values: np.ndarray) -> Tuple[int, int]:
    array = np.ascontiguousarray(values)
    offset = len(payload)
    raw = array.tobytes(order="C")
    payload.extend(raw)
    return offset, len(raw)


def _forest_payload(classifier) -> Tuple[bytes, dict]:
    """Encode RF trees as int32 child links, int16 features, and float32 values."""
    raw = bytearray()
    trees = []
    for estimator in classifier.estimators_:
        tree = estimator.tree_
        node_count = int(tree.node_count)
        children_left = np.asarray(tree.children_left, dtype="<i4")
        children_right = np.asarray(tree.children_right, dtype="<i4")
        features = np.asarray(tree.feature, dtype="<i2")
        thresholds = np.asarray(tree.threshold, dtype="<f4")
        values = np.asarray(tree.value[:, 0, 1], dtype="<f4")
        class_totals = np.asarray(tree.value[:, 0, :].sum(axis=1), dtype="<f4")
        with np.errstate(divide="ignore", invalid="ignore"):
            probabilities = np.divide(values, class_totals, out=np.zeros_like(values), where=class_totals > 0)
        start = len(raw)
        raw.extend(U32.pack(node_count))
        _append_array(raw, children_left)
        _append_array(raw, children_right)
        _append_array(raw, features)
        _append_array(raw, thresholds)
        _append_array(raw, probabilities)
        trees.append({"offset": start, "node_count": node_count})
    return bytes(raw), {"tree_count": len(trees), "trees": trees}


def _calibration_metadata(root: pathlib.Path, X_train, y_train, groups_train, manifest: dict) -> dict:
    """Fit the same OOF calibrator used by Chunk 6 and serialize its parameters."""
    raw_y, raw_prob = _oof_predictions(
        X_train, y_train, groups_train,
        manifest["selector"], manifest["classifier"], int(manifest["k"]),
    )
    calibration = fit_calibrator(raw_prob, raw_y)
    calibrator = calibration["calibrator"]
    if calibration["method"] == "isotonic":
        return {
            "method": "isotonic",
            "x_thresholds": [float(x) for x in calibrator.X_thresholds_],
            "y_thresholds": [float(y) for y in calibrator.y_thresholds_],
            "ece": float(calibration["selected_ece"]),
        }
    return {
        "method": "platt",
        "coef": float(calibrator.coef_[0, 0]),
        "intercept": float(calibrator.intercept_[0]),
        "ece": float(calibration["selected_ece"]),
    }


def export_model(
    root: pathlib.Path = ROOT,
    *,
    model_path: Optional[pathlib.Path] = None,
    output_path: Optional[pathlib.Path] = None,
) -> dict:
    """Export the locked finalist and write its integrity manifest."""
    model_path = model_path or root / "ml" / "models" / "best_model.joblib"
    output_path = output_path or root / "extension" / "public" / "model.bin"
    manifest_path = root / "ml" / "models" / "model.manifest.json"
    train_path = root / "data" / "splits" / "train.csv"
    if not all(path.exists() for path in (model_path, manifest_path, train_path)):
        raise FileNotFoundError("Chunk 5 model, manifest, and training split are required")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["schema"] != train.SCHEMA:
        raise ValueError(f"Unsupported schema: {manifest['schema']}")
    model = _load_model(model_path)
    X_train, y_train, groups_train = train.load_split(train_path, cache_dir=root / "data" / "processed")
    scaler = model.named_steps["scaler"]
    selector = model.named_steps["selector"]
    classifier = model.named_steps["classifier"]
    if manifest["classifier"] != "rf" or not hasattr(classifier, "estimators_"):
        raise ValueError("Chunk 7 currently exports the trained RandomForest finalist only")

    selected_indices = np.flatnonzero(selector.get_support()).astype("<u2")
    forest_bytes, forest_info = _forest_payload(classifier)
    payload = bytearray()
    scaler_offset, scaler_min_bytes = _append_array(payload, np.asarray(scaler.min_, dtype="<f4"))
    _, scaler_scale_bytes = _append_array(payload, np.asarray(scaler.scale_, dtype="<f4"))
    selected_offset, selected_bytes = _append_array(payload, selected_indices)
    forest_offset = len(payload)
    payload.extend(forest_bytes)
    compressed_payload = zlib.compress(bytes(payload), level=9)
    calibration = _calibration_metadata(root, X_train, y_train, groups_train, manifest)
    thresholds = json.loads((root / "thresholds.json").read_text(encoding="utf-8"))
    header = {
        "format_version": FORMAT_VERSION,
        "schema": manifest["schema"],
        "model_version": MODEL_VERSION,
        "feature_count": int(manifest["feature_count"]),
        "sample_count": int(len(y_train)),
        "k": int(manifest["k"]),
        "selector": manifest["selector"],
        "classifier": "rf",
        "compression": "zlib",
        "payload_uncompressed_bytes": len(payload),
        "payload_compressed_bytes": len(compressed_payload),
        "sections": {
            "scaler_min": {"offset": scaler_offset, "bytes": scaler_min_bytes, "dtype": "float32"},
            "scaler_scale": {"offset": scaler_offset + scaler_min_bytes, "bytes": scaler_scale_bytes, "dtype": "float32"},
            "selected_indices": {"offset": selected_offset, "bytes": selected_bytes, "dtype": "uint16"},
            "forest": {"offset": forest_offset, "bytes": len(forest_bytes), **forest_info},
        },
        "calibration": calibration,
        "thresholds": thresholds,
        "oracle": str(model_path.relative_to(root)),
        "source_model_sha256": _sha256(model_path),
    }
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    artifact = HEADER.pack(MAGIC, FORMAT_VERSION, len(header_bytes)) + header_bytes + compressed_payload
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(artifact)
    exported_sha256 = _sha256(output_path)
    export_manifest = dict(manifest)
    export_manifest.update({
        "model_version": MODEL_VERSION,
        "binary_file": str(output_path.relative_to(root)),
        "binary_sha256": exported_sha256,
        "binary_size_bytes": len(artifact),
        "binary_format": "PGM1",
        "calibration": calibration,
        "thresholds": thresholds,
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    manifest_path.write_text(json.dumps(export_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if len(artifact) >= 2 * 1024 * 1024:
        raise ValueError(f"Exported model is {len(artifact)} bytes; target is under 2 MiB")
    return export_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Export PhishGuard model.bin.")
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--model", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    result = export_model(
        pathlib.Path(args.root),
        model_path=pathlib.Path(args.model) if args.model else None,
        output_path=pathlib.Path(args.output) if args.output else None,
    )
    print(json.dumps({
        "binary_file": result["binary_file"],
        "binary_sha256": result["binary_sha256"],
        "binary_size_bytes": result["binary_size_bytes"],
        "model_version": result["model_version"],
    }, indent=2))


if __name__ == "__main__":
    main()
