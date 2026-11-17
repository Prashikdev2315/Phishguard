#!/usr/bin/env python3
"""Export and read the pickle-free PGM1 RandomForest wire format."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zlib
from typing import Dict, Iterable, List, Tuple

import joblib
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAGIC = b"PGM1"
FORMAT_VERSION = 1
MODEL_VERSION = "pg-model-1.0.0"
HEADER_STRUCT = struct.Struct("<4sBI")
TREE_HEADER = struct.Struct("<I")


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_joblib(path: pathlib.Path):
    """Load models produced by ``python ml/train.py`` and its __main__ class."""
    import ml.train as train_module

    setattr(sys.modules["__main__"], "_RFImportanceSelector", train_module._RFImportanceSelector)
    model = joblib.load(path)
    classifier = model.named_steps.get("classifier")
    for estimator in getattr(classifier, "estimators_", ()):
        if not hasattr(estimator, "monotonic_cst"):
            estimator.monotonic_cst = None
    return model


def _tree_bytes(tree) -> bytes:
    structure = tree.tree_
    node_count = int(structure.node_count)
    left = np.asarray(structure.children_left, dtype="<i4")
    right = np.asarray(structure.children_right, dtype="<i4")
    feature = np.asarray(structure.feature, dtype="<i2")
    t_f64 = np.asarray(structure.threshold, dtype=np.float64)
    t_f32 = np.asarray(t_f64, dtype=np.float32)
    round_up = t_f32.astype(np.float64) > t_f64
    t_f32[round_up] = np.nextafter(t_f32[round_up], np.float32(-np.inf))
    threshold = np.asarray(t_f32, dtype="<f4")
    values = np.asarray(structure.value, dtype=np.float64)
    totals = values.sum(axis=2)
    probabilities = np.divide(
        values[:, 0, 1],
        totals[:, 0],
        out=np.zeros(node_count, dtype=np.float64),
        where=totals[:, 0] != 0,
    ).astype("<f4")
    return b"".join(
        (
            TREE_HEADER.pack(node_count),
            left.tobytes(),
            right.tobytes(),
            feature.tobytes(),
            threshold.tobytes(),
            probabilities.tobytes(),
        )
    )


def _forest_bytes(classifier) -> bytes:
    if len(classifier.estimators_) != 200:
        raise ValueError(f"Expected 200 forest estimators, found {len(classifier.estimators_)}")
    return b"".join(_tree_bytes(tree) for tree in classifier.estimators_)


def _calibration_metadata(root: pathlib.Path, manifest: dict, model) -> dict:
    from ml.evaluate import fit_calibrator, _oof_predictions_by_seed
    from ml.train import load_split

    train_path = root / "data" / "splits" / "train.csv"
    X_train, y_train, groups = load_split(train_path, cache_dir=root / "data" / "processed")
    per_seed = _oof_predictions_by_seed(
        X_train,
        y_train,
        groups,
        manifest["selector"],
        manifest["classifier"],
        int(manifest["k"]),
    )
    calibration = fit_calibrator(
        np.mean([item[2] for item in per_seed], axis=0),
        y_train,
    )
    calibrator = calibration["calibrator"]
    result = {
        "method": calibration["method"],
        "ece": float(calibration["selected_ece"]),
        "sample_count": int(calibration["sample_count"]),
    }
    if calibration["method"] == "isotonic":
        result["x_thresholds"] = [float(value) for value in calibrator.X_thresholds_]
        result["y_thresholds"] = [float(value) for value in calibrator.y_thresholds_]
    else:
        result["coefficient"] = float(calibrator.coef_[0, 0])
        result["intercept"] = float(calibrator.intercept_[0])
    return result


def _header_and_payload(model, root: pathlib.Path, model_path: pathlib.Path) -> Tuple[dict, bytes]:
    manifest_path = root / "ml" / "models" / "model.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pipeline = model
    scaler = pipeline.named_steps["scaler"]
    selector = pipeline.named_steps["selector"]
    classifier = pipeline.named_steps["classifier"]
    selected_indices = np.flatnonzero(selector.get_support()).astype("<u2")
    if selected_indices.size != 20:
        raise ValueError(f"Expected 20 selected features, found {selected_indices.size}")
    if len(scaler.min_) != 50 or len(scaler.scale_) != 50:
        raise ValueError("The exporter requires the frozen fs1 50-feature schema")

    scaler_min = np.asarray(scaler.min_, dtype="<f8").tobytes()
    scaler_scale = np.asarray(scaler.scale_, dtype="<f8").tobytes()
    selected = selected_indices.tobytes()
    forest = _forest_bytes(classifier)
    sections = {}
    offset = 0
    for name, data in (
        ("scaler_min", scaler_min),
        ("scaler_scale", scaler_scale),
        ("selected_indices", selected),
        ("forest", forest),
    ):
        sections[name] = {"offset": offset, "length": len(data)}
        offset += len(data)
    payload = b"".join((scaler_min, scaler_scale, selected, forest))
    compressed = zlib.compress(payload, level=9)
    thresholds = json.loads((root / "thresholds.json").read_text(encoding="utf-8"))
    header = {
        "schema": "fs1",
        "model_version": MODEL_VERSION,
        "feature_count": 50,
        "sample_count": 7781,
        "k": 20,
        "selector": "rf_importance",
        "classifier": "rf",
        "compression": "zlib",
        "payload_uncompressed_bytes": len(payload),
        "payload_compressed_bytes": len(compressed),
        "sections": sections,
        "calibration": _calibration_metadata(root, manifest, model),
        "thresholds": {
            "T_block": thresholds["T_block"],
            "T_warn": thresholds["T_warn"],
            "bands": {
                "safe_max": thresholds["T_safe_max"],
                "suspicious_min": thresholds["T_suspicious_min"],
                "suspicious_max": thresholds["T_suspicious_max"],
                "high_risk_min": thresholds["T_high_risk_min"],
            },
        },
        "oracle": "ml/models/best_model.joblib",
        "source_model_sha256": _sha256(model_path),
    }
    return header, compressed


def export_model(root, model_path, output_path) -> dict:
    """Export the finalist pipeline to the deterministic PGM1 binary format."""
    root = pathlib.Path(root).resolve()
    model_path = pathlib.Path(model_path)
    output_path = pathlib.Path(output_path)
    if not model_path.is_absolute():
        model_path = root / model_path
    if not output_path.is_absolute():
        output_path = root / output_path
    model = _load_joblib(model_path)
    header, compressed = _header_and_payload(model, root, model_path)
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(HEADER_STRUCT.pack(MAGIC, FORMAT_VERSION, len(header_bytes)) + header_bytes + compressed)
    if output_path.stat().st_size >= 2 * 1024 * 1024:
        raise ValueError(f"Exported model is too large: {output_path.stat().st_size} bytes")

    manifest_path = root / "ml" / "models" / "model.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(
        {
            "binary_file": str(output_path.relative_to(root)).replace("\\", "/"),
            "binary_sha256": _sha256(output_path),
            "binary_size_bytes": output_path.stat().st_size,
            "binary_format": "PGM1",
            "model_version": MODEL_VERSION,
            "calibration": header["calibration"],
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"header": header, "output": str(output_path), "size_bytes": output_path.stat().st_size}


def _read_array(payload: bytes, section: dict, dtype: str, count: int) -> np.ndarray:
    start = int(section["offset"])
    end = start + int(section["length"])
    array = np.frombuffer(payload[start:end], dtype=dtype, count=count)
    if array.size != count:
        raise ValueError("Truncated PGM1 section")
    return array


def load_exported_model(path: pathlib.Path) -> dict:
    """Parse a PGM1 file into numpy arrays and traversable tree dictionaries."""
    raw = pathlib.Path(path).read_bytes()
    if len(raw) < HEADER_STRUCT.size:
        raise ValueError("Truncated PGM1 header")
    magic, version, header_length = HEADER_STRUCT.unpack_from(raw)
    if magic != MAGIC or version != FORMAT_VERSION:
        raise ValueError("Unsupported PGM1 header")
    header_start = HEADER_STRUCT.size
    header_end = header_start + header_length
    header = json.loads(raw[header_start:header_end].decode("utf-8"))
    compressed = raw[header_end:]
    payload = zlib.decompress(compressed)
    sections = header["sections"]
    scaler_min = _read_array(payload, sections["scaler_min"], "<f8", header["feature_count"])
    scaler_scale = _read_array(payload, sections["scaler_scale"], "<f8", header["feature_count"])
    selected_indices = _read_array(payload, sections["selected_indices"], "<u2", header["k"])
    forest_start = int(sections["forest"]["offset"])
    forest_end = forest_start + int(sections["forest"]["length"])
    cursor = forest_start
    trees = []
    while cursor < forest_end:
        node_count = TREE_HEADER.unpack_from(payload, cursor)[0]
        cursor += TREE_HEADER.size
        sizes = (
            ("children_left", "<i4"),
            ("children_right", "<i4"),
            ("feature", "<i2"),
            ("threshold", "<f4"),
            ("probabilities", "<f4"),
        )
        tree = {"node_count": node_count}
        for name, dtype in sizes:
            width = np.dtype(dtype).itemsize * node_count
            tree[name] = np.frombuffer(payload, dtype=dtype, count=node_count, offset=cursor)
            cursor += width
        trees.append(tree)
    if cursor != forest_end or len(trees) != 200:
        raise ValueError("PGM1 forest section is malformed")
    return {
        "header": header,
        "scaler_min": scaler_min,
        "scaler_scale": scaler_scale,
        "selected_indices": selected_indices,
        "trees": trees,
    }


def predict_exported_model(model_dict: dict, X: np.ndarray) -> np.ndarray:
    """Return malicious probabilities from an unpacked PGM1 model."""
    features = np.asarray(X, dtype=np.float64)
    if features.ndim != 2 or features.shape[1] != model_dict["header"]["feature_count"]:
        raise ValueError("X must have shape (n_samples, 50)")
    scaled = features * model_dict["scaler_scale"] + model_dict["scaler_min"]
    selected = np.asarray(scaled[:, model_dict["selected_indices"]], dtype=np.float32)
    predictions = np.zeros(len(selected), dtype=np.float32)
    for tree in model_dict["trees"]:
        node = np.zeros(len(selected), dtype=np.int32)
        active = np.ones(len(selected), dtype=bool)
        while active.any():
            rows = np.flatnonzero(active)
            current = node[rows]
            leaves = tree["children_left"][current] == tree["children_right"][current]
            if leaves.any():
                active[rows[leaves]] = False
            branches = ~leaves
            if branches.any():
                branch_rows = rows[branches]
                branch_nodes = current[branches]
                feature = tree["feature"][branch_nodes]
                go_left = selected[branch_rows, feature] <= tree["threshold"][branch_nodes]
                node[branch_rows[go_left]] = tree["children_left"][branch_nodes[go_left]]
                node[branch_rows[~go_left]] = tree["children_right"][branch_nodes[~go_left]]
        predictions += tree["probabilities"][node]
    return predictions / len(model_dict["trees"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--model", default="ml/models/best_model.joblib")
    parser.add_argument("--output", default="extension/public/model.bin")
    args = parser.parse_args()
    result = export_model(args.root, args.model, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
