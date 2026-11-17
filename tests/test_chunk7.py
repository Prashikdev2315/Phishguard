import hashlib
import json
import pathlib
import struct

import numpy as np

import ml.train
from ml.export import _load_joblib, load_exported_model, predict_exported_model
from ml.features import extract_vector


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "ml" / "models" / "best_model.joblib"
BINARY_PATH = ROOT / "extension" / "public" / "model.bin"


def test_export_header_and_tree_count():
    raw = BINARY_PATH.read_bytes()
    magic, version, header_length = struct.unpack_from("<4sBI", raw)
    header = json.loads(raw[9 : 9 + header_length].decode("utf-8"))
    assert magic == b"PGM1"
    assert version == 1
    assert header["schema"] == "fs1"
    assert header["feature_count"] == 50
    assert header["k"] == 20
    assert header["payload_compressed_bytes"] == len(raw) - 9 - header_length
    assert len(load_exported_model(BINARY_PATH)["trees"]) == 200


def test_exported_model_is_under_size_limit():
    assert BINARY_PATH.stat().st_size < 2 * 1024 * 1024


def test_export_sha256_matches_manifest():
    manifest = json.loads(
        (ROOT / "ml" / "models" / "model.manifest.json").read_text(encoding="utf-8")
    )
    digest = hashlib.sha256(BINARY_PATH.read_bytes()).hexdigest()
    assert manifest["binary_format"] == "PGM1"
    assert manifest["binary_sha256"] == digest
    assert manifest["binary_size_bytes"] == BINARY_PATH.stat().st_size


def test_exported_predictions_match_joblib_oracle():
    frame = np.asarray(
        [extract_vector(url) for url in [
            "https://example.com/",
            "http://login-secure.example.com/account/verify",
            "https://www.wikipedia.org/",
        ]],
        dtype=float,
    )
    oracle = _load_joblib(MODEL_PATH)
    transformed = oracle.named_steps["selector"].transform(
        oracle.named_steps["scaler"].transform(frame)
    ).astype(np.float32)
    expected = np.zeros(len(frame), dtype=np.float32)
    for estimator in oracle.named_steps["classifier"].estimators_:
        tree = estimator.tree_
        node = np.zeros(len(frame), dtype=np.int32)
        active = np.ones(len(frame), dtype=bool)
        while active.any():
            rows = np.flatnonzero(active)
            current = node[rows]
            leaves = tree.children_left[current] == tree.children_right[current]
            if leaves.any():
                active[rows[leaves]] = False
            branches = ~leaves
            if branches.any():
                branch_rows = rows[branches]
                branch_nodes = current[branches]
                go_left = transformed[branch_rows, tree.feature[branch_nodes]] <= tree.threshold[branch_nodes]
                node[branch_rows[go_left]] = tree.children_left[branch_nodes[go_left]]
                node[branch_rows[~go_left]] = tree.children_right[branch_nodes[~go_left]]
        values = tree.value[:, 0, :]
        expected += (values[node, 1] / values[node].sum(axis=1)).astype(np.float32)
    expected /= len(oracle.named_steps["classifier"].estimators_)
    actual = predict_exported_model(load_exported_model(BINARY_PATH), frame)
    np.testing.assert_allclose(actual, expected, rtol=0, atol=1e-4)
