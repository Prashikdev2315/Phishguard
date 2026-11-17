"""Exhaustive Chunk 8 PAR-01/PAR-02 parity gate."""
import json
from pathlib import Path
import os
import subprocess
import tempfile

import numpy as np

from ml.export import _load_joblib
from ml.features import extract_vector
from ml.normalize import normalize


ROOT = Path(__file__).resolve().parents[2]


def test_typescript_parity_gate_builds_and_runs():
    assert (ROOT / "extension" / "src" / "lib" / "model.ts").exists()
    assert (ROOT / "extension" / "public" / "model.bin").stat().st_size < 2 * 1024 * 1024
    npm = "npm.cmd" if os.name == "nt" else "npm"
    subprocess.run([npm, "run", "typecheck"], cwd=ROOT, check=True)
    subprocess.run([npm, "test", "--", "--run"], cwd=ROOT, check=True)
    subprocess.run([npm, "exec", "tsx", "--", "tests/parity/run_ts_parity.ts"], cwd=ROOT, check=True,
                   stdout=(output := tempfile.NamedTemporaryFile(mode="w+b", delete=False)))
    output.close()
    try:
        ts_rows = json.loads(Path(output.name).read_text(encoding="utf-8"))
    finally:
        Path(output.name).unlink(missing_ok=True)

    import pandas as pd
    test_frame = pd.read_csv(ROOT / "data/splits/test.csv", dtype=str, keep_default_na=False)
    oracle = _load_joblib(ROOT / "ml/models/best_model.joblib")
    python_vectors = np.asarray([extract_vector(url) for url in test_frame["URL"]], dtype=np.float64)
    transformed = oracle.named_steps["selector"].transform(
        oracle.named_steps["scaler"].transform(python_vectors)
    )
    raw_probabilities = np.zeros(len(transformed), dtype=np.float32)
    for estimator in oracle.named_steps["classifier"].estimators_:
        tree = estimator.tree_
        nodes = np.zeros(len(transformed), dtype=np.int32)
        active = np.ones(len(transformed), dtype=bool)
        while active.any():
            rows = np.flatnonzero(active)
            current = nodes[rows]
            leaves = tree.children_left[current] == tree.children_right[current]
            active[rows[leaves]] = False
            branches = ~leaves
            if branches.any():
                branch_rows = rows[branches]
                branch_nodes = current[branches]
                go_left = transformed[branch_rows, tree.feature[branch_nodes]] <= tree.threshold[branch_nodes]
                nodes[branch_rows[go_left]] = tree.children_left[branch_nodes[go_left]]
                nodes[branch_rows[~go_left]] = tree.children_right[branch_nodes[~go_left]]
        values = tree.value[:, 0, :]
        raw_probabilities += (values[nodes, 1] / values[nodes].sum(axis=1)).astype(np.float32)
    raw_probabilities /= len(oracle.named_steps["classifier"].estimators_)
    import struct
    binary = (ROOT / "extension/public/model.bin").read_bytes()
    header_length = struct.unpack_from("<I", binary, 5)[0]
    model_header = json.loads(binary[9:9 + header_length].decode("utf-8"))
    calibration = model_header["calibration"]
    python_probabilities = np.interp(
        raw_probabilities,
        np.asarray(calibration["x_thresholds"], dtype=float),
        np.asarray(calibration["y_thresholds"], dtype=float),
    )
    python_risks = np.rint(100.0 * python_probabilities).astype(int)
    assert len(ts_rows) == len(test_frame) == 1896
    max_feature_diff = 0.0
    max_risk_diff = 0
    normalization_mismatches = 0
    for index, row in enumerate(ts_rows):
        py_norm = normalize(test_frame.iloc[index]["URL"])
        if row["normalized"] != {
            "raw": py_norm.raw, "error": py_norm.error, "normalized": py_norm.normalized,
            "cache_key": py_norm.cache_key, "display_host": py_norm.display_host,
            "puny_host": py_norm.puny_host, "registrable_domain": py_norm.registrable_domain,
            "public_suffix": py_norm.public_suffix, "scheme": py_norm.scheme, "path": py_norm.path,
            "query": py_norm.query, "fragment": py_norm.fragment, "is_ip_host": py_norm.is_ip_host,
            "is_punycode": py_norm.is_punycode, "decoded_url": py_norm.decoded_url,
            "raw_length": py_norm.raw_length,
        }:
            normalization_mismatches += 1
        max_feature_diff = max(max_feature_diff, float(np.max(np.abs(np.asarray(row["vector"], dtype=np.float32) - python_vectors[index]))))
        max_risk_diff = max(max_risk_diff, abs(int(row["risk"]) - int(python_risks[index])))
    assert normalization_mismatches == 0
    assert max_feature_diff <= 1e-6
    assert max_risk_diff <= 1
