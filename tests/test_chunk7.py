import hashlib
import json
import zlib
from pathlib import Path

from ml.export import HEADER, MAGIC, FORMAT_VERSION


def _read_model(path: Path):
    data = path.read_bytes()
    magic, version, header_length = HEADER.unpack_from(data)
    start = HEADER.size
    header = json.loads(data[start:start + header_length])
    payload = zlib.decompress(data[start + header_length:])
    return data, magic, version, header, payload


def test_exported_model_has_frozen_header_and_integrity():
    path = Path("extension/public/model.bin")
    data, magic, version, header, payload = _read_model(path)

    assert magic == MAGIC
    assert version == FORMAT_VERSION
    assert header["schema"] == "fs1"
    assert header["classifier"] == "rf"
    assert header["feature_count"] == 50
    assert header["sections"]["forest"]["tree_count"] == 200
    assert len(payload) == header["payload_uncompressed_bytes"]
    assert len(data) < 2 * 1024 * 1024
    assert hashlib.sha256(data).hexdigest() == json.loads(
        Path("ml/models/model.manifest.json").read_text(encoding="utf-8")
    )["binary_sha256"]
