"""Chunk 8 parity gate smoke checks.

The exhaustive URL-by-URL bridge is intentionally kept as a separate
validation command because it requires the Node toolchain. This test verifies
that the TypeScript build, PGM1 artifact, and Vitest parity suite are wired
into the repository test workflow.
"""
from pathlib import Path
import os
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def test_typescript_parity_gate_builds_and_runs():
    assert (ROOT / "extension" / "src" / "lib" / "model.ts").exists()
    assert (ROOT / "extension" / "public" / "model.bin").stat().st_size < 2 * 1024 * 1024
    npm = "npm.cmd" if os.name == "nt" else "npm"
    subprocess.run([npm, "run", "typecheck"], cwd=ROOT, check=True)
    subprocess.run([npm, "test", "--", "--run"], cwd=ROOT, check=True)
