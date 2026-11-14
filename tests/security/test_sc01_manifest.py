"""
SC-01 — Manifest permissions equal the approved list.

PRD §8.1: The final permission list is confirmed in the M0 spike and then
frozen.  SC-01 fails the build if the manifest differs from the approved list.

Approved list (confirmed during Chunk 1 spike):
  permissions        : ["storage", "webNavigation", "alarms"]
  optional_permissions: ["scripting"]
  host_permissions   : []          (no broad host access in the core manifest)
  optional_host_permissions: ["<all_urls>"]

Any deviation — addition OR removal — must be a deliberate PRD change first.
"""

from __future__ import annotations

import json
import pathlib
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]  # phishguard/
MANIFEST = ROOT / "extension" / "manifest.json"

# ── Approved lists (frozen in Chunk 1) ──────────────────────────────────────
APPROVED_PERMISSIONS: set[str] = {"storage", "webNavigation", "alarms"}
APPROVED_OPTIONAL_PERMISSIONS: set[str] = {"scripting"}
APPROVED_HOST_PERMISSIONS: set[str] = set()          # none in core manifest
APPROVED_OPTIONAL_HOST_PERMISSIONS: set[str] = {"<all_urls>"}


@pytest.fixture(scope="module")
def manifest() -> dict:
    assert MANIFEST.exists(), f"manifest.json not found at {MANIFEST}"
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_version(manifest):
    assert manifest.get("manifest_version") == 3, "Must be Manifest V3"


def test_required_permissions(manifest):
    actual = set(manifest.get("permissions", []))
    assert actual == APPROVED_PERMISSIONS, (
        f"permissions mismatch.\n"
        f"  approved : {sorted(APPROVED_PERMISSIONS)}\n"
        f"  actual   : {sorted(actual)}\n"
        f"  added    : {sorted(actual - APPROVED_PERMISSIONS)}\n"
        f"  removed  : {sorted(APPROVED_PERMISSIONS - actual)}"
    )


def test_optional_permissions(manifest):
    actual = set(manifest.get("optional_permissions", []))
    assert actual == APPROVED_OPTIONAL_PERMISSIONS, (
        f"optional_permissions mismatch.\n"
        f"  approved : {sorted(APPROVED_OPTIONAL_PERMISSIONS)}\n"
        f"  actual   : {sorted(actual)}"
    )


def test_host_permissions(manifest):
    actual = set(manifest.get("host_permissions", []))
    assert actual == APPROVED_HOST_PERMISSIONS, (
        f"host_permissions must be empty in the core manifest.\n"
        f"  actual: {sorted(actual)}"
    )


def test_optional_host_permissions(manifest):
    actual = set(manifest.get("optional_host_permissions", []))
    assert actual == APPROVED_OPTIONAL_HOST_PERMISSIONS, (
        f"optional_host_permissions mismatch.\n"
        f"  approved : {sorted(APPROVED_OPTIONAL_HOST_PERMISSIONS)}\n"
        f"  actual   : {sorted(actual)}"
    )


def test_no_remote_code_csp(manifest):
    """SEC-01: CSP must forbid remote code and eval."""
    csp_block = manifest.get("content_security_policy", {})
    ext_pages_csp = csp_block.get("extension_pages", "")
    assert "script-src 'self'" in ext_pages_csp, (
        "CSP must contain \"script-src 'self'\""
    )
    assert "object-src 'self'" in ext_pages_csp, (
        "CSP must contain \"object-src 'self'\""
    )
    assert "base-uri 'self'" in ext_pages_csp, (
        "CSP must contain \"base-uri 'self'\""
    )
    assert "'unsafe-eval'" not in ext_pages_csp, "CSP must not allow eval"
    assert "'unsafe-inline'" not in ext_pages_csp, "CSP must not allow inline scripts"


def test_no_web_accessible_resources(manifest):
    """SEC-03: warning.html must not be web-accessible."""
    war = manifest.get("web_accessible_resources", [])
    assert war == [], (
        f"web_accessible_resources must be empty. Got: {war}"
    )


def test_no_externally_connectable(manifest):
    """SEC-03: no externally_connectable so web pages cannot message the worker."""
    assert "externally_connectable" not in manifest, (
        "externally_connectable must not be present"
    )


def test_minimum_chrome_version(manifest):
    minimum = manifest.get("minimum_chrome_version", "0")
    assert int(minimum) >= 120, (
        f"minimum_chrome_version must be >= 120, got {minimum}"
    )


def test_background_is_service_worker(manifest):
    bg = manifest.get("background", {})
    assert "service_worker" in bg, "background must declare a service_worker"
    assert bg.get("type") == "module", "service_worker type must be 'module'"
