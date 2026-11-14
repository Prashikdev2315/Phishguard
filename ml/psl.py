"""
ml/psl.py — Public Suffix List reader for PhishGuard (N-11)
============================================================

Primary source  : lists/psl.dat  (pinned snapshot — team must provide this file)
No silent fallback: if lists/psl.dat is absent, get_psl() raises FileNotFoundError.

For unit tests only, use PSL.for_testing() which loads a minimal in-memory PSL
(handles all UT-01 and PSL test-vector cases without requiring psl.dat on disk).

Algorithm
---------
Implements the standard Mozilla PSL matching algorithm:
  https://wiki.mozilla.org/Public_Suffix_List/Algorithm

Three rule types (§ of the PSL spec):
  1. Normal   : "com"       — 'com' is a public suffix
  2. Wildcard : "*.uk"      — every 'X.uk' is a public suffix
  3. Exception: "!www.ck"  — 'www.ck' is NOT a suffix despite matching "*.ck"
                              effective suffix for subdomains of www.ck is 'ck'

For registrable_domain():
  - Find the prevailing rule (longest match; exception > wildcard of equal length).
  - Exception rule: effective suffix = exception minus its leftmost label.
  - Normal/wildcard: effective suffix = the matched rule.
  - Registrable domain = effective_suffix + one label to the left.
  - If the hostname IS the effective suffix → registrable domain is None.

Contract (frozen in CONTRACTS.md, N-11):
  - The same pinned PSL file ships in Python and TypeScript.
  - Private-section entries ARE included so tenant hosts resolve correctly.
  - IP hosts: registrable_domain() returns None (caller detects IPs before calling).
"""

from __future__ import annotations

import pathlib
from typing import FrozenSet, List, Optional, Set, Tuple


# ── Path constant ─────────────────────────────────────────────────────────────

_DEFAULT_PSL = (
    pathlib.Path(__file__).resolve().parent.parent / "lists" / "psl.dat"
)

MIN_PSL_SIZE_BYTES = 100 * 1024  # 100 KB
PRIVATE_DOMAINS_MARKER = "BEGIN PRIVATE DOMAINS"


# ── Minimal PSL used by PSL.for_testing() ─────────────────────────────────────
# Covers UT-01 and official test-vector cases (rules, wildcards, exceptions).
# NEVER used by profile.py or production code.
_MINIMAL_PSL_TEXT = """\
// Minimal PSL for PhishGuard unit tests only.
// Public section
com
net
org
edu
gov
biz
info
uk
co.uk
org.uk
me.uk
za
co.za
org.za
br
com.br
net.br
org.br
jp
ac.jp
*.kyoto.jp
!ide.kyoto.jp
*.kobe.jp
!city.kobe.jp
*.ck
!www.ck
us
ak.us
k12.ak.us
// Private section (BEGIN PRIVATE DOMAINS)
blogspot.com
github.io
pages.dev
workers.dev
netlify.app
vercel.app
weebly.com
wixsite.com
herokuapp.com
firebaseapp.com
web.app
glitch.me
duckdns.org
ngrok.io
000webhostapp.com
"""


# ═══════════════════════════════════════════════════════════════════════════════
# PSL class
# ═══════════════════════════════════════════════════════════════════════════════

class PSL:
    """
    Public Suffix List that finds the registrable domain (eTLD+1).

    Instantiation
    -------------
    # Production — reads lists/psl.dat; raises FileNotFoundError or ValueError
    # if absent, under 100 KB, or missing the private-domains marker:
    psl = PSL()
    psl = PSL(psl_path=pathlib.Path("lists/psl.dat"))

    # Tests only — uses the minimal built-in PSL text:
    psl = PSL.for_testing()
    """

    # ── construction ──────────────────────────────────────────────────────────

    def __init__(self, psl_path: Optional[pathlib.Path] = None, *, _validate: bool = True) -> None:
        if psl_path is None:
            psl_path = _DEFAULT_PSL

        if not psl_path.exists():
            raise FileNotFoundError(
                f"[PhishGuard] lists/psl.dat not found at {psl_path}.\n"
                f"  Add the pinned Mozilla Public Suffix List snapshot to {psl_path}.\n"
                f"  Source: https://publicsuffix.org/list/public_suffix_list.dat\n"
                f"  For unit tests, use PSL.for_testing() instead of PSL()."
            )

        if _validate:
            size = psl_path.stat().st_size
            if size < MIN_PSL_SIZE_BYTES:
                raise ValueError(
                    f"[PhishGuard] lists/psl.dat at {psl_path} is only {size} bytes (< {MIN_PSL_SIZE_BYTES} bytes / 100 KB).\n"
                    f"  The official Mozilla Public Suffix List snapshot is required.\n"
                    f"  Source: https://publicsuffix.org/list/public_suffix_list.dat\n"
                    f"  Place the complete snapshot at: {psl_path}"
                )

        content = psl_path.read_text(encoding="utf-8")
        if _validate and PRIVATE_DOMAINS_MARKER not in content:
            raise ValueError(
                f"[PhishGuard] lists/psl.dat at {psl_path} is missing the required private-domains marker "
                f"('{PRIVATE_DOMAINS_MARKER}').\n"
                f"  The snapshot must include the private domains section so tenant hosts resolve correctly."
            )

        self._source = str(psl_path)
        self._rules:      Set[str] = set()   # normal rules, e.g. "com", "co.uk"
        self._wildcards:  Set[str] = set()   # wildcard parents, e.g. "ck" from "*.ck"
        self._exceptions: Set[str] = set()   # exception targets, e.g. "www.ck" from "!www.ck"
        self._parse(content)

    @classmethod
    def for_testing(cls) -> "PSL":
        """
        Return a PSL loaded from the minimal in-memory text.
        Use ONLY in unit tests of the parser algorithm itself.
        Never used by profile.py.
        """
        obj = object.__new__(cls)
        obj._source     = "minimal-builtin"
        obj._rules      = set()
        obj._wildcards  = set()
        obj._exceptions = set()
        obj._parse(_MINIMAL_PSL_TEXT)
        return obj

    # ── parsing ───────────────────────────────────────────────────────────────

    def _parse(self, text: str) -> None:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            line = line.lower()
            if line.startswith("!"):
                # Exception rule: store the target without '!'
                self._exceptions.add(line[1:])
            elif line.startswith("*."):
                # Wildcard rule: store the parent (strip "*.")
                self._wildcards.add(line[2:])
            else:
                self._rules.add(line)

    # ── public API ────────────────────────────────────────────────────────────

    @property
    def source(self) -> str:
        return self._source

    def registrable_domain(self, hostname: str) -> Optional[str]:
        """
        Return the eTLD+1 (registrable domain) for a hostname, or None.

        Returns None when:
          - hostname is empty
          - hostname has fewer than 2 labels
          - hostname IS a public suffix (or matches a wildcard suffix directly)

        Examples (with private section):
          "www.google.com"      → "google.com"
          "username.github.io"  → "username.github.io"  (github.io is PSL private)
          "www.ck"              → "www.ck"               (exception to *.ck)
          "b.test.ck"           → "b.test.ck"            (test.ck is a suffix via *.ck)
          "www.www.ck"          → "www.ck"               (exception applies)
          "city.kobe.jp"        → "city.kobe.jp"         (exception to *.kobe.jp)
          "192.168.1.1"         → caller should detect IP before calling
        """
        if not hostname:
            return None
        h = hostname.lower().rstrip(".")
        labels = h.split(".")
        n = len(labels)
        if n < 1:
            return None

        # ── 1. Check exception rules (highest priority) ───────────────────────
        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self._exceptions:
                # Effective suffix = candidate minus its leftmost label
                # = labels[i+1:]
                effective_suffix_start = i + 1
                # Registrable = one label before the effective suffix
                reg_start = effective_suffix_start - 1  # == i
                if reg_start < 0 or effective_suffix_start > n:
                    return None
                return ".".join(labels[reg_start:])

        # ── 2. Find longest normal / wildcard suffix ───────────────────────────
        best_suffix_start: Optional[int] = None
        best_len: int = 0

        for i in range(n):
            candidate = ".".join(labels[i:])
            suffix_len = n - i

            # Normal rule
            if candidate in self._rules and suffix_len > best_len:
                best_len = suffix_len
                best_suffix_start = i

            # Wildcard: check if *.labels[i:] is a rule.
            # For this, labels[i:] must be a wildcard parent and there must
            # be at least one label to the left (i > 0), because the wildcard
            # expands to label[i-1].labels[i:] as the suffix.
            if i > 0 and candidate in self._wildcards:
                wildcard_suffix_start = i - 1  # labels[i-1:] is the matched suffix
                wildcard_len = n - wildcard_suffix_start
                if wildcard_len > best_len:
                    best_len = wildcard_len
                    best_suffix_start = wildcard_suffix_start

        # ── 3. Default rule: last label is the TLD ────────────────────────────
        if best_suffix_start is None:
            best_suffix_start = n - 1

        # ── 4. Registrable = one label before the effective suffix ────────────
        reg_start = best_suffix_start - 1
        if reg_start < 0:
            return None   # hostname itself IS a public suffix

        return ".".join(labels[reg_start:])

    def public_suffix(self, hostname: str) -> Optional[str]:
        """Return the eTLD (public suffix) portion of a hostname, or None."""
        if not hostname:
            return None
        h = hostname.lower().rstrip(".")
        labels = h.split(".")
        n = len(labels)

        # Exception rules
        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self._exceptions:
                effective_suffix_start = i + 1
                if effective_suffix_start >= n:
                    return None
                return ".".join(labels[effective_suffix_start:])

        best_suffix_start: Optional[int] = None
        best_len: int = 0

        for i in range(n):
            candidate = ".".join(labels[i:])
            suffix_len = n - i

            if candidate in self._rules and suffix_len > best_len:
                best_len = suffix_len
                best_suffix_start = i

            if i > 0 and candidate in self._wildcards:
                wildcard_start = i - 1
                wildcard_len = n - wildcard_start
                if wildcard_len > best_len:
                    best_len = wildcard_len
                    best_suffix_start = wildcard_start

        if best_suffix_start is None:
            # Default: last label
            return labels[-1] if labels else None

        return ".".join(labels[best_suffix_start:])


# ── Module-level singleton ─────────────────────────────────────────────────────
# Loaded lazily on first call.  Raises FileNotFoundError if psl.dat is absent.

_psl_instance: Optional[PSL] = None


def get_psl() -> PSL:
    """
    Return the module-level PSL singleton loaded from lists/psl.dat.
    Raises FileNotFoundError if lists/psl.dat is not present.
    For unit tests, do NOT call this; use PSL.for_testing() instead.
    """
    global _psl_instance
    if _psl_instance is None:
        _psl_instance = PSL()   # raises if psl.dat missing
    return _psl_instance


def reset_psl() -> None:
    """Force the singleton to reload on the next get_psl() call. Used in tests."""
    global _psl_instance
    _psl_instance = None
