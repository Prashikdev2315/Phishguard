"""
ml/normalize.py — URL normalization, rules N-01 to N-12 (PRD §6.1)
====================================================================

Schema: fs1 (frozen in CONTRACTS.md)

This module is the SINGLE source of truth for URL normalization in Python.
The TypeScript port (Chunk 8) must produce identical outputs; parity is
verified by PAR-01 on every dataset URL.

Public API
----------
normalize(raw: str) -> NormalizeResult

NormalizeResult fields
----------------------
raw             : str            original input (unchanged)
error           : str | None     None | 'url_too_long' | 'whitespace_inside' | 'invalid_url'
normalized      : str            normalized URL including fragment (for features)
cache_key       : str            normalized URL, no fragment, tracking params stripped
display_host    : str            Unicode hostname (for UI display)
puny_host       : str            ACE / punycode hostname (for IDNA comparisons)
registrable_domain: str | None   eTLD+1 via PSL (N-11)
public_suffix   : str | None     eTLD via PSL
scheme          : str            'http' | 'https' | '' (on error)
path            : str            normalized path component
query           : str            query string (with leading '?' or '')
fragment        : str            fragment (with leading '#' or '')
is_ip_host      : bool           N-07: host is any IP form
is_punycode     : bool           N-04: host contains xn-- or was IDN-encoded
decoded_url     : str            percent-decoded, lowercased (N-10, keyword matching)
raw_length      : int            len(normalized) — for length features (N-10)
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from ml.psl import get_psl, PSL

# ── constants ─────────────────────────────────────────────────────────────────

MAX_URL_LENGTH = 2048  # N-12

# Tracking parameters stripped from cache key (N-09)
_TRACKING_PARAMS: frozenset[str] = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format",
    "utm_marketing_tactic",
    "fbclid", "gclid", "msclkid",
})

# BOM characters that count as leading whitespace for N-01
_BOM_CHARS: frozenset[str] = frozenset({"\ufeff", "\ufffe"})

# IP detection patterns (N-07)
# Dotted decimal: four octets 0-255
_RE_IPV4_DECIMAL = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)
# Hex IP: 0x followed by 8 hex digits (may have leading zeros)
_RE_IPV4_HEX = re.compile(r"^0x[0-9a-f]{1,8}$", re.IGNORECASE)
# Octal IP: each octet starts with 0 and contains only 0-7
_RE_IPV4_OCTAL = re.compile(r"^0[0-7]*\.0[0-7]*\.0[0-7]*\.0[0-7]*$")
# Pure integer: decimal integer (uint32)
_RE_IPV4_INT = re.compile(r"^\d+$")
# IPv6 literal inside brackets [...]
_RE_IPV6 = re.compile(r"^\[.*\]$")


# ── result dataclass ──────────────────────────────────────────────────────────

@dataclass
class NormalizeResult:
    raw:                str
    error:              Optional[str]       = None
    normalized:         str                 = ""
    cache_key:          str                 = ""
    display_host:       str                 = ""
    puny_host:          str                 = ""
    registrable_domain: Optional[str]       = None
    public_suffix:      Optional[str]       = None
    scheme:             str                 = ""
    path:               str                 = ""
    query:              str                 = ""
    fragment:           str                 = ""
    is_ip_host:         bool                = False
    is_punycode:        bool                = False
    decoded_url:        str                 = ""
    raw_length:         int                 = 0


# ── helpers ────────────────────────────────────────────────────────────────────

def _strip_bom_and_nbsp(s: str) -> str:
    """Remove BOM chars and U+00A0 (non-breaking space) from both ends."""
    while s and (s[0] in _BOM_CHARS or s[0] == "\u00a0" or s[0].isspace()):
        s = s[1:]
    while s and (s[-1] in _BOM_CHARS or s[-1] == "\u00a0" or s[-1].isspace()):
        s = s[:-1]
    return s


def _has_internal_whitespace(s: str) -> bool:
    """True if the string contains any whitespace character (N-01)."""
    return any(c.isspace() or c == "\u00a0" for c in s)


def _is_ip_host(host: str) -> bool:
    """
    N-07: Return True if host is any IP form.
    Handles: IPv6 literal, dotted decimal, hex, octal, integer.
    Never resolves — only pattern-matches.
    """
    if not host:
        return False
    h = host.lower().rstrip(".")

    # IPv6 literal: [...]
    if _RE_IPV6.match(h):
        return True

    # Strip port if present (e.g. "192.168.1.1" — port already removed by this point)
    # but handle the case where it slipped through
    if ":" in h and not h.startswith("["):
        h = h.rsplit(":", 1)[0]

    # Hex IP: 0xC0A80101
    if _RE_IPV4_HEX.match(h):
        val = int(h, 16)
        return 0 <= val <= 0xFFFFFFFF

    # Pure integer (uint32)
    if _RE_IPV4_INT.match(h):
        try:
            return 0 <= int(h) <= 0xFFFFFFFF
        except ValueError:
            return False

    # Octal dotted: 0300.0250.01.01
    if _RE_IPV4_OCTAL.match(h):
        return True

    # Dotted decimal: validate each octet
    m = _RE_IPV4_DECIMAL.match(h)
    if m:
        return all(0 <= int(g) <= 255 for g in m.groups())

    return False


def _is_loopback_or_private(host: str) -> bool:
    """
    Pre-filter check (PRD §4): loopback and private-network hosts are skipped.
    Used by profile.py for analysis; not part of normalization output per se.
    """
    h = host.lower().rstrip(".")
    if h in ("localhost", "localhost.localdomain"):
        return True
    if h.startswith("[") and h.endswith("]"):
        inner = h[1:-1]
        if inner in ("::1", "0:0:0:0:0:0:0:1"):
            return True
        return False  # other IPv6 — not loopback
    # Dotted decimal
    m = _RE_IPV4_DECIMAL.match(h)
    if m:
        a, b, c, d = (int(g) for g in m.groups())
        if a == 127:                        return True   # 127.x.x.x
        if a == 10:                         return True   # 10.x.x.x
        if a == 172 and 16 <= b <= 31:      return True   # 172.16-31.x.x
        if a == 192 and b == 168:           return True   # 192.168.x.x
        if a == 169 and b == 254:           return True   # 169.254.x.x
        if a == 0:                          return True   # 0.x.x.x
    return False


def _host_to_punycode(unicode_host: str) -> str:
    """
    N-04: Encode each label of the host to ACE/punycode (IDNA).
    Returns the original host if encoding fails.
    """
    labels = unicode_host.split(".")
    encoded = []
    for label in labels:
        if not label:
            encoded.append(label)
            continue
        try:
            encoded.append(label.encode("idna").decode("ascii"))
        except (UnicodeError, UnicodeDecodeError):
            encoded.append(label)
    return ".".join(encoded)


def _resolve_path(path: str) -> str:
    """
    N-06: Resolve '.' and '..' segments.
    Follows RFC 3986 §5.2.4 logic without touching query or fragment.
    """
    # Split on '/' but keep the leading slash
    if not path:
        return path
    segments = path.split("/")
    resolved: list[str] = []
    for seg in segments:
        if seg == ".":
            continue
        elif seg == "..":
            if resolved and resolved[-1] != "":
                resolved.pop()
        else:
            resolved.append(seg)
    # Preserve leading slash
    result = "/".join(resolved)
    if path.startswith("/") and not result.startswith("/"):
        result = "/" + result
    return result


def _strip_tracking_params(query: str) -> str:
    """
    N-09: Remove tracking parameters from a query string (for cache key only).
    Preserves order of remaining parameters.
    Returns a query string without the leading '?'.
    """
    if not query:
        return query
    q = query.lstrip("?")
    if not q:
        return ""
    parts = q.split("&")
    kept = []
    for part in parts:
        name = part.split("=", 1)[0].lower()
        # Strip utm_* (any suffix) and the named params
        if name.startswith("utm_") or name in _TRACKING_PARAMS:
            continue
        kept.append(part)
    return "&".join(kept)


def _decode_for_keywords(url: str) -> str:
    """N-10: percent-decoded, lowercased copy for keyword matching."""
    try:
        decoded = urllib.parse.unquote(url, errors="replace")
    except Exception:
        decoded = url
    return decoded.lower()


def _detect_punycode(host: str) -> bool:
    """True if the ACE-encoded host contains any xn-- label."""
    return "xn--" in host.lower()


# ── main entry point ──────────────────────────────────────────────────────────

def normalize(raw: str) -> NormalizeResult:
    """
    Apply normalization rules N-01 to N-12 and return a NormalizeResult.
    Never raises; errors are reported via result.error.
    """
    result = NormalizeResult(raw=raw)

    # ── N-01: trim leading/trailing whitespace, BOM, U+00A0 ─────────────────
    cleaned = _strip_bom_and_nbsp(raw)
    # Reject if whitespace remains inside (after outer trim)
    if _has_internal_whitespace(cleaned):
        result.error = "whitespace_inside"
        return result

    # ── N-12: length gate (before normalization adds anything) ───────────────
    if len(cleaned) > MAX_URL_LENGTH:
        result.error = "url_too_long"
        return result

    # ── N-02: add scheme if missing ──────────────────────────────────────────
    url_str = cleaned
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_str):
        url_str = "http://" + url_str

    # ── parse ─────────────────────────────────────────────────────────────────
    try:
        parsed = urllib.parse.urlparse(url_str)
    except Exception:
        result.error = "invalid_url"
        return result

    scheme = parsed.scheme.lower()  # N-03: lowercase scheme
    if scheme not in ("http", "https"):
        # Treat unknown scheme as invalid for scoring purposes
        result.error = "invalid_url"
        return result

    # ── N-03: lowercase host ─────────────────────────────────────────────────
    netloc = parsed.netloc
    # Separate userinfo, host, port
    # netloc may be "user:pass@host:port" or "[ipv6]:port" or "host:port"
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.rsplit("@", 1)

    # Separate host from port for IPv6 and regular hosts
    if host_port.startswith("["):
        # IPv6
        bracket_end = host_port.find("]")
        raw_host = host_port[: bracket_end + 1].lower()
        port_part = host_port[bracket_end + 1 :]
    elif ":" in host_port:
        raw_host, port_str = host_port.rsplit(":", 1)
        raw_host = raw_host.lower()
        # N-05: drop default ports
        try:
            port_val = int(port_str)
            if (scheme == "http" and port_val == 80) or \
               (scheme == "https" and port_val == 443):
                port_part = ""
            else:
                port_part = ":" + port_str
        except ValueError:
            port_part = ":" + port_str
    else:
        raw_host = host_port.lower()
        port_part = ""

    # N-05: remove trailing dot from host
    raw_host = raw_host.rstrip(".")

    if not raw_host:
        result.error = "invalid_url"
        return result

    # ── N-07: IP detection ───────────────────────────────────────────────────
    is_ip = _is_ip_host(raw_host)

    # ── N-04: punycode encode ────────────────────────────────────────────────
    display_host = raw_host   # Unicode form for display
    puny_host = _host_to_punycode(raw_host)
    is_punycode = _detect_punycode(puny_host)

    # Reconstruct netloc (without userinfo — we drop it for normalization)
    new_netloc = puny_host + port_part

    # ── N-06: resolve path ───────────────────────────────────────────────────
    resolved_path = _resolve_path(parsed.path)

    # ── Reconstruct query and fragment ────────────────────────────────────────
    query = ("?" + parsed.query) if parsed.query else ""
    fragment = ("#" + parsed.fragment) if parsed.fragment else ""

    # ── Build normalized URL (N-08: features include fragment) ───────────────
    normalized = urllib.parse.urlunparse((
        scheme, new_netloc, resolved_path, "", parsed.query, parsed.fragment
    ))

    # ── Build cache key (N-08: drop fragment; N-09: strip tracking params) ───
    stripped_query = _strip_tracking_params(parsed.query)
    cache_key = urllib.parse.urlunparse((
        scheme, new_netloc, resolved_path, "", stripped_query, ""
    ))

    # ── N-11: registrable domain via PSL ─────────────────────────────────────
    psl = get_psl()
    if is_ip:
        reg_domain = None
        pub_suffix = None
    else:
        reg_domain = psl.registrable_domain(puny_host)
        pub_suffix = psl.public_suffix(puny_host)

    # ── N-10: decoded URL for keyword matching ────────────────────────────────
    decoded = _decode_for_keywords(normalized)

    # ── Post-normalize length check (N-12 again after scheme prepend) ─────────
    if len(normalized) > MAX_URL_LENGTH:
        result.error = "url_too_long"
        return result

    result.error              = None
    result.normalized         = normalized
    result.cache_key          = cache_key
    result.display_host       = display_host
    result.puny_host          = puny_host
    result.registrable_domain = reg_domain
    result.public_suffix      = pub_suffix
    result.scheme             = scheme
    result.path               = resolved_path
    result.query              = query
    result.fragment           = fragment
    result.is_ip_host         = is_ip
    result.is_punycode        = is_punycode
    result.decoded_url        = decoded
    result.raw_length         = len(normalized)

    return result
