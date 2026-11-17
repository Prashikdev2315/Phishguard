"""Experimental, leakage-resistant URL features.

This module intentionally does not replace the frozen ``fs1`` extractor.  It
defines a separate experimental schema for evaluating whether ratio-based and
query-masked features generalize better across datasets.
"""
from __future__ import annotations

import hashlib
import math
import re
import urllib.parse
from collections import Counter
from typing import Dict, Iterable

from ml.normalize import normalize

SCHEMA = "url-experimental-v2"
FEATURE_NAMES = (
    "host_entropy",
    "path_entropy",
    "query_entropy",
    "host_length_log",
    "path_length_log",
    "query_length_log",
    "path_ratio",
    "query_ratio",
    "digit_ratio",
    "special_ratio",
    "letter_ratio",
    "path_depth_log",
    "query_param_count_log",
    "has_path",
    "has_query",
    "has_fragment",
    "login_token",
    "sensitive_token_count",
    "encoded_token_ratio",
    "host_label_entropy",
    "log_tranco_rank",
    "is_root_domain",
    "domain_token_count",
    "tld_risk_score",
    "path_to_domain_length_ratio",
    "path_depth",
    "path_entropy_relative",
    "query_param_count",
    "query_value_density",
    "digit_to_alpha_ratio_path",
    "domain_suspicious_keyword_count",
    "path_suspicious_keyword_count",
    "double_slash_in_path",
    "at_symbol_in_url",
    "hex_pattern_count",
)

_TOKEN_RE = re.compile(
    r"(?:^|[/_.?&#=\-])(login|signin|sign-in|log-in|signup|sign-up|"
    r"register|account|accounts|auth|sso|oauth)(?:$|[/_.?&#=\-])",
    re.IGNORECASE,
)
_SENSITIVE = ("login", "signin", "verify", "secure", "account", "password", "confirm", "banking", "wallet")
_SUSPICIOUS = ("login", "verify", "account", "admin", "secure", "update", "banking")
_TLD_RISK = {
    "com": 0.10,
    "org": 0.15,
    "net": 0.20,
    "edu": 0.05,
    "gov": 0.05,
    "xyz": 0.90,
    "top": 0.90,
    "click": 0.85,
    "zip": 0.85,
    "tk": 0.90,
}
_HEX_PATTERN = re.compile(r"%[0-9a-fA-F]{2}|(?<![A-Za-z0-9])[0-9a-fA-F]{8,}(?![A-Za-z0-9])")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = float(len(value))
    return -sum((n / size) * math.log(n / size, 2) for n in counts.values())


def mask_query(query: str) -> str:
    """Replace query values with typed tokens while retaining key structure."""
    if not query:
        return ""
    masked = []
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        decoded = urllib.parse.unquote_plus(value)
        if decoded.isdigit():
            token = "<NUM>"
        elif re.fullmatch(r"[0-9a-fA-F-]{8,}", decoded):
            token = "<HEX>"
        elif decoded:
            token = "<STR>"
        else:
            token = "<EMPTY>"
        masked.append(f"{urllib.parse.quote_plus(key)}={token}")
    return "&".join(masked)


def _tld_risk(host: str) -> float:
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    return _TLD_RISK.get(tld, 0.50)


def _keyword_count(value: str) -> int:
    lowered = value.lower()
    return sum(lowered.count(keyword) for keyword in _SUSPICIOUS)


def extract_features(url: str, tranco_rank: int | None = None) -> Dict[str, float]:
    """Extract the experimental v2 feature vector.

    ``tranco_rank`` is optional because D1 has no rank column.  Missing or
    non-positive ranks use the documented unranked fallback of ``7.0``.
    """
    result = normalize(url)
    if result.error:
        raise ValueError(f"URL normalization failed: {result.error}")
    host = (result.puny_host or "").lower().removeprefix("www.")
    registrable_domain = result.registrable_domain or host
    path = result.path or ""
    masked_query = mask_query(result.query.lstrip("?"))
    fragment = result.fragment.lstrip("#")
    lexical = f"{host}{path}?{masked_query}#{fragment}".rstrip("?#")
    total = max(float(len(lexical)), 1.0)
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", lexical))
    special = sum(not char.isalnum() for char in lexical)
    digits = sum(char.isdigit() for char in lexical)
    letters = sum(char.isalpha() for char in lexical)
    labels = [label for label in host.split(".") if label]
    path_segments = [part for part in path.split("/") if part]
    path_entropy = _entropy(path)
    entropy_denominator = math.log(len(path), 2) if len(path) > 1 else 0.0
    path_alpha = sum(char.isalpha() for char in path)
    path_digits = sum(char.isdigit() for char in path)
    params = urllib.parse.parse_qsl(result.query.lstrip("?"), keep_blank_values=True)
    rank_value = math.log10(tranco_rank) if tranco_rank is not None and tranco_rank > 0 else 7.0
    return {
        "host_entropy": _entropy(host),
        "path_entropy": path_entropy,
        "query_entropy": _entropy(masked_query),
        "host_length_log": math.log1p(len(host)),
        "path_length_log": math.log1p(len(path)),
        "query_length_log": math.log1p(len(masked_query)),
        "path_ratio": len(path) / total,
        "query_ratio": len(masked_query) / total,
        "digit_ratio": digits / total,
        "special_ratio": special / total,
        "letter_ratio": letters / total,
        "path_depth_log": math.log1p(len([part for part in path.split("/") if part])),
        "query_param_count_log": math.log1p(len(urllib.parse.parse_qsl(result.query.lstrip("?"), keep_blank_values=True))),
        "has_path": int(bool(path.rstrip("/"))),
        "has_query": int(bool(masked_query)),
        "has_fragment": int(bool(fragment)),
        "login_token": int(bool(_TOKEN_RE.search(path + "?" + masked_query))),
        "sensitive_token_count": sum(path.lower().count(token) for token in _SENSITIVE),
        "encoded_token_ratio": encoded / total,
        "host_label_entropy": _entropy("|".join(labels)),
        "log_tranco_rank": rank_value,
        "is_root_domain": int(not path.rstrip("/") and not masked_query),
        "domain_token_count": max(len(registrable_domain.split(".")) - 1, 0),
        "tld_risk_score": _tld_risk(host),
        "path_to_domain_length_ratio": len(path) / max(len(registrable_domain), 1),
        "path_depth": len(path_segments),
        "path_entropy_relative": (
            path_entropy / entropy_denominator if entropy_denominator else 0.0
        ),
        "query_param_count": len(params),
        "query_value_density": len(masked_query) / total,
        "digit_to_alpha_ratio_path": path_digits / max(path_alpha, 1),
        "domain_suspicious_keyword_count": _keyword_count(host),
        "path_suspicious_keyword_count": _keyword_count(path),
        "double_slash_in_path": int("//" in path),
        "at_symbol_in_url": int("@" in result.normalized),
        "hex_pattern_count": len(_HEX_PATTERN.findall(lexical)),
    }


def extract_vector(url: str, tranco_rank: int | None = None) -> list[float]:
    row = extract_features(url, tranco_rank=tranco_rank)
    return [row[name] for name in FEATURE_NAMES]


def extract_many(urls: Iterable[str]) -> list[list[float]]:
    return [extract_vector(url) for url in urls]


def stable_query_fingerprint(url: str) -> str:
    """Return a non-reversible fingerprint for diagnostics, never a raw query."""
    result = normalize(url)
    return hashlib.sha256(mask_query(result.query.lstrip("?")).encode("utf-8")).hexdigest()
