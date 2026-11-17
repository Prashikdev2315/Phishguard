#!/usr/bin/env python3
"""PhishGuard fs1 URL feature extraction (50 features; Chunk 4).

All lexical string features use the scheme-stripped normalized URL (N-13).
No network requests are made. WHOIS fields are deliberately excluded from fs1.

Set PHISHGUARD_ENV=development (or test) for local development. In other
(non-development) environments, placeholder word lists produce a warning.
"""
from __future__ import annotations

import json
import logging
import math
import os
import pathlib
import re
import unicodedata
import urllib.parse
from collections import Counter
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ml.normalize import normalize

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "ml" / "feature_spec.json"
LOGGER = logging.getLogger(__name__)

_ENVIRONMENT = os.environ.get("PHISHGUARD_ENV", "production").strip().lower()
_DEVELOPMENT_ENVIRONMENTS = {"dev", "development", "test", "testing"}
_IS_DEVELOPMENT = _ENVIRONMENT in _DEVELOPMENT_ENVIRONMENTS

_SPEC = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
if _SPEC.get("schema") != "fs1":
    raise ValueError("Unsupported feature schema: %r" % _SPEC.get("schema"))
FEATURE_NAMES = tuple(_SPEC["feature_order"])
SCHEMA = "fs1"
if len(FEATURE_NAMES) != 50 or len(set(FEATURE_NAMES)) != 50:
    raise ValueError("fs1 must contain exactly 50 unique features")
if int(_SPEC.get("feature_count", -1)) != len(FEATURE_NAMES):
    raise ValueError("feature_count does not match feature_order")

# PRD-defined neutral values for domain-derived features on IP-literal hosts.
# Keep these values in feature_spec.json so the policy is explicit and versioned.
_IP_HOST_FEATURES = (
    "tld_length",
    "subdomain_count",
    "registrable_domain_length",
    "domain_hyphen_count",
    "domain_digit_count",
    "is_punycode",
    "mixed_script_host",
    "suspicious_tld",
    "longest_subdomain_label",
)
_IP_HOST_CONSTANTS = _SPEC.get("ip_host_constants", {})
_missing_ip_constants = set(_IP_HOST_FEATURES).difference(_IP_HOST_CONSTANTS)
if _missing_ip_constants:
    raise ValueError(
        "feature_spec.json is missing IP-host constants: %s"
        % sorted(_missing_ip_constants)
    )


def _words(filename: str, key: str) -> Tuple[str, ...]:
    """Load one shared word list and warn on placeholder data outside dev/test."""
    path = ROOT / "lists" / filename
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Word-list file must contain a JSON object: %s" % path)

    if (
        str(data.get("_status", "")).strip().upper() == "PLACEHOLDER"
        and not _IS_DEVELOPMENT
    ):
        LOGGER.warning(
            "PhishGuard list %s is marked PLACEHOLDER; its seed entries are "
            "being used in PHISHGUARD_ENV=%s. Replace it with the curated list "
            "before production use.",
            path.name,
            _ENVIRONMENT or "production",
        )

    return tuple(str(item).lower() for item in data.get(key, []) if item)


SENSITIVE_WORDS = _words("sensitive_words.json", "words")
ACTION_WORDS = _words("action_words.json", "words")
BRANDS = _words("brands.json", "brands")
SHORTENERS = _words("shorteners.json", "shorteners")
FREE_HOSTING = _words("hosting.json", "platforms")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = float(len(value))
    return -sum((count / n) * math.log(count / n, 2) for count in counts.values())


def _max_run(value: str, predicate) -> int:
    best = run = 0
    for char in value:
        if predicate(char):
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _contains_any(value: str, words: Sequence[str]) -> bool:
    return any(word and word in value for word in words)


def _count_words(value: str, words: Sequence[str]) -> int:
    return sum(value.count(word) for word in words if word)


def _mixed_script(host: str) -> int:
    scripts = set()
    for char in host:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in (
            "LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC",
            "HIRAGANA", "KATAKANA", "CJK", "HANGUL", "DEVANAGARI",
        ):
            if script in name:
                scripts.add(script)
                break
    return int(len(scripts) > 1)


def _suffix_from_host(host: str, public_suffix: Optional[str]) -> str:
    if public_suffix:
        return public_suffix.lower()
    return host.rsplit(".", 1)[-1] if "." in host else ""


def _matches_domain(host: str, domains: Sequence[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains if domain)


def _scheme_stripped(normalized: str) -> str:
    return re.sub(r"^https?://", "", normalized, count=1, flags=re.I)


def extract_features(
    url: str,
    suspicious_tlds: Optional[Mapping[str, bool]] = None,
) -> Dict[str, float]:
    """Return one fs1 feature dictionary in the frozen order.

    Invalid URLs raise ValueError; callers should handle normalization errors
    before passing records into a model.
    """
    result = normalize(url)
    if result.error:
        raise ValueError("URL normalization failed: " + result.error)

    parsed = urllib.parse.urlsplit(result.normalized)
    host = (result.puny_host or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = result.path or ""
    query = result.query.lstrip("?")
    fragment = result.fragment.lstrip("#")
    lexical = _scheme_stripped(result.normalized)
    decoded_lexical = _scheme_stripped(result.decoded_url)
    reg = result.registrable_domain or ""
    is_ip_host = bool(result.is_ip_host)
    suffix = (result.public_suffix or "").lower()
    subdomains = host[:-len(reg) - 1].split(".") if reg and not is_ip_host and host.endswith("." + reg) else []
    subdomains = [label for label in subdomains if label and label != "www"]

    try:
        port = parsed.port
    except ValueError:
        port = None

    non_default_port = int(
        port is not None
        and not (
            (result.scheme == "http" and port == 80)
            or (result.scheme == "https" and port == 443)
        )
    )
    n = float(len(lexical)) if lexical else 0.0
    host_for_tokens = host
    # These two indicators are defined by their names: path means path only,
    # and subdomain-or-path excludes query parameters.
    path_lower = path.lower()
    tld = "" if is_ip_host else (suffix or _suffix_from_host(host, None))
    suspicious = int(
        not is_ip_host and bool(suspicious_tlds and suspicious_tlds.get(tld, False))
    )
    consonant = lambda char: char.isalpha() and char.lower() in "bcdfghjklmnpqrstvwxyz"

    values = {
        "url_length": len(lexical),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "tld_length": int(_IP_HOST_CONSTANTS["tld_length"]) if is_ip_host else len(tld),
        "subdomain_count": int(_IP_HOST_CONSTANTS["subdomain_count"]) if is_ip_host else len(subdomains),
        "path_depth": len([part for part in path.split("/") if part]),
        "query_param_count": len([part for part in query.split("&") if part]) if query else 0,
        "dot_count": lexical.count("."),
        "hyphen_count": lexical.count("-"),
        "underscore_count": lexical.count("_"),
        "at_symbol_count": lexical.count("@"),
        "double_slash_in_path": int("//" in path),
        "non_default_port": non_default_port,
        "has_ip_host": int(result.is_ip_host),
        "digit_count": sum(char.isdigit() for char in lexical),
        "digit_ratio": sum(char.isdigit() for char in lexical) / n if n else 0.0,
        "letter_ratio": sum(char.isalpha() for char in lexical) / n if n else 0.0,
        "uppercase_ratio": sum(char.isupper() for char in lexical) / n if n else 0.0,
        "special_char_count": sum(not char.isalnum() for char in lexical),
        "special_char_ratio": sum(not char.isalnum() for char in lexical) / n if n else 0.0,
        "percent_encoded_count": len(re.findall(r"%[0-9a-fA-F]{2}", lexical)),
        "equals_count": lexical.count("="),
        "ampersand_count": lexical.count("&"),
        "tilde_count": lexical.count("~"),
        "sensitive_word_count": _count_words(decoded_lexical, SENSITIVE_WORDS),
        "action_word_count": _count_words(decoded_lexical, ACTION_WORDS),
        "keyword_in_host": int(_contains_any(host_for_tokens, SENSITIVE_WORDS + ACTION_WORDS)),
        "keyword_in_path": int(_contains_any(path_lower, SENSITIVE_WORDS + ACTION_WORDS)),
        "brand_in_subdomain_or_path": int(
            _contains_any(".".join(subdomains) + "/" + path_lower, BRANDS)
        ),
        "is_url_shortener": int(_matches_domain(host, SHORTENERS)),
        "is_free_hosting": int(_matches_domain(host, FREE_HOSTING)),
        "registrable_domain_length": int(_IP_HOST_CONSTANTS["registrable_domain_length"]) if is_ip_host else len(reg),
        "domain_hyphen_count": int(_IP_HOST_CONSTANTS["domain_hyphen_count"]) if is_ip_host else reg.count("-"),
        "domain_digit_count": int(_IP_HOST_CONSTANTS["domain_digit_count"]) if is_ip_host else sum(char.isdigit() for char in reg),
        "is_punycode": int(_IP_HOST_CONSTANTS["is_punycode"]) if is_ip_host else int(result.is_punycode),
        "mixed_script_host": int(_IP_HOST_CONSTANTS["mixed_script_host"]) if is_ip_host else _mixed_script(result.display_host or host),
        "suspicious_tld": int(_IP_HOST_CONSTANTS["suspicious_tld"]) if is_ip_host else suspicious,
        "longest_subdomain_label": int(_IP_HOST_CONSTANTS["longest_subdomain_label"]) if is_ip_host else max([len(label) for label in subdomains] or [0]),
        "embedded_url_in_path_or_query": int(
            bool(re.search(r"(https?%3a%2f%2f|https?://)", (path + "?" + query).lower()))
        ),
        "url_entropy": _entropy(lexical),
        "host_entropy": _entropy(host),
        "path_entropy": _entropy(path),
        "query_entropy": _entropy(query),
        "distinct_char_ratio": len(set(lexical)) / n if n else 0.0,
        "max_digit_run": _max_run(lexical, str.isdigit),
        "max_consonant_run": _max_run(lexical, consonant),
        "host_bigram_distinct_count": len({host[index:index + 2] for index in range(max(0, len(host) - 1))}),
        "host_trigram_distinct_count": len({host[index:index + 3] for index in range(max(0, len(host) - 2))}),
    }

    missing = set(FEATURE_NAMES).difference(values)
    extra = set(values).difference(FEATURE_NAMES)
    if missing or extra:
        raise RuntimeError(
            "Feature implementation does not match fs1: missing=%s extra=%s"
            % (sorted(missing), sorted(extra))
        )
    return {name: values[name] for name in FEATURE_NAMES}


def extract_vector(
    url: str,
    suspicious_tlds: Optional[Mapping[str, bool]] = None,
) -> list:
    row = extract_features(url, suspicious_tlds)
    return [row[name] for name in FEATURE_NAMES]


def extract_many(
    urls: Iterable[str],
    suspicious_tlds: Optional[Mapping[str, bool]] = None,
):
    """Return a pandas DataFrame in fs1 order."""
    import pandas as pd

    return pd.DataFrame(
        [extract_features(url, suspicious_tlds) for url in urls],
        columns=FEATURE_NAMES,
    )


def derive_suspicious_tlds(
    urls: Sequence[str],
    labels: Sequence[object],
    min_malicious_share: float = 0.80,
    min_domains: int = 20,
) -> Dict[str, bool]:
    """Learn suspicious TLD flags from training rows only (PRD §6.2)."""
    from collections import defaultdict

    if len(urls) != len(labels):
        raise ValueError(
            "urls and labels must have the same length; got %d and %d"
            % (len(urls), len(labels))
        )
    if not 0.0 <= min_malicious_share <= 1.0:
        raise ValueError("min_malicious_share must be between 0 and 1")
    if min_domains < 1:
        raise ValueError("min_domains must be at least 1")

    totals = defaultdict(int)
    malicious = defaultdict(int)
    domains = defaultdict(set)

    for url, label in zip(urls, labels):
        normalized = normalize(str(url))
        if normalized.error or not normalized.public_suffix or not normalized.registrable_domain:
            continue

        tld = normalized.public_suffix.lower()
        totals[tld] += 1
        is_malicious = str(label).strip().lower() in ("malicious", "1", "true")
        malicious[tld] += int(is_malicious)

        if is_malicious:
            domains[tld].add(normalized.registrable_domain)

    return {
        tld: (
            totals[tld] > 0
            and malicious[tld] / float(totals[tld]) >= min_malicious_share
            and len(domains[tld]) >= min_domains
        )
        for tld in totals
    }
