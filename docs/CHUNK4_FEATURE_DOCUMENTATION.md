# PhishGuard Chunk 4 — Feature Engineering Documentation

## 1. Purpose and scope

This document records the Python URL-feature implementation for the frozen `fs1` schema.

The source of truth for feature count and order is `ml/feature_spec.json`:

- Schema: `fs1`
- Feature count: 50
- Feature names: exactly 50 unique entries in the declared order
- `is_https`: excluded under the N-13 ruling in `docs/CONTRACTS.md`
- Optional WHOIS v1.1 features: not included

The Python implementation is in `ml/features.py`. It uses the shared URL normalizer in `ml/normalize.py`, the frozen feature specification, and versioned data files under `lists/`.

This document describes the current Python implementation. It does not claim that JavaScript/TypeScript parity, production list curation, or the complete extension inference pipeline has been completed.

## 2. Shared extraction conventions

### 2.1 Normalization

Feature extraction first calls the shared `normalize()` function. If normalization reports an error, feature extraction raises `ValueError`.

The implementation uses normalized URL components, including the hostname, path, query, fragment, registrable domain, public suffix, punycode status, IP-host status, and display hostname.

### 2.2 N-13 scheme-stripped string features

As required by N-13, string-based features are calculated on the scheme-stripped normalized URL. For example:

`https://example.com/path` → `example.com/path`

The model feature list therefore does not contain `is_https`. The runtime rule `NO_HTTPS` remains separate and can inspect the original URL scheme.

### 2.3 Network and WHOIS

- Feature extraction makes no network requests.
- WHOIS fields are not included in `fs1`.
- The Public Suffix List-backed normalizer supplies registrable-domain and public-suffix information.

### 2.4 IP-literal host constants

For an IP-literal hostname, the following domain-derived features use explicit neutral constants defined in `ml/feature_spec.json` under `ip_host_constants`: `tld_length`, `subdomain_count`, `registrable_domain_length`, `domain_hyphen_count`, `domain_digit_count`, `is_punycode`, `mixed_script_host`, `suspicious_tld`, and `longest_subdomain_label`. The current `fs1` constants are all zero. `has_ip_host` remains 1 for an IP-literal host.

### 2.5 Training-derived suspicious TLD mapping

`suspicious_tld` is data-dependent. The mapping must be derived from the applicable training partition only, then reused to transform that partition's validation data.

The default qualification rule is:

- At least 80% of rows for the TLD are malicious; and
- Those malicious rows represent at least 20 distinct registrable domains.

The implementation exposes these as `min_malicious_share=0.80` and `min_domains=20`. It also checks that URL and label input lengths match.

For cross-validation, derive the mapping separately inside each training fold. Do not derive it from validation, test, E1 holdout, or E2 labels.

## 3. Feature inventory

The following groupings are documentation categories for readability. The authoritative feature order remains the order in `ml/feature_spec.json`.

### 3.1 URL and component structure

| # | Feature | Current calculation / meaning |
|---:|---|---|
| 1 | `url_length` | Character length of the scheme-stripped normalized URL. |
| 2 | `hostname_length` | Character length of the normalized hostname. |
| 3 | `path_length` | Character length of the normalized path. |
| 4 | `query_length` | Character length of the query after removing its leading `?`. |
| 5 | `fragment_length` | Character length of the fragment after removing its leading `#`. |
| 6 | `tld_length` | Character length of the normalized public suffix; zero for an IP-literal host. |
| 7 | `subdomain_count` | Number of subdomain labels preceding the registrable domain, excluding `www`. |
| 8 | `path_depth` | Number of non-empty path segments. |
| 9 | `query_param_count` | Number of non-empty `&`-separated query components; zero for an empty query. |

### 3.2 Punctuation and URL structure

| # | Feature | Current calculation / meaning |
|---:|---|---|
| 10 | `dot_count` | Number of `.` characters in the scheme-stripped normalized URL. |
| 11 | `hyphen_count` | Number of `-` characters in the scheme-stripped normalized URL. |
| 12 | `underscore_count` | Number of `_` characters in the scheme-stripped normalized URL. |
| 13 | `at_symbol_count` | Number of `@` characters in the scheme-stripped normalized URL. |
| 14 | `double_slash_in_path` | Binary indicator that the normalized path contains `//`. |
| 15 | `non_default_port` | Binary indicator for an explicit port other than HTTP 80 or HTTPS 443. |
| 16 | `has_ip_host` | Binary indicator supplied by URL normalization for an IP-literal hostname. |

### 3.3 Character composition

| # | Feature | Current calculation / meaning |
|---:|---|---|
| 17 | `digit_count` | Number of digit characters in the scheme-stripped normalized URL. |
| 18 | `digit_ratio` | Digit count divided by the scheme-stripped URL length; zero for an empty string. |
| 19 | `letter_ratio` | Unicode alphabetic-character count divided by URL length; zero for an empty string. |
| 20 | `uppercase_ratio` | Uppercase-character count divided by URL length; zero for an empty string. |
| 21 | `special_char_count` | Number of characters for which `isalnum()` is false. |
| 22 | `special_char_ratio` | Special-character count divided by URL length; zero for an empty string. |
| 23 | `percent_encoded_count` | Number of `%HH` percent-encoding sequences. |
| 24 | `equals_count` | Number of `=` characters in the scheme-stripped normalized URL. |
| 25 | `ampersand_count` | Number of `&` characters in the scheme-stripped normalized URL. |
| 26 | `tilde_count` | Number of `~` characters in the scheme-stripped normalized URL. |

### 3.4 Lexical indicators and list-based features

| # | Feature | Current calculation / meaning |
|---:|---|---|
| 27 | `sensitive_word_count` | Sum of substring-occurrence counts for configured sensitive words in the decoded, scheme-stripped URL. |
| 28 | `action_word_count` | Sum of substring-occurrence counts for configured action words in the decoded, scheme-stripped URL. |
| 29 | `keyword_in_host` | Binary indicator that a sensitive or action word occurs in the lowercase hostname. |
| 30 | `keyword_in_path` | Binary indicator that a sensitive or action word occurs in the lowercase path only; query parameters are excluded. |
| 31 | `brand_in_subdomain_or_path` | Binary indicator that a configured brand occurs in the subdomain labels or lowercase path only; query parameters are excluded. |
| 32 | `is_url_shortener` | Binary indicator for a hostname matching a configured shortener domain or its subdomain. |
| 33 | `is_free_hosting` | Binary indicator for a hostname matching a configured free-hosting platform or its subdomain. |

List files used by the current Python extractor:

- `lists/sensitive_words.json` (`words`)
- `lists/action_words.json` (`words`)
- `lists/brands.json` (`brands`)
- `lists/shorteners.json` (`shorteners`)
- `lists/hosting.json` (`platforms`)

List status matters. `action_words.json` and `brands.json` are currently marked `PLACEHOLDER`; their values are seed data, not completed curation. The Python extractor warns when these placeholder lists are loaded outside development/test mode. `sensitive_words.json` contains the ten seed words stated in PRD §6.2.

### 3.5 Registrable-domain and hostname characteristics

| # | Feature | Current calculation / meaning |
|---:|---|---|
| 34 | `registrable_domain_length` | Character length of the normalized registrable domain; zero when unavailable. |
| 35 | `domain_hyphen_count` | Number of hyphens in the registrable domain. |
| 36 | `domain_digit_count` | Number of digits in the registrable domain. |
| 37 | `is_punycode` | Binary indicator supplied by URL normalization. |
| 38 | `mixed_script_host` | Binary indicator that the hostname contains letters from more than one recognized Unicode script among the scripts checked by the implementation. |
| 39 | `suspicious_tld` | Binary indicator looked up from the training-derived suspicious-TLD mapping. |
| 40 | `longest_subdomain_label` | Maximum length among subdomain labels, excluding `www`; zero when there are none. |
| 41 | `embedded_url_in_path_or_query` | Binary indicator for an embedded HTTP(S) URL pattern in the path/query text. |

### 3.6 Entropy and sequence statistics

Entropy uses Shannon entropy in bits over character frequencies.

| # | Feature | Current calculation / meaning |
|---:|---|---|
| 42 | `url_entropy` | Shannon character entropy of the scheme-stripped normalized URL. |
| 43 | `host_entropy` | Shannon character entropy of the normalized hostname. |
| 44 | `path_entropy` | Shannon character entropy of the normalized path. |
| 45 | `query_entropy` | Shannon character entropy of the normalized query. |
| 46 | `distinct_char_ratio` | Number of distinct characters divided by scheme-stripped URL length; zero for an empty string. |
| 47 | `max_digit_run` | Length of the longest consecutive digit sequence in the scheme-stripped URL. |
| 48 | `max_consonant_run` | Length of the longest consecutive run of ASCII English consonants in the scheme-stripped URL. |
| 49 | `host_bigram_distinct_count` | Number of distinct two-character sequences in the hostname. |
| 50 | `host_trigram_distinct_count` | Number of distinct three-character sequences in the hostname. |

## 4. Public Python interface

`ml/features.py` provides these main interfaces:

| Function / constant | Purpose |
|---|---|
| `FEATURE_NAMES` | Frozen ordered tuple loaded from `ml/feature_spec.json`. |
| `SCHEMA` | Schema identifier, `fs1`. |
| `extract_features(url, suspicious_tlds=None)` | Returns a feature dictionary in frozen feature order. |
| `extract_vector(url, suspicious_tlds=None)` | Returns a list of feature values in frozen feature order. |
| `extract_many(urls, suspicious_tlds=None)` | Returns a pandas DataFrame with columns in frozen feature order. |
| `derive_suspicious_tlds(urls, labels, min_malicious_share=0.80, min_domains=20)` | Derives the TLD flags from the supplied training records. |

The extractor validates that the generated feature keys match the frozen feature specification. Invalid normalized URLs raise `ValueError`.

## 5. Current validation evidence

The project test suite previously completed with:

`164 passed`

The feature-specific tests cover:

- Exactly 50 unique ordered features.
- Exclusion of `is_https` and WHOIS features.
- Scheme-stripped URL length behavior.
- URL components and keyword/brand indicators.
- IP-host feature constants.
- Empty path/query entropy.
- Rejection of invalid URLs.
- Feature-vector ordering.

Passing these tests demonstrates the tested Python behavior; it does not by itself demonstrate all contract semantics or cross-language parity.

## 6. Outstanding Chunk 4 work

| Item | Status / action |
|---|---|
| `fs1` count and order | Implemented: 50 unique ordered features. |
| N-13 scheme stripping | Implemented in Python feature extraction. |
| WHOIS exclusion | Implemented for `fs1`. |
| Training-fold-only suspicious TLD derivation | Implemented at the inspected benchmark, calibration, diagnostics, and E1 call sites. |
| Sensitive-word seed | Matches the ten PRD seed words. |
| Action-word curation | Outstanding: current file is `PLACEHOLDER`; curate from reviewed phishing-report evidence and document source/version. |
| Brand curation | Outstanding: current file is `PLACEHOLDER`; compile from public phishing reports and document source/version. |
| Python/JavaScript parity | TypeScript normalization and feature parity pass on the D1 hold-out; exhaustive model-risk parity remains a release gate. |
| Full extension inference | Not implemented in the current service-worker spike; coordinate with the extension owner. |
| Final feature contract review | Path-only semantics are frozen for `keyword_in_path` and `brand_in_subdomain_or_path`; IP-host domain constants are explicit in `feature_spec.json`. Exhaustive model-risk parity and list curation remain outstanding. |

## 7. Files of record

- `ml/feature_spec.json` — authoritative schema and feature order.
- `ml/features.py` — Python feature implementation.
- `ml/normalize.py` — shared Python URL normalization.
- `tests/test_features_fs1.py` — feature-specific tests.
- `docs/CONTRACTS.md` — normalization and schema contract.
- `docs/PRD.md` — feature requirements and list requirements.
- `docs/ASSUMPTIONS.md` — placeholder-list assumption A-10 and N-13 decision A-13.
