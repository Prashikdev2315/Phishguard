# PhishGuard — CONTRACTS.md
# Frozen Interface Contracts

These items are **frozen**. Any change requires a PRD revision and a matching
update to this file, the relevant test, and `docs/ASSUMPTIONS.md`.
Automated guard: `tests/security/test_sc01_manifest.py` (SC-01) fails CI if
the manifest deviates from the permission contract.

---

## 1. Permission contract

Frozen in Chunk 1. Source of truth: `docs/PERMISSIONS.md` + SC-01 test.

| Field                       | Frozen value                                |
|-----------------------------|---------------------------------------------|
| `permissions`               | `["storage", "webNavigation", "alarms"]`    |
| `optional_permissions`      | `["scripting"]`                             |
| `host_permissions`          | `[]`  (empty — no broad host in core)       |
| `optional_host_permissions` | `["<all_urls>"]`                            |
| `manifest_version`          | `3`                                         |
| `minimum_chrome_version`    | `"120"`                                     |
| `web_accessible_resources`  | `[]`  (empty — warning.html not web-accessible) |
| `externally_connectable`    | absent                                      |

---

## 2. Content Security Policy (CSP)

Frozen in Chunk 1. Applied to `extension_pages` in `manifest.json`.

```
script-src 'self'; object-src 'self'; base-uri 'self'
```

Rules that must never be relaxed (SEC-01):
- No `'unsafe-eval'`
- No `'unsafe-inline'`
- No remote script origins

---

## 3. Storage keys

Frozen in Chunk 1. Source: PRD §8.3.
Full URL never stored; path, query, fragment never persisted (SEC-06).

| Key            | Area    | Type / contents                                              | Retention                       |
|----------------|---------|--------------------------------------------------------------|---------------------------------|
| `settings`     | local   | `{ enforcementMode, failureMode, bannerEnabled }`            | Until cleared                   |
| `userAllowlist`| local   | Array of registrable domains / tenant hosts                  | Until removed                   |
| `cache`        | local   | `{ [hashKey]: { risk, band, modelVersion, timestamp } }`     | TTL + LRU, 2 000 entries max    |
| `history`      | local   | Array of `{ time, host, band, risk, action }`                | 500 rows, 30 days, daily purge  |
| `counters`     | local   | `{ scans, blocks, warnings, overrides }`  (integers)         | Until cleared                   |
| `pending`      | session | `{ [pending:<token>]: { host, risk, band, reasons, modelVersion } }` | Browser session     |
| `overrides`    | session | `{ [urlHash]: expiry }`  (30-minute scoped overrides)        | Browser session                 |
| `tabState`     | session | `{ [tabId]: { token, lastVerdict } }`                        | Browser session                 |

The initial settings default is `enforcementMode="warn_only"`,
`failureMode="open"`, and `bannerEnabled=true`.

**Key-name contract** (must match exactly in service worker and all pages):

```
"settings"       "userAllowlist"   "cache"      "history"
"counters"       "pending:<token>" "overrides"  "tabState"
```

---

## 4. Message-type contract

Frozen in Chunk 1. Source: PRD §8.4.
Every handler validates `sender.id === chrome.runtime.id` (SEC-04).

| `msg.type`         | From              | To      | Payload fields                          |
|--------------------|-------------------|---------|-----------------------------------------|
| `GET_TAB_STATUS`   | popup             | worker  | _(none)_                                |
| `GET_BLOCK_DETAILS`| warning page      | worker  | `token: string`                         |
| `GO_BACK`          | warning page      | worker  | `token: string`                         |
| `PROCEED_OVERRIDE` | warning page      | worker  | `token: string`  (trusted click only)   |
| `TRUST_DOMAIN`     | popup, options    | worker  | `host: string`                          |
| `UPDATE_SETTINGS`  | options           | worker  | `settings: Partial<Settings>`           |
| `CLEAR_DATA`       | options           | worker  | `scope: "history" | "cache" | "all"`    |

---

## 5. `thresholds.json` defaults

Frozen in Chunk 1. Source: PRD §6.3 and §7.6.
Values are **defaults only**; calibration in Chunk 6 may update them and must
log the change here and in `data/PROVENANCE.md`.

```json
{
  "schema":           "fs1",
  "T_safe_max":       34,
  "T_suspicious_min": 35,
  "T_suspicious_max": 69,
  "T_high_risk_min":  70,
  "T_block":          70,
  "T_warn":           35
}
```

Risk band formula: `risk = round(100 × p)`
- Safe       : `risk ≤ 34`
- Suspicious : `35 ≤ risk ≤ 69`
- High-Risk  : `risk ≥ 70`

---

## 6. Feature schema identifier

| Field          | Value  | Where used                                              |
|----------------|--------|---------------------------------------------------------|
| `schema`       | `fs1`  | `model.bin` header, `model.manifest.json`, `thresholds.json` |
| Feature count  | 50     | Frozen (50 features: `is_https` dropped per A-13 ruling) |
| Feature order  | Frozen in `ml/features.py` spec file (Chunk 4)         |

---

## 7. Model binary format

The shipped `extension/public/model.bin` is a pickle-free, little-endian
binary model package. Its format is frozen in Chunk 7.

| Prefix field | Encoding |
|---|---|
| Magic | ASCII `PGM1` (4 bytes) |
| Format version | `uint8`, value `1` |
| Header length | `uint32`, little-endian |
| Header | Canonical UTF-8 JSON |
| Payload | Level-9 zlib-compressed bytes |

The JSON header contains `schema=fs1`, `model_version=pg-model-1.0.0`,
`feature_count=50`, `sample_count=7781`, `k=20`, `selector=rf_importance`,
`classifier=rf`, payload sizes, section offsets and lengths, calibration
metadata, thresholds, the joblib oracle path, and the source-model SHA-256.

The uncompressed payload sections are, in order, `scaler_min` (50 float64
values), `scaler_scale` (50 float64 values), `selected_indices` (20 uint16
values), and `forest`. The forest contains exactly 200 trees. Each tree is
encoded as `node_count` (`uint32`) followed by `children_left` and
`children_right` (`int32`), `feature` (`int16`), `threshold` (`float32`), and
leaf malicious probabilities (`float32`) arrays of `node_count` elements.
Tree probabilities are averaged for inference after MinMax scaling and feature
selection. The final file must be strictly smaller than 2 MiB.

---

## 8. Reason-code identifiers

Frozen in Chunk 1. Source: PRD §6.4. Must match exactly in Python and TypeScript.

| Code  | Key              |
|-------|------------------|
| R-00  | `GENERIC`        |
| R-01  | `IP_HOST`        |
| R-02  | `BRAND_MISMATCH` |
| R-03  | `SENSITIVE_WORDS`|
| R-04  | `LONG_URL`       |
| R-05  | `DEEP_SUBDOMAINS`|
| R-06  | `SUSPICIOUS_TLD` |
| R-07  | `HOMOGRAPH`      |
| R-08  | `FREE_HOSTING`   |
| R-09  | `EMBEDDED_URL`   |
| R-10  | `NO_HTTPS`       | (Evaluated at runtime using the actual URL scheme `r.scheme == 'http'`; unaffected by dropping `is_https` from model features) |
| R-11  | `RANDOM_HOST`    |

---

## 9. `ml/normalize.py` behavior contract

The extension release bundle is produced with esbuild. `pako` is retained only
as a bundled zlib implementation for PGM1 payload inflation, and `punycode` is
retained only for IDNA normalization; neither package is loaded as a bare
runtime import by the unpacked extension.

Frozen in Chunk 2; amended for train/serve skew fix. Source: PRD §6.1 (N-01 to N-15).
TypeScript port (Chunk 8) must produce identical outputs; verified by PAR-01.

### Return type: `NormalizeResult` fields

| Field | Type | Description |
|-------|------|-------------|
| `raw` | str | Original unmodified input |
| `error` | str \| None | `None` \| `"url_too_long"` \| `"whitespace_inside"` \| `"invalid_url"` |
| `normalized` | str | Normalized URL **including fragment** (used for features) |
| `cache_key` | str | Normalized URL, **no fragment, tracking params stripped** |
| `display_host` | str | Unicode hostname (for UI display, N-04) |
| `puny_host` | str | ACE/punycode hostname (for IDNA comparisons, N-04) |
| `registrable_domain` | str \| None | eTLD+1 via PSL (N-11); `None` for IP hosts |
| `public_suffix` | str \| None | eTLD via PSL |
| `scheme` | str | `"http"` \| `"https"` \| `""` on error |
| `path` | str | Resolved path component (N-06) |
| `query` | str | Query string with leading `?` or `""` |
| `fragment` | str | Fragment with leading `#` or `""` |
| `is_ip_host` | bool | N-07: host is any IP form |
| `is_punycode` | bool | N-04: host contains `xn--` label |
| `decoded_url` | str | Percent-decoded, lowercased (N-10, keyword matching) |
| `raw_length` | int | `len(normalized)` — used for length features |

### Rule summary

| Rule | Behavior (frozen) |
|------|-------------------|
| N-01 | Strip leading/trailing whitespace, U+00A0, BOM (U+FEFF, U+FFFE). Error `whitespace_inside` if whitespace remains. |
| N-02 | Prepend `http://` if no scheme present. |
| N-03 | Lowercase scheme and host. Path and query case preserved. |
| N-04 | Host encoded to punycode (IDNA). Unicode form kept as `display_host`. `is_punycode=True` if any `xn--` label. |
| N-05 | Remove trailing dot from host. Drop port 80 on http, 443 on https. Other ports kept. |
| N-06 | Resolve `.` and `..` path segments (RFC 3986 §5.2.4). Path case preserved. |
| N-07 | Detect IP hosts: IPv6 `[...]`, dotted decimal, hex (`0x...`), octal (leading `0`), integer. Flag as `is_ip_host=True`. Never resolve. |
| N-08 | `normalized` includes fragment. `cache_key` excludes fragment. Fragment never stored. |
| N-09 | Tracking params (`utm_*`, `fbclid`, `gclid`, `msclkid`) stripped from `cache_key` only. Full query in `normalized`. |
| N-10 | `decoded_url` = percent-decoded + lowercased `normalized`. Length/char counts use `raw_length = len(normalized)`. |
| N-11 | Registrable domain via pinned PSL (`lists/psl.dat`; fallback to minimal built-in). Private section included so `username.github.io` → `username.github.io`. |
| N-12 | `len(url) > 2048` → error `url_too_long`. Checked on raw input AND on result. |
| N-13 | All string-based features are computed on the scheme-stripped normalized URL (e.g. `example.com/path` instead of `http://example.com/path`). `is_https` dropped from model features in schema `fs1` (feature count = 50). R-10 (`NO_HTTPS`) continues to evaluate the real scheme at runtime. |
| N-14 | A root path `"/"` is canonical empty (`https://host/` == `https://host`). |
| N-15 | For feature computation strip one leading `"www."` label from the host (display and cache keys keep it). |

### PSL contract

- Primary: `lists/psl.dat` pinned snapshot (team provides; includes private section)
- Fallback: minimal built-in PSL in `ml/psl.py` (covers test suite + all hosting platforms)
- **The same PSL snapshot ships in Python and TypeScript** (Chunk 8)
- Pinned PSL SHA-256: `e029473ba3a8486cee25c52a62787f9f66389ba2288b45dac183b1efc183af3a`
- IP hosts: `registrable_domain = None`, `public_suffix = None`

### Error precedence

`url_too_long` → `whitespace_inside` → `invalid_url`
(length is checked on raw input first, then after scheme prepend)

---

*Last updated: Approved contract change — N-14 and N-15 added to address train/serve skew and source shortcuts.*
