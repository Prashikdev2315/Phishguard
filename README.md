# PhishGuard

> **On-Device ML-Based Phishing Detection & Prevention Chrome Extension (Manifest V3)**

PhishGuard provides real-time, privacy-preserving, on-device phishing detection directly inside Chromium-based browsers without sending browsing history or raw URLs over the network.

---

## 🚀 Progress & Roadmap

We are executing against the 12 chunks defined in PRD v2.0:

| # | Chunk | Scope / Deliverables | Status |
|---|-------|----------------------|--------|
| 1 | **Spike & scaffold** | Repo layout, bare MV3 extension, race harness, frozen permissions | ✅ Complete |
| 2 | **Dataset profile** | N-01 to N-13 normalizer, Mozilla PSL parser, `profile.py`, shortcut audit, `PROVENANCE.md` | ✅ Complete |
| 3 | **Data build** | D1 cleaning/splits and E1 structural build; review and E2 pending | PARTIAL |
| 4 | **Normalization & features** | Python feature extraction, specification and tests | COMPLETE |
| 5 | **Benchmark** | Benchmarking deliverables | TEAMMATE-OWNED |
| 6 | **Calibration & gates** | Threshold calibration, Gates G-1 to G-8 including adversarial suite | 📋 Queued |
| 7 | **Export** | Binary model packager (`model.bin`, `PGM1`), manifest, joblib oracle | 📋 Queued |
| 8 | **TypeScript port** | Full on-device TypeScript runtime, Parity tests (G-5) | 📋 Queued |
| 9 | **Extension core** | Service worker navigation pipeline, cache, allowlist, override flow | 📋 Queued |
| 10 | **User Interface** | Extension popup, options, warning interstitial, about, history | 📋 Queued |
| 11 | **Hardening** | Performance (< 20 ms), CSP compliance, accessibility, security suite | 📋 Queued |
| 12 | **Release** | Final packaging, model card, user manual, unpacked Chrome demo | 📋 Queued |

---

## 📁 Repository Layout

```text
phishguard/
├── data/                  # Provenance records & sample audit data (PRD O-01 / R-08)
│   ├── review_sample.csv  # 100 random rows/class for manual label verification
│   └── PROVENANCE.md      # Dataset origin and validation record
├── docs/                  # Architecture contracts, assumptions, and specifications
│   ├── ASSUMPTIONS.md     # Tracked project assumptions and rulings
│   ├── CONTRACTS.md       # Frozen architecture, schema (fs1), and rule contracts
│   ├── PERMISSIONS.md     # Frozen Manifest V3 permissions
│   ├── PRD.md             # Complete PhishGuard Product Requirements Document (v2.0)
│   └── SPIKE_RESULTS.md   # Navigation race harness benchmarks
├── extension/             # Chrome Extension (Manifest V3)
│   ├── manifest.json      # Extension manifest
│   └── src/               # Service worker, warning page, popup, options
├── lists/                 # Auxiliary rule sets & domain lookups
│   ├── psl.dat            # Official Mozilla Public Suffix List snapshot (340+ KB)
│   ├── hosting.json       # Free hosting platform identifiers
│   ├── shorteners.json    # Known URL shortener domains
│   └── sensitive_words.json
├── ml/                    # Machine Learning pipeline
│   ├── normalize.py       # N-01 to N-13 URL normalizer
│   ├── psl.py             # Mozilla Public Suffix List parser with private section support
│   ├── profile.py         # Dataset profiler and shortcut baseline auditor
│   └── report/            # Generated profile artifacts (profile_D1.md, profile_D1.json)
├── tests/                 # Unit, security, and parity tests
│   ├── security/          # SC-01 Manifest V3 security tests
│   └── test_normalize_ut01.py # UT-01 URL normalization and PSL test suite
├── tools/                 # Development and benchmarking tools
│   └── spike/race_harness.py # Playwright-based navigation race harness (FR-09)
├── requirements.lock      # Fully pinned Python dependencies
├── thresholds.json        # Calibrated decision thresholds
└── pytest.ini             # Pytest configuration
```

---

## 🧪 Testing

Install pinned dependencies from `requirements.lock`, then run:

```bash
# Run all automated tests
python -m pytest tests/ -v
```

Current test suite: **166 tests passed, 0 failed**.

---

## 📊 Dataset Profile & Shortcut Baseline (Chunk 2)

- **Analyzed Rows**: 11,000 URLs (6,500 Benign, 4,500 Malicious)
- **Shortcut Baseline Balanced Accuracy**: **85.26%** (Deployable features: scheme-stripped length, `has_path`, TLD one-hot)
- **Gate G-1 Risk**: **Passed** ($< 95\%$ balanced accuracy threshold)
- Full details in [`ml/report/profile_D1.md`](ml/report/profile_D1.md).
