# PhishGuard

**On-Device ML-Based Phishing Detection & Prevention Chrome Extension (Manifest V3)**

PhishGuard is a Chrome extension project designed to detect and prevent phishing attempts using machine learning directly inside the browser. Its design goal is privacy-preserving, on-device URL analysis without transmitting browsing history or raw URLs to an external detection service.

---

## 🚀 Project Progress & Roadmap

The project is organized into 12 development chunks defined in PRD v2.0.

| # | Chunk | Scope / Deliverables | Status |
|---|---|---|---|
| 1 | **Spike & Scaffold** | Repository layout, MV3 extension scaffold, navigation race harness, frozen permissions | ✅ Complete |
| 2 | **Dataset Profile** | N-01 to N-13 normalizer, Mozilla PSL parser, dataset profiling, shortcut baseline audit | ✅ Complete |
| 3 | **Data Build** | D1 cleaning and domain-based splits; E1 structural dataset construction | ⚠️ Partial — D1 review and E1 verification pending; E2 blocked |
| 4 | **Normalization & Features** | FS1 feature extraction, 50-feature specification, implementation and unit tests | ✅ Complete |
| 5 | **Benchmark** | Model selection, cross-validation, performance metrics and benchmark evaluation | 🔄 Teammate-owned |
| 6 | **Calibration & Gates** | Threshold calibration and Gates G-1 to G-8, including adversarial evaluation | 📋 Queued |
| 7 | **Export** | Binary model packager (`model.bin`, `PGM1`), manifest and joblib oracle | 📋 Queued |
| 8 | **TypeScript Port** | On-device TypeScript runtime and Python/TypeScript parity tests (G-5) | 📋 Queued |
| 9 | **Extension Core** | Service-worker navigation pipeline, cache, allowlist and override flow | 📋 Queued |
| 10 | **User Interface** | Popup, options page, warning interstitial, about and history pages | 📋 Queued |
| 11 | **Hardening** | Performance target (<20 ms), CSP compliance, accessibility and security testing | 📋 Queued |
| 12 | **Release** | Final packaging, model card, user manual and unpacked Chrome demonstration | 📋 Queued |

### Current development notes

- D1 contains 11,000 URLs. Its original source, licence, collection date and labeling methodology remain unresolved.
- E1 has passed structural validation: 2,591 URLs across 866 registrable domains, with domain-separated training and holdout sets.
- E1 source permissions and benign-label verification remain pending.
- E2 has not been built because the D1 collection date is unknown.
- Chunk 5 benchmarking is being handled by a teammate.

---

## 📁 Repository Layout

```text
PhishGuard/
│
├── data/
│   └── PROVENANCE.md
│
├── docs/
│   ├── ASSUMPTIONS.md
│   ├── CONTRACTS.md
│   ├── PERMISSIONS.md
│   ├── PRD.md
│   ├── SPIKE_RESULTS.md
│   ├── CHUNK4_FEATURE_DOCUMENTATION.md
│   └── implementation/
│       ├── CHUNK3_IMPLEMENTATION_README.md
│       └── CHUNK3_REMAINING_README.md
│
├── extension/
│   ├── manifest.json
│   └── src/
│       ├── sw/
│       └── pages/
│
├── lists/
│   ├── psl.dat
│   ├── hosting.json
│   ├── shorteners.json
│   └── sensitive_words.json
│
├── ml/
│   ├── normalize.py
│   ├── psl.py
│   ├── profile.py
│   ├── build_dataset.py
│   ├── build_external.py
│   ├── collect_e1.py
│   ├── evaluate_e1.py
│   ├── features.py
│   ├── feature_spec.json
│   └── report/
│
├── tests/
│   ├── security/
│   ├── test_normalize_ut01.py
│   ├── test_build_dataset.py
│   ├── test_build_external.py
│   └── test_features_fs1.py
│
├── tools/
│   └── spike/
│       └── race_harness.py
│
├── requirements.lock
├── thresholds.json
├── pytest.ini
└── README.md
```

**Dataset note:** Raw and generated datasets are maintained locally. They are not included in the current GitHub commit because their source and redistribution permissions have not been fully verified.

---

## 🧪 Testing

Install dependencies from `requirements.lock` and execute:

```bash
python -m pytest -v
```

**Latest full local test result (16 November 2026):**

- Tests collected: 166
- Passed: 166
- Failed: 0

### Navigation Race Harness (FR-09)

The Playwright-based race harness completed 200 navigation runs.

| Metric | Result |
|---|---:|
| Total navigations | 200 |
| Cold navigations | 40/40 — 100% interstitial |
| Warm navigations | 160/160 — 100% interstitial |
| Overall interstitial rate | 100% |
| Target page committed | 0 |
| Playwright route interceptions | 197 |
| Route no-fetch | 3 |
| Verdict | PASS |

The route interception measurements use Playwright's in-memory route handling. They should not be interpreted as proof that no network request was initiated.

Detailed results: [`docs/SPIKE_RESULTS.md`](docs/SPIKE_RESULTS.md).

---

## 📊 Dataset Profile & Shortcut Baseline (Chunk 2)

| Metric | Result |
|---|---:|
| Total D1 URLs | 11,000 |
| Benign URLs | 6,500 |
| Malicious URLs | 4,500 |
| Exact duplicates | 152 |
| Normalized duplicates | 153 |
| Cross-class normalized duplicates | 0 |
| Shortcut baseline balanced accuracy | 85.26% |

The shortcut baseline remains below the 95% risk threshold specified for Gate G-1.

Detailed profile: [`ml/report/profile_D1.md`](ml/report/profile_D1.md).

---

## ⚠️ Data Provenance & Validation

Dataset provenance is documented in [`data/PROVENANCE.md`](data/PROVENANCE.md).

The following items remain open:

- D1 original source, licence, collection date and labeling methodology.
- Independent D1 label spot-check (200-row sample).
- E1 source-term and benign-label verification.
- E2 fresh phishing dataset construction.

Unknown provenance information is explicitly marked as unknown rather than assumed or fabricated.

---

## 👥 Development

Development is divided across the 12 chunks in PRD v2.0. Chunk 3 data engineering and Chunk 4 feature engineering have been committed to the `main` branch. Chunk 5 benchmarking is teammate-owned.

