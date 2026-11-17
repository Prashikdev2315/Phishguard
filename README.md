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
| 3 | **Data Build** | D1 cleaning, domain-based splits (80/20 grouped), cross-validation folds, E1 pipeline | ✅ Complete |
| 4 | **Normalization & Features** | FS1 feature extraction, 50-feature specification, implementation and unit tests | ✅ Complete |
| 5 | **Benchmark** | 25-run benchmark (5 selectors × 5 classifiers, 3 seeds × 5 folds), leakage guards, model selection, Gate G-1 & G-4 evaluation | ✅ Complete |
| 6 | **Calibration & Gates** | Threshold calibration and Gates G-1 to G-8, including adversarial evaluation | ✅ Implemented; external evidence pending |
| 7 | **Export** | Binary model packager (`model.bin`, `PGM1`), manifest and joblib oracle | ✅ Complete |
| 8 | **TypeScript Port** | On-device TypeScript runtime and Python/TypeScript parity tests (G-5) | ✅ Complete |
| 9 | **Extension Core** | Service-worker navigation pipeline, cache, allowlist and override flow | ✅ Complete |
| 10 | **User Interface** | Popup, options page, warning interstitial, about and history pages | ✅ Complete |
| 11 | **Hardening** | Performance target (<20 ms), CSP compliance, accessibility and security testing | 📋 Queued |
| 12 | **Release** | Final packaging, model card, user manual and unpacked Chrome demonstration | 📋 Queued |

### Current development notes

- Cleaned D1 dataset generated: 9,677 rows (6,170 Benign, 3,507 Malicious) across 80/20 domain-grouped splits (7,781 train / 1,896 test) with 0 domain overlap.
- Chunk 5 25-run benchmark completed: shortcut baseline is 84.25% balanced accuracy; Gate G-1 passed (+6.43 pp margin) and Gate G-4 passed (<1.2 pp gap).
- Current D1 benchmark metadata selects `l1_lr` × RandomForest (hold-out balanced accuracy 87.5794%, grouped CV balanced accuracy 86.2385%). The older 90.68% `rf_importance` result is retained only as a historical report and is not the active model.
- Chunk 6 calibration is implemented in `ml/evaluate.py`; the generated report is `ml/report/calibration_D1.md`.
- Chunk 7/8 export generated as a 1,591,036-byte PGM1 binary artifact (`model.bin`) with float64 scaler parameters and float32 threshold encoding, remaining well under the 2 MiB budget.
- Chunk 8 G-5 parity remediation complete: TypeScript runtime matches Python oracle across all D1 and hostile fixtures with 0 differing predictions. Both Pytest (187/187 tests) and Vitest (8/8 tests) pass cleanly at original tolerances.
- Chunk 9 Extension Core & E2E-10 race harness complete: Service worker navigation pipeline, LRU/TTL cache, and 30-min token-bound override flow verified in real Chromium. E2E-10 race harness achieved 200/200 navigations intercepted (100.0% interstitial rate, 0 target page commits, cold-start p95 = 47.0 ms), documented in `docs/SPIKE_RESULTS.md`.
- Chunk 10 User Interface complete: Popup with real-time risk meter and trigger reasons, Options page with allowlist management and multi-tenant hosting root rejection (FR-08), Warning Interstitial with fail-closed support, and First-run onboarding page. All UI code adheres to strict CSP (`script-src 'self'`) with zero remote dependencies and zero `innerHTML`. Verified with Playwright UI test suite (`tools/test_chunk10_ui_validation.py`).

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
│   └── public/
│       └── model.bin
│   └── src/
│       ├── sw/
│       └── pages/
│   └── dist/                 # generated esbuild bundles
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
│   ├── export.py
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

**Latest local validation:**

- TypeScript typecheck: passed.
- Vitest: 5 passed.
- esbuild extension bundle: passed.
- Exhaustive G-5: failing; maximum observed risk difference remains 94 against the active scikit-learn/joblib environment.

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

