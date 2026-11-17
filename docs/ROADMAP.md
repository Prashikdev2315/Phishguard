# PhishGuard Project Progress & Roadmap

**Project:** PhishGuard — On-Device ML-Based Phishing Detection & Prevention Chrome Extension (Manifest V3)  
**Version:** 0.1.0 (MV3)  
**Last Updated:** November 2026  

---

## 📊 Development Roadmap & Status Overview

| Chunk | Title | Scope & Deliverables | Status |
|:---:|:---|:---|:---:|
| **1** | **Spike & Scaffold** | Repository structure, Manifest V3 manifest, permission lockdown (SC-01), navigation race harness stub. | ✅ Complete |
| **2** | **Dataset Profile** | Normalizer (N-01 to N-13), Mozilla Public Suffix List (PSL) parser, exploratory data analysis, shortcut baseline. | ✅ Complete |
| **3** | **Data Build** | Cleaned D1 dataset (9,677 samples, 80/20 domain-grouped split, 0 leakage), 5-fold CV splits, E1 ingestion pipeline. | ✅ Complete |
| **4** | **Normalization & Features** | 50 ordered lexical/structural features (FS1), IDN/punycode resolution, Shannon entropy, unit test coverage. | ✅ Complete |
| **5** | **Benchmark** | 25-run benchmark (5 selectors × 5 classifiers across 3 seeds × 5 folds), leakage guards, model selection, G-1 & G-4 gates. | ✅ Complete |
| **6** | **Calibration & Gates** | Probability calibration, threshold selection, robustness checks, G-1 to G-8 gate validations. | ✅ Complete |
| **7** | **Model Export** | Binary model packager (`PGM1` format, `model.bin`), manifest generation, joblib parity oracle. File size < 2 MiB. | ✅ Complete |
| **8** | **TypeScript Port** | Pure TypeScript feature extraction & tree evaluation runtime. Float64 scaling, `Math.fround` float32 parity (G-5). | ✅ Complete |
| **9** | **Extension Core** | MV3 background service worker, navigation interceptor (`webNavigation`), LRU/TTL cache, tokenized interstitial redirect, 30-min override. | ✅ Complete |
| **10** | **User Interface** | Popup UI (risk meter & trigger reasons), Options page (allowlist & hosting root rejection), Warning Interstitial, First-run onboarding. | ✅ Complete |
| **11** | **Hardening** | Performance budgeting (< 20 ms warm inference), CSP compliance verification, accessibility & edge cases. | 📋 Queued |
| **12** | **Release** | Final packaging, model card, user manual, and unpacked Chrome store package. | 📋 Queued |

---

## 🎯 Detailed Chunk Status & Achievements

### Chunk 1–4: Foundations & Data Pipeline
- **Dataset (D1)**: 9,677 deduplicated URLs (6,170 Benign, 3,507 Malicious) partitioned strictly by registrable domain (80% train / 20% test, 0 overlap).
- **Features (FS1)**: 50 deterministic features extracted entirely client-side without remote DNS/WHOIS queries.
- **Security (SC-01)**: Frozen minimal permissions (`storage`, `webNavigation`, `alarms`), zero `eval`, zero remote scripts, strict CSP (`script-src 'self'`).

### Chunk 5–7: Model Selection, Calibration & Export
- **Best Model**: `RandomForestClassifier` with `rf_importance` feature selection. Holdout balanced accuracy: **90.68%** (5-fold CV: 0.9123 ± 0.0111).
- **Exported Binary (`model.bin`)**: Custom `PGM1` binary format packed into **1.59 MB** (well under the 2 MB PRD limit).
- **Calibration**: Isotonic regression calibration mapped to 4 explicit risk bands: Safe (0–29), Low-Risk (30–49), Suspicious (50–69), and High-Risk (70–100).

### Chunk 8: TypeScript Parity (Gate G-5)
- **Remediation**: Scaler parameters exported in float64; scaling arithmetic executed in float64 and rounded with `Math.fround()` before tree split comparisons.
- **Parity Result**: **0 differing URL classifications** between Python joblib oracle and TypeScript runtime across all cleaned D1 test splits and hostile fixtures.
- **Test Suite**: 187/187 Pytest unit tests passing; 8/8 Vitest unit tests passing at original strict tolerances.

### Chunk 9: Extension Core & E2E-10 Race Harness
- **Service Worker**: MV3 service worker implementing `webNavigation.onBeforeNavigate` interception.
- **Race Harness**: Real Chromium Playwright evaluation (`tools/spike/race_harness.py`) across 200 navigations (40 cold, 160 warm):
  - **Interstitial rate**: **100.0%** (200/200, meeting the ≥ 99% gate).
  - **Target page committed**: **0** (0%).
  - **Cold start p95**: **47.0 ms** (under 150 ms budget).
  - **Override Flow**: Opaque cryptographically random token with 30-minute expiration on the exact URL.

### Chunk 10: User Interface
- **Popup (`popup.html` & `popup.js`)**: Real-time risk badge, score meter, trigger explanation chips, "Trust this site" action, and "Copy report" button.
- **Options (`options.html` & `options.js`)**: Enforcement mode toggle (`warn_only` vs `block`), failure mode toggle (`open` vs `closed`), allowlist management with multi-tenant hosting root rejection (e.g. `github.io` blocked, `tenant.github.io` allowed), cache & history controls.
- **Warning Interstitial (`warning.html` & `warning.js`)**: Red warning page with IDN homoglyph display, human-readable reason breakdown, fail-closed diagnostic banner, and 30-minute override bypass.
- **First-Run Onboarding (`first_run.html` & `first_run.js`)**: Privacy-first onboarding screen explaining local model execution and setting initial protection level.
- **Compliance**: Zero inline scripts, strict CSP (`script-src 'self'`), zero `innerHTML` (all DOM operations strictly use `textContent` and `createElement`). Verified via `tools/test_chunk10_ui_validation.py`.

---

## 🔮 Next Milestones

### Chunk 11: Hardening & Performance Optimization
- [ ] Measure end-to-end memory footprint of the service worker in long-running tabs.
- [ ] Profile and enforce < 20 ms warm inference p95 across 1,000 synthetic navigations.
- [ ] Automated accessibility audit (WCAG AA compliance for Popup, Options, and Warning pages).
- [ ] Edge-case fuzzing against malformed URLs, huge query strings, and data URLs.

### Chunk 12: Release & Documentation
- [ ] Final production extension packaging (`.zip` for Chrome Web Store / developer distribution).
- [ ] Publish comprehensive Model Card and Dataset Provenance sheets.
- [ ] User Manual and developer documentation.
- [ ] Demonstration video and test walkthrough.
