# PhishGuard: ML-Based Phishing Detection & Prevention Chrome Extension

**Product Requirements Document, v2.0** (revises v1.0) · Target: Chrome, Edge, Brave (Manifest V3, Chromium 120+) · Status: ready for build, gated by the M0 spike and the M1 data checks

## 0. What changed from v1.0

v1.0 was thorough, but it rested on a dataset whose classes could be separated by trivial shortcuts, it required a backend that real users cannot run, and it carried 34 functional requirements for an MVP. v2.0 keeps the strong parts (URL-only features, Python/TypeScript parity, graded response, privacy stance) and fixes the gaps.

| Area | v1.0 | v2.0 | Why |
| --- | --- | --- | --- |
| Training data | One file, random 80/20 split, goal of matching the paper's 98.8% | Primary dataset plus external evaluation sets, domain-grouped splits, honest release gates | Shortcut-separable data makes random-split accuracy meaningless |
| Class balance | 2,500 / 2,500 | About 2:1 benign to malicious (reported \~4,001 / \~2,000, to be re-measured) | Imbalance must be handled in training and in metrics |
| WHOIS and backend | Required for stage 2 | Moved to v1.1 as optional; v1 runs fully on device | Users cannot run a backend; WHOIS for old URLs is time-skewed |
| Scope | 34 FRs, 7 screens, 14 documents | 23 FRs, 4 screens plus a first-run page, one master document | A shippable MVP |
| Enforcement | Always block at risk ≥ 70 | Block only if the false-positive gate passes; otherwise warn-only | Protects users from false blocks while evidence is thin |
| Blocking claim | Target page is never rendered | Measured target using a spike harness (FR-09) | MV3 has no blocking webRequest, so the claim must be tested |
| Explanations | Undefined (KNN has no native attributions) | Deterministic reason codes (section 6.4) | Users need plain-language reasons |
| Gaps filled |  | Full feature list, normalization rules, public-suffix handling, calibration procedure, model file format, UI copy, threat table, milestones, repo layout |  |

**Dataset note.** The team reports a primary dataset of about 4,001 benign and 2,000 malicious URLs. v1.0 profiled a different-sized file (5,000 rows, 2,500 / 2,500). Every count and shortcut statistic must be re-measured on the actual training file by `ml/profile.py` and recorded in `data/PROVENANCE.md` during M0. Nothing in this PRD depends on the exact counts except the imbalance handling in section 7.4.

## 1. Product overview

### 1.1 Problem

Zero-hour phishing URLs evade blacklists because they are new. Content-based detectors fetch the page first, which adds latency and exposes the user to the threat before the verdict. PhishGuard classifies the URL string before the page is trusted, entirely on the user's device, and responds with a graded warning.

### 1.2 Goals

- G1: Score every top-level http(s) navigation on-device in under 30 ms (warm).
- G2: Block high-confidence phishing with a plain-language interstitial, and always let the user override.
- G3: Keep false blocks rare and recoverable (allowlist, override, warn-only fallback).
- G4: Report results honestly: domain-grouped splits, external sets, confidence intervals, and a shortcut baseline beside every headline metric.
- G5: Send zero URLs off the device in v1.

### 1.3 Non-goals (v1)

Page-content or DOM analysis, iframe scanning, email or SMS scanning, multi-class labels, online learning, mobile or non-Chromium browsers, remote model updates, user blocklists, managed enterprise policy, third-party reputation APIs, and cancelling form submits.

### 1.4 Success metrics

| Metric | Target | Measured by |
| --- | --- | --- |
| Malicious recall, domain-grouped hold-out | ≥ 90% | ML-04 (G-2) |
| Recall on fresh phishing feed (E2) | ≥ 80% | ML-07 (G-2) |
| Block FPR on benign deep-link hold-out (E1), allowlist off | ≤ 0.5% point estimate, 95% interval reported | ML-07 (G-3) |
| Margin over shortcut baseline | ≥ 5 pp balanced accuracy | ML-04 (G-1) |
| Warm end-to-end latency | < 30 ms p95 | PF-01 |
| Outbound requests during normal use | 0 | SC-05 |
| Interstitial shown before target commits | ≥ 99% of 200 test navigations | E2E-10 |

These targets are initial. Re-baseline them after the first honest benchmark (M2) and record any change in the change log (section 15).

## 2. Users and stories

- **P1 Everyday user (Meera, 34):** shops and banks online; wants protection without jargon and with few false alarms.
- **P2 Evaluator (Dr. Rao, 29):** instructor or security reviewer; wants reproducible results, a model card, and honest limits.
- **P3 Cautious professional (Arjun, 41):** clicks invoice and email links; wants predictable warnings, a strict mode, and an easy way to report mistakes.

| ID | Story |
| --- | --- |
| US-1 | As P1, I want safe sites to load untouched so protection is invisible. |
| US-2 | As P1, I want a clear warning with a one-click way back when a site looks like phishing. |
| US-3 | As P1, I want to trust a site I know when the extension is wrong. |
| US-4 | As P3, I want a strict mode that stops me when the extension cannot decide. |
| US-5 | As P3, I want to copy a problem report without anything being sent automatically. |
| US-6 | As P2, I want a model card with version, hash, features, metrics, and limits. |
| US-7 | As P2, I want to rerun training and get identical results from the same seed. |
| US-8 | As any user, I want to clear all stored data in one click. |

## 3. Release plan

| Release | Contents |
| --- | --- |
| **v1 (MVP)** | On-device URL model (51 features), allowlists, badge, popup, High-Risk interstitial with override, settings, local history, about/model card, first-run page, offline training and benchmark pipeline, optional reference API |
| **v1.1** | Optional WHOIS enrichment through a local backend (second-stage model) and the WHOIS ablation, in-page banner polish, local stats view, one-click FP/FN report through an issue template, batch API |
| **v2** | Lightweight DOM signals (password field on an unfamiliar domain, form-action mismatch, brand or favicon mismatch), blocklist updates shipped with releases, Firefox, managed policy |

## 4. How detection works

1. **Navigation event.** `webNavigation.onBeforeNavigate` (frameId 0). Listeners are registered synchronously at the top level of the service worker so they survive restarts.
2. **Pre-filter.** Only http and https are scanned. Browser pages, extension pages, file, data, blob, about, and loopback or private-network hosts are skipped.
3. **Normalize** the URL (6.1) and build the cache key.
4. **Short-circuit** in this precedence: active override, user allowlist, default allowlist, cache hit.
5. **Score.** Extract 51 features (6.2), scale, keep the selected Top-k, run the model, calibrate to a probability p, and set risk = round(100 × p).
6. **Classify.** Safe < 35, Suspicious 35-69, High-Risk ≥ 70 (defaults; final cut-offs are set by the procedure in 7.6).
7. **Act.** Safe: badge OK. Suspicious: badge `!`, detail in the popup, optional in-page banner. High-Risk: interstitial when enforcement is `block`; banner and badge when it is `warn_only`.
8. **Record.** Cache the verdict, update counters, and write a history row (host only) unless the window is incognito.
9. **Redirects.** Every hop is scanned as its own navigation, linked by a parent token, with a depth cap of 10.

**MV3 engineering notes**

- There is no `webRequestBlocking`. The interstitial is applied with `tabs.update` to an extension page right after the verdict. The request may already be in flight, so the guarantee is measured, not assumed (FR-09, M0 spike).
- The service worker is ephemeral. The model loads from the packaged `model.bin` on wake and parsed arrays are cached in module scope. Cold start counts toward the latency targets.
- Per-tab state lives in `storage.session`, not only in module variables.
- v1 has no asynchronous enrichment, so a verdict is never retroactively upgraded: one navigation, one verdict.

## 5. Functional requirements

P0 must ship, P1 should ship, P2 is optional. Every requirement has an acceptance criterion (AC) and test IDs defined in section 12.

| ID | Pri | Requirement | Acceptance criterion | Tests |
| --- | --- | --- | --- | --- |
| FR-01 | P0 | **Scan trigger.** One pipeline run per top-level navigation; ignore subframes and restricted schemes. | One run per navigation; subframes, chrome://, extension, file, data, blob, about, and loopback pages are never scanned. | UT-01, E2E-05 |
| FR-02 | P0 | **URL normalization** by rules N-01 to N-12 (6.1). | Python and TypeScript outputs are identical for every dataset URL and every table case, including the dataset's anomalous rows. | UT-01, PAR-01 |
| FR-03 | P0 | **Feature extraction:** the 51 URL features in frozen order (6.2). | Hand-computed vectors match; a non-finite value yields `feature_error`; Python and TypeScript agree within 1e-6. | UT-02, PAR-01 |
| FR-04 | P0 | **Local inference:** scale, select Top-k, classify, calibrate, risk 0-100. | Matches the Python oracle within 1 risk point on all dataset URLs; inference p95 < 15 ms warm. | PAR-02, PF-01 |
| FR-05 | P0 | **Risk bands and enforcement mode** (`block` or `warn_only`); the default mode is set by gate G-3. | Boundaries 34/35/69/70 are correct; in `warn_only` a High-Risk page gets banner and badge, never the interstitial. | UT-03, E2E-02, E2E-04 |
| FR-06 | P0 | **Reason codes:** up to 3 plain-language signals from deterministic rules (6.4). | Each rule fires on its trigger fixture and not on its negatives; a generic reason shows when no rule fires. | UT-06 |
| FR-07 | P0 | **Result cache** keyed by hash; TTL Safe 24 h, Suspicious 6 h, High-Risk 1 h; cap 2,000 (LRU); cleared on model version change. | Hit path < 5 ms; eviction and TTL correct; survives service-worker restart; no raw URL stored. | UT-04, E2E-06, SC-06 |
| FR-08 | P0 | **Allowlists:** bundled default list (7.2) and a user list; hosting platforms are never allowlistable at domain level. Precedence: override > user > default > model. | Precedence verified; allowlisting a multi-tenant host trusts only that tenant host. | UT-05, E2E-08 |
| FR-09 | P0 | **High-Risk interstitial** (`warning.html`) via `tabs.update` before the target renders; true host shown in Unicode and punycode. | Block-race harness: ≥ 99% of 200 mixed cold and warm navigations show the interstitial with no committed target document; residual failures documented. | E2E-02, E2E-10, SC-03 |
| FR-10 | P0 | **Proceed-anyway override:** behind a disclosure, risk checkbox, ≥ 1 s delay, trusted click; scoped to the exact URL for 30 min; logged locally. | Scope is the exact URL key; scripted (untrusted) clicks are rejected; entry is logged. | E2E-03 |
| FR-11 | P1 | **Suspicious handling:** page loads, badge `!`, detail in popup; optional in-page banner (closed Shadow DOM) when host access is granted. | Banner appears only when enabled and permitted; never blocks; never reads page content. | E2E-04 |
| FR-12 | P0 | **Redirects and multi-tab:** per-tab monotonic token, results applied only if the token is current, 500 ms duplicate collapse, SPA history updates scanned once. | Stale results are dropped; parallel tabs are independent; chain depth capped at 10. | E2E-05 |
| FR-13 | P0 | **Failure policy:** `failureMode` open (default) or closed; error states `model_corrupt`, `feature_error`, `url_too_long`, `unsupported`. | Open: page loads, grey `?` badge. Closed: neutral 'could not verify' interstitial with go-back and proceed. All 4 errors × 2 modes pass. | E2E-07 |
| FR-14 | P0 | **Model loading and integrity:** SHA-256 check against the manifest, schema and version check, version shown in the UI. | A corrupt, missing, or mismatched file triggers `model_corrupt` handling and never crashes the worker. | UT-07, E2E-07 |
| FR-15 | P0 | **Popup (360×520):** status band, risk, up to 3 reasons, Trust this site, Copy report, Open settings; five states (loading, safe, suspicious, high-risk, unscanned or error). | All five states render; keyboard operable; axe reports no serious or critical issues. | E2E-01 to E2E-04, AX-01 |
| FR-16 | P0 | **Settings page:** enforcement mode, failure mode, banner toggle, allowlist editor, history viewer, clear history, clear cache, clear all. | Validation rules enforced; each clear action leaves the matching storage empty. | UT-08, E2E-08, SC-06 |
| FR-17 | P1 | **About and model card:** model version, schema, hash, feature list, training-data summary, latest benchmark and gate results, known limits. | Values are read from shipped artifacts, never hard-coded. | E2E-11 |
| FR-18 | P1 | **First-run page:** what it does, permissions, enforcement mode, optional host-access request. | Shown once on install; a short 'What's new' note on update. | E2E-11 |
| FR-19 | P1 | **Local history:** host, band, risk, action, time; cap 500 rows, 30-day retention, daily purge; nothing written in incognito. | No path, query, or fragment is stored; purge verified. | E2E-08, E2E-09, SC-06 |
| FR-20 | P0 | **Training and evaluation pipeline:** 5 selectors × 5 classifiers (25 runs), grouped CV, calibration, gates, auto-generated report. | One command reproduces all outputs; the same seed gives identical metrics; every headline metric is shown with its grouped-split and shortcut-baseline counterpart. | ML-01 to ML-07 |
| FR-21 | P0 | **Model export and parity:** `model.bin`, manifest, joblib oracle. | Risk difference ≤ 1 point on 100% of dataset URLs (G-5). | PAR-02, UT-07 |
| FR-22 | P0 | **Dataset profiling, cleaning, and build** (7.1 to 7.3). | Dedupe, per-domain cap, and shortcut audit run and are recorded in `PROVENANCE.md`. | ML-01, ML-08 |
| FR-23 | P2 | **Reference API** `POST /predict` (developer tool for parity checks and demos). | Returns the same risk as the extension for the same URL. | API-01 |

## 6. Detection engine specification

### 6.1 URL normalization (N-01 to N-12)

| Rule | Behavior |
| --- | --- |
| N-01 | Trim leading and trailing whitespace, including U+00A0 and a BOM. Reject the URL if whitespace remains inside. |
| N-02 | If there is no scheme, prepend `http://` (the dataset contains scheme-less rows). |
| N-03 | Lowercase the scheme and host. Keep path and query case. |
| N-04 | Convert the host to punycode (IDNA). Keep the Unicode form for display. |
| N-05 | Remove a trailing dot from the host and drop default ports (80 for http, 443 for https). |
| N-06 | Resolve `.` and `..` path segments. Do nothing else to the path. |
| N-07 | Detect IP hosts: IPv6 literals, dotted decimal, and hex, octal, or integer forms. Flag them; never resolve them. |
| N-08 | Features use the full URL including fragment. The cache key drops the fragment, and the fragment is never stored. |
| N-09 | Strip known tracking parameters (`utm_*`, `fbclid`, `gclid`, `msclkid`) for the cache key only. Features use the full query. |
| N-10 | Keyword matching uses a percent-decoded, lowercased copy. Length and character counts use the raw normalized string. |
| N-11 | Extract the registrable domain with one pinned Public Suffix List snapshot that includes the private section, so tenant hosts such as `x.github.io` count as separate registrable domains. The same file ships in Python and TypeScript. |
| N-12 | URLs longer than 2,048 characters are not scored (`url_too_long`); the failure policy applies. |

### 6.2 Features (51)

The order is frozen under schema `fs1`. The list lives in one spec file from which `features.py` and `features.ts` are generated, so the two implementations cannot drift. The 5 optional WHOIS features (v1.1) bring the total to 56.

| Group | Count | Features |
| --- | --- | --- |
| A. Length and structure | 17 | url\_length, hostname\_length, path\_length, query\_length, fragment\_length, tld\_length, subdomain\_count (www excluded), path\_depth, query\_param\_count, dot\_count, hyphen\_count, underscore\_count, at\_symbol\_count, double\_slash\_in\_path, non\_default\_port, is\_https, has\_ip\_host |
| B. Character composition | 10 | digit\_count, digit\_ratio, letter\_ratio, uppercase\_ratio, special\_char\_count, special\_char\_ratio, percent\_encoded\_count, equals\_count, ampersand\_count, tilde\_count |
| C. Lexical and keyword | 7 | sensitive\_word\_count, action\_word\_count, keyword\_in\_host, keyword\_in\_path, brand\_in\_subdomain\_or\_path, is\_url\_shortener, is\_free\_hosting |
| D. Host and domain | 8 | registrable\_domain\_length, domain\_hyphen\_count, domain\_digit\_count, is\_punycode, mixed\_script\_host, suspicious\_tld, longest\_subdomain\_label, embedded\_url\_in\_path\_or\_query |
| E. Statistical | 9 | url\_entropy, host\_entropy, path\_entropy, query\_entropy, distinct\_char\_ratio, max\_digit\_run, max\_consonant\_run, host\_bigram\_distinct\_count, host\_trigram\_distinct\_count |
| F. WHOIS (v1.1, optional) | 5 | whois\_available, domain\_age\_days, registration\_length\_days, recent\_domain (under 180 days), whois\_private |

**Definitions and rules**

- Entropy is Shannon entropy in base 2 over the relevant substring, and 0 for an empty substring. Ratios divide by total URL length, and are 0 for an empty URL.
- For IP hosts, domain-based features take documented constants (stored in the spec file).
- Word lists (sensitive words, action words, brands, shorteners, hosting platforms) are versioned data files under `lists/`, shared by Python and TypeScript. The sensitive-word seed is: login, signin, verify, secure, account, update, password, confirm, banking, wallet. The brand list (top impersonated brands) must be compiled by the team from public phishing reports; the dataset does not provide it.
- `suspicious_tld` is data-driven: a TLD qualifies only if at least 80% of its training rows are malicious across at least 20 distinct registrable domains. This keeps a single host from defining a TLD as suspicious.
- **Shortcut-prone features** (url\_length, path\_length, is\_https, is\_free\_hosting, suspicious\_tld) are kept but evaluated in a no-shortcut-features ablation. The production model must still pass gate G-1.
- Drop any feature that is constant for at least 99% of training rows.

### 6.3 Scoring

risk = round(100 × p), where p is the calibrated probability of Malicious. Bands are Safe < 35, Suspicious 35-69, High-Risk ≥ 70. Allowlisted or overridden URLs are not scored and show risk as n/a.

### 6.4 Reason codes

KNN has no native attributions, so reasons are deterministic rules over the features. They explain visible signals; they are not a decomposition of the model's score, and the model card says so. The popup and interstitial show up to 3 reasons, ordered by severity. If the score is ≥ 35 and no rule fires, the generic reason is shown.

| Code | Trigger | User-facing text |
| --- | --- | --- |
| R-01 IP\_HOST | has\_ip\_host = 1 | This address uses a raw number instead of a website name. |
| R-02 BRAND\_MISMATCH | brand\_in\_subdomain\_or\_path = 1 and the registrable domain is not that brand's | The name of a well-known company appears here, but the site is not that company. |
| R-03 SENSITIVE\_WORDS | sensitive\_word\_count ≥ 2 | The address contains words like login, verify, or password. |
| R-04 LONG\_URL | url\_length ≥ the 95th percentile of benign training URLs (stored in the manifest) | This address is unusually long. |
| R-05 DEEP\_SUBDOMAINS | subdomain\_count ≥ 4 or longest\_subdomain\_label ≥ 25 | The address has an unusual number of sections before the main name. |
| R-06 SUSPICIOUS\_TLD | suspicious\_tld = 1 | The ending of this address is common on malicious sites. |
| R-07 HOMOGRAPH | is\_punycode = 1 or mixed\_script\_host = 1 | The name uses look-alike characters that can imitate another site. |
| R-08 FREE\_HOSTING | is\_free\_hosting = 1 | This page is on a free hosting service that attackers often abuse. |
| R-09 EMBEDDED\_URL | at\_symbol\_count ≥ 1 in the authority, or embedded\_url\_in\_path\_or\_query = 1 | This address contains another web address inside it. |
| R-10 NO\_HTTPS | is\_https = 0 and sensitive\_word\_count ≥ 1 | This page asks for sensitive actions without encryption. |
| R-11 RANDOM\_HOST | host\_entropy ≥ the 95th percentile of benign training hosts | The site name looks randomly generated. |
| R-00 GENERIC | none of the above, risk ≥ 35 | The overall pattern resembles known phishing addresses. |

## 7. Machine learning specification

### 7.1 Data sources

| Set | Role | Content | Rules |
| --- | --- | --- | --- |
| **D1** primary dataset | Train, validate, test | About 4,001 benign and 2,000 malicious URLs (re-measure) | Clean per 7.2; domain-grouped splits |
| **E1** benign deep links | Half joins training, half is the FPR hold-out; split by domain | At least 2,000 URLs from at least 800 domains: Tranco-ranked sites with 1 to 3 real inner-page URLs each, from sitemaps or crawled links | Built by the team; record date and method. Adding E1 to training breaks the 'has a path means phishing' shortcut |
| **E2** fresh phishing | Temporal recall check; never trained on | At least 500 verified phishing URLs from PhishTank or OpenPhish, collected after D1's collection date | Check the feed's terms; remove any domain already in D1 |
| **E3** malware stress set (the second dataset) | Recall on malware-style URLs only | 428 benign and about 23k malware | Never used for training or threshold selection; the benign side is too small to report |

### 7.2 Cleaning and audit (FR-22)

1. Normalize (6.1) and drop exact and normalized duplicates.
2. Cap rows per registrable domain at max(50, 1% of the class) so that a few hosts, such as one free-hosting site, cannot dominate. Record the dropped counts.
3. Validate labels by spot-checking 100 random rows per class and logging the error rate. Decide here whether malware-style rows stay in the malicious class or are filtered out (open decision D-3).
4. **Shortcut audit.** Train a depth-2 decision tree on length, has\_path, https, and TLD only. Its grouped-split balanced accuracy is the shortcut baseline. If the baseline is ≥ 95%, stop and rebalance (add E1 to training) before any model work.
5. **Concentration report.** Top 20 registrable domains per class, and the share of each class that is a bare homepage.
6. Record source, terms of use (O-01), collection dates, counts before and after each step, and the final file hash in `data/PROVENANCE.md`.

**Default allowlist.** A pinned snapshot (date recorded) of the top 5,000 Tranco-ranked registrable domains, minus hosting platforms, URL shorteners, and any domain that appears as malicious in D1. It should stay under 100 KB.

### 7.3 Splits and leakage rules

- The group key is the registrable domain. An 80/20 grouped hold-out split is locked and evaluated once per candidate set.
- Selection and tuning use 5-fold StratifiedGroupKFold on the training portion, repeated with 3 seeds (42 plus two more).
- **Leakage rule.** The scaler, selector, classifier, and calibrator are fit inside each training fold through a single pipeline. Nothing is fit on validation or test data. ML-01 asserts zero group overlap and checks that fitted statistics change when the training fold changes.
- A random stratified split is reported next to the grouped split. Their gap is gate G-4.
- Library versions are pinned in a lockfile.

### 7.4 Class imbalance

- Stratify every split. Use `class_weight=balanced` for LR, RF, and SVM, and prior-corrected weighted voting for KNN. Do not oversample before splitting.
- Headline metrics are balanced accuracy, recall, FPR, PR-AUC, and MCC. Accuracy is reported but never used for selection.
- Real browsing is overwhelmingly benign, so precision on D1 overstates deployment precision. Report expected false blocks per user per month = block-FPR × monthly navigations. Illustration only: 0.5% of 3,000 navigations is 15 events if nothing were allowlisted. That is why G-3 is measured with the allowlist off (worst case) and reported again with it on.

### 7.5 Experiments

- **Selectors (5):** RF importance, Chi-square (on min-max scaled features), mutual information, L1 (L1 logistic regression, C = 0.1), RFE (RF base estimator, 200 trees). Top-k = 20 is primary, with sensitivity runs at k = 10, 15, 30, and all 51.
- **Classifiers (5):** KNN (odd k from 3 to 25, distance-weighted), RF, SVM (RBF, grid over C and gamma), LR (L2), Gaussian NB. An optional extra baseline is histogram gradient boosting, for reference only.
- **Runs:** 25 combinations × 5 folds × 3 seeds. Metrics: accuracy, balanced accuracy, precision, recall, F1, F2, FPR, FNR, ROC-AUC, PR-AUC, MCC, Brier score, ECE, model size, and per-URL inference latency (Python and exported JavaScript). The Top-20 list is saved for every combination.
- **Comparison:** mean and standard deviation across folds, then a paired bootstrap on the hold-out for the top 3 before naming a winner.
- **WHOIS ablation** moves to v1.1. The harness accepts an optional feature block, so no redesign is needed.
- **Paper reference.** Khedekar and Pawar (2026) inspired the methodology. The figures quoted in v1.0 (about 98.8% accuracy) came from the project brief and are unverified here. They are not targets.

### 7.6 Calibration and thresholds

1. KNN probability is the weighted neighbour vote. When generating calibration data, exclude each training point from its own neighbour list (leave-one-out). Otherwise probabilities collapse to 0 or 1.
2. Fit Platt scaling (or isotonic regression if there are at least 1,000 calibration points and it improves ECE) on out-of-fold predictions only.
3. Report Brier score, ECE, and a reliability plot.
4. Choose T\_block on the validation folds as the lowest threshold that meets the block-FPR target on the validation portion of E1, then freeze it and evaluate once on the hold-out. Choose T\_warn for recall ≥ 90% with an FPR cap of 5%, since warnings do not block.
5. The cut-offs 35 and 70 are defaults. If calibration moves the best values, change them in one place (`thresholds.json`) and log the change.

### 7.7 Release gates

| Gate | Pass rule | If it fails |
| --- | --- | --- |
| G-1 Shortcut margin | Grouped-test balanced accuracy exceeds the shortcut baseline by ≥ 5 pp | Rebalance data (7.2); do not ship |
| G-2 Recall | ≥ 90% on the D1 grouped hold-out and ≥ 80% on E2 | Iterate on features and data; do not ship |
| G-3 Block FPR | ≤ 0.5% point estimate on the E1 hold-out with the allowlist off; 95% Wilson interval reported | Default enforcement becomes `warn_only` |
| G-4 Generalization gap | Random-split minus grouped-split accuracy ≤ 5 pp | Investigate leakage and shortcuts |
| G-5 Parity | Python and TypeScript risk within 1 point on 100% of dataset URLs and golden vectors | Block the release |
| G-6 Performance | Inference p95 < 15 ms warm; end-to-end < 30 ms warm; cold start < 150 ms | Shrink the model (fewer neighbours or samples, or switch to LR) |
| G-7 Calibration | ECE ≤ 0.05, Brier score reported | Recalibrate; if unresolved, narrow the Safe and Suspicious bands |
| G-8 Robustness | Recall on the adversarial suite drops ≤ 10 pp versus clean | Add features or augmentation, or document the limit in the model card |

**Adversarial suite (ML-06).** Transforms applied to malicious test URLs: (a) append benign-looking path or query tokens, (b) prepend a popular brand as a subdomain, (c) move to a free-hosting host, (d) insert hyphens and digits in the domain, (e) substitute look-alike characters, (f) change the path length to benign-typical values.

### 7.8 Production model selection and export

- **Selection rule.** Among candidates that pass G-1 to G-4 on the grouped folds, pick the highest recall at the block-FPR target. Ties go to the smaller, faster, simpler model. RFE + KNN is preferred (as in the original brief) when it is within 1 pp of the best.
- **Export (FR-21).** The shipped RF finalist is exported by `python -m ml.export` to `extension/public/model.bin`. The file uses the frozen PGM1 wire format: a canonical JSON header followed by a level-9 zlib payload containing the 50-value MinMax scaler arrays, 20 selected feature indices, and all 200 packed forest trees. Each tree stores node count, child indices, split features, thresholds, and float32 malicious-leaf probabilities. `ml/models/model.manifest.json` records the binary SHA-256, byte size, format, model version, calibration metadata, metric summary, gate results, thresholds, and data hashes. The artifact is strictly under 2 MiB; the joblib model stays as the Python oracle.
- **Versioning.** `pg-model-1.0.0`. Model updates ship only with extension releases.

## 8. Extension specification

### 8.1 Manifest and permissions

- `manifest_version` 3, minimum Chrome 120, service-worker background, toolbar action with popup, options page.
- **Permissions:** `storage`, `webNavigation`, `alarms`. **Optional:** `scripting` plus optional host access (`<all_urls>`), used only for the in-page banner and only after the user grants it. The final list is confirmed in the M0 spike (for example, whether `tabs.update` needs the `tabs` permission) and then frozen. SC-01 fails the build if the manifest differs from the approved list.
- **Evaluated in the spike, adopted only if it helps:** `declarativeNetRequest` session rules to harden repeat visits to a High-Risk URL.
- **CSP:** `script-src 'self'; object-src 'self'; base-uri 'self'`. No remote code, no `eval`, no inline scripts.
- `web_accessible_resources`: none, so web pages cannot frame or imitate `warning.html`. No `externally_connectable`.

### 8.2 Components

- **Service worker:** event handling, pipeline orchestration, model holder, cache, decisions.
- **`lib/` (pure TypeScript, no DOM):** normalize, features, model, reasons, thresholds. Shared by the worker and the tests.
- **Pages:** popup, warning, options (Settings, Allowlist, History, and Data controls as tabs), about, first-run.
- **Optional content script:** banner and password-field tooltip, registered dynamically after host access is granted.

### 8.3 Storage map

| Key | Area | Contents | Retention |
| --- | --- | --- | --- |
| `settings` | local | enforcementMode, failureMode, bannerEnabled | Until cleared |
| `userAllowlist` | local | Registrable domains or tenant hosts | Until removed |
| `cache` | local | Hash key mapped to risk, band, model version, timestamp | TTL and LRU, 2,000 entries |
| `history` | local | Time, host, band, risk, action | 500 rows, 30 days, daily purge |
| `counters` | local | Scans, blocks, warnings, overrides (integers) | Until cleared |
| `pending` | session | Token mapped to full URL, risk, band, reasons (needed by the warning page) | Browser session |
| `overrides` | session | URL hash mapped to expiry | 30 minutes |
| `tabState` | session | Per-tab token and last verdict | Browser session |

Full URLs exist only in `storage.session` and in memory. Nothing persisted to disk contains a path, query, or fragment.

### 8.4 Messaging

| Message | From | To | Purpose |
| --- | --- | --- | --- |
| GET\_TAB\_STATUS | popup | worker | Current verdict, risk, reasons |
| GET\_BLOCK\_DETAILS(token) | warning page | worker | Host, reasons, mode |
| GO\_BACK(token) | warning page | worker | Navigate to a safe page or the previous entry |
| PROCEED\_OVERRIDE(token) | warning page | worker | Create a 30-minute URL override; requires a trusted click |
| TRUST\_DOMAIN(host) | popup, options | worker | Add to the user allowlist, with hosting-platform rules |
| UPDATE\_SETTINGS, CLEAR\_DATA(scope) | options | worker | Validated settings change; clear history, cache, or all |

Every handler validates `sender.id === chrome.runtime.id` and, for sensitive actions, that the sender is an extension page. The warning page URL carries only an opaque token and fetches details from the worker. URL-derived text is never inserted into HTML; pages use `textContent`.

### 8.5 Lifecycle

- `onInstalled` with reason `install` opens the first-run page; reason `update` shows a short 'What's new' note.
- The worker loads and verifies the model lazily on the first event after a wake and awaits it before scoring. The hash is verified at install or update and once per browser session.
- Alarms: a daily history purge and an hourly cache sweep.
- Per-tab scan cap (20 scans per 10 seconds); beyond it, the failure policy applies.

## 9. UI/UX specification

### 9.1 Screens

| Screen | Purpose | Key elements |
| --- | --- | --- |
| **Popup** (360×520) | Status at a glance | Band chip with icon and text, risk meter, up to 3 reasons, Trust this site, Copy report, Open settings, scan counter |
| **Warning page** | Stop and inform on High-Risk (or closed-mode errors) | Plain-language headline, true host in Unicode and punycode with the registrable domain highlighted, reasons, primary Go back to safety, disclosure for Proceed anyway |
| **Options** | Control and data | Enforcement mode, failure mode, banner toggle, allowlist editor, history list, Clear history, Clear cache, Clear all |
| **About and model card** | Transparency | Model version and hash, feature groups, data summary, benchmark and gate results, known limits, privacy statement |
| **First-run page** | Onboarding | What it does, what it does not do, permissions, enforcement mode choice, optional host-access request |

Every screen defines loading, empty, error, and success states. The popup defines five: loading, safe, suspicious, high-risk, and unscanned or error.

### 9.2 Interstitial copy

- **Headline:** Deceptive site blocked
- **Body:** PhishGuard thinks this address is likely a phishing page. Pages like this are used to steal passwords and payment details.
- **Address line:** Real address: the Unicode host, then the punycode host if they differ, with the registrable domain emphasized.
- **Why:** up to 3 reasons from 6.4.
- **Primary button:** Go back to safety (focused by default).
- **Secondary:** a disclosure labelled 'I understand the risk, show options'. It reveals a checkbox (I understand this site may steal my information) and a Proceed anyway button that enables after the checkbox is ticked and 1 second has passed.
- **Footer:** Wrong? Copy a report. This copies host, band, risk, model version, and reasons to the clipboard; nothing is sent.
- **Closed-mode error variant:** Could not verify this site, with the same two actions.

### 9.3 Visual and accessibility rules

- Color is never the only signal: each band has an icon and a text label. Suggested palette: red `#B3261E` (High-Risk), amber `#B26A00` (Suspicious), green `#1E7B34` (Safe), neutral grey for unscanned. Text contrast is at least 4.5:1 in light and dark themes (`prefers-color-scheme`).
- Full keyboard operation, visible focus rings, a logical tab order, and ARIA labels for the risk meter and the disclosure.
- Minimum 44 px targets in the popup, no motion beyond simple fades, and respect for reduced-motion settings.
- English in v1 with all strings in a `chrome.i18n` messages file, so translation needs no code change.
- WCAG 2.1 AA target, checked with axe and a manual keyboard pass (AX-01).

## 10. Security and privacy

### 10.1 Requirements

| ID | Requirement | Test |
| --- | --- | --- |
| SEC-01 | MV3 with strict CSP, no remote code, no `eval`, no inline scripts | SC-02 |
| SEC-02 | Only the approved permission list; any change requires a PRD change | SC-01 |
| SEC-03 | Warning page is not web-accessible; details come by token from the worker; override requires a trusted user gesture (`event.isTrusted`) on the extension page | SC-03, E2E-03 |
| SEC-04 | Every message handler validates the sender | SC-03 |
| SEC-05 | Hostile URLs (script tags, RTL override U+202E, very long hosts, look-alike characters) cannot alter or break any screen | SC-04 |
| SEC-06 | Zero outbound requests in v1; no raw URL persisted; queries, paths, and fragments never stored | SC-05, SC-06 |
| SEC-07 | Incognito: scan only if the user enabled the extension there; never write history, cache, or counters | E2E-09 |
| SEC-08 | Artifact integrity: SHA-256 check of the model against the manifest. This detects corruption and partial updates; the store's package signing is the root of trust against a malicious publisher | UT-07 |
| SEC-09 | Supply chain: zero runtime dependencies in the extension, pinned lockfiles, reproducible build, license check | CI |
| SEC-10 | Training-data integrity: provenance and hashes recorded, data files hash-verified in CI, top-weighted domains reviewed for poisoning-like artifacts | ML-08 |
| SEC-11 | Flood resistance: per-tab scan caps and duplicate collapse | E2E-05 |

### 10.2 Threat summary

| Threat | Example | Mitigation |
| --- | --- | --- |
| Evasion of URL-only features | A phishing page on a compromised legitimate domain, or a clean-looking new domain | Stated in the model card as a limit; v2 adds DOM signals; allowlists never weaken the model |
| Spoofed or framed warning page | A web page imitates the interstitial | Not web-accessible; token flow; no inline script |
| Override abuse | A script clicks Proceed | Trusted-gesture check, checkbox, 1 s delay |
| Tampered or corrupted model | Swapped or truncated `model.bin` | Hash check, failure policy, store signing |
| Privacy leakage | History, logs, backups | Host-only storage, no network, one-click clear |
| Scan flooding | A page fires many navigations | Per-tab caps, duplicate collapse |
| Training-data poisoning | Mislabeled or planted rows | Provenance, audits, per-domain caps |
| Dataset bias causing false blocks | Deep links on real sites flagged | E1 hold-out, grouped evaluation, warn-only fallback |

## 11. Non-functional requirements

| ID | Requirement | Target | Test |
| --- | --- | --- | --- |
| NFR-01 | Cached decision latency | < 10 ms p95 | PF-01 |
| NFR-02 | Warm end-to-end decision | < 30 ms p95 | PF-01 |
| NFR-03 | Cold-start decision (service worker wake, model load) | < 150 ms p95 | PF-01 |
| NFR-04 | Model inference alone | < 15 ms p95 | PF-01 |
| NFR-05 | Extension memory | < 50 MB | PF-02 |
| NFR-06 | Average CPU overhead | < 3% | PF-02 |
| NFR-07 | Size | Model and lists < 2 MB; package < 5 MB | CI |
| NFR-08 | Reliability | No unhandled errors in a 1,000-navigation soak | PF-02 |
| NFR-09 | Compatibility | Chrome, Edge, Brave on Chromium 120 or later | E2E suite on Chrome; manual on Edge and Brave |
| NFR-10 | Accessibility | WCAG 2.1 AA, axe clean | AX-01 |
| NFR-11 | Reproducibility | Same seed and data give identical metrics and model hash | ML-02 |
| NFR-12 | Maintainability | Lint and type checks clean, coverage ≥ 85% for `lib/` and `ml/`, complexity ≤ 15 | CI |
| NFR-13 | Privacy | Zero outbound requests during normal use | SC-05 |

## 12. Testing and validation

**Approach.** Unit tests for pure logic, parity tests between Python and TypeScript, ML tests for leakage and reproducibility, Playwright end-to-end tests with the unpacked extension in a persistent Chromium context, performance runs, security checks, and accessibility checks. A traceability script (`tools/trace.py`) fails CI if any FR, NFR, or SEC ID has no test, or if any test ID is undefined.

| Test | What it verifies |
| --- | --- |
| UT-01 | Normalization table of at least 60 cases, including the dataset's anomalous rows (scheme-less, leading U+00A0, punycode) |
| UT-02 | At least 30 hand-computed feature vectors |
| UT-03 | Band boundaries 34, 35, 69, 70 |
| UT-04 | Cache TTL, LRU eviction, and model-version invalidation |
| UT-05 | Allowlist precedence and the hosting-platform rule |
| UT-06 | Each reason code on trigger and negative fixtures |
| UT-07 | Model loader with corrupt, missing, and mismatched files |
| UT-08 | Settings validation |
| PAR-01 | Python and TypeScript features match on every dataset URL (1e-6) |
| PAR-02 | Python and TypeScript risk differs by at most 1 on every dataset URL and golden vector |
| ML-01 | No group overlap between train and test; fitted statistics change with the training fold |
| ML-02 | Same seed gives identical metrics and model hash |
| ML-03 | The 25-run benchmark completes and writes its report |
| ML-04 | Gates G-1, G-2 (D1), G-4, and G-7 evaluated and recorded |
| ML-05 | Calibration report (Brier, ECE, reliability plot) |
| ML-06 | Adversarial suite (G-8) |
| ML-07 | E1, E2, and E3 evaluation (G-2 on E2, G-3 on E1) |
| ML-08 | Dataset integrity: dedupe, domain cap, shortcut audit, provenance complete |
| API-01 | Reference API returns the same risk as the extension |
| E2E-01 | Safe navigation is untouched |
| E2E-02 | High-Risk navigation shows the interstitial; Go back works |
| E2E-03 | Override flow, scope, delay, and logging |
| E2E-04 | Suspicious navigation shows badge and popup detail; banner only when granted |
| E2E-05 | Redirect chains, multi-tab, stale results, duplicate collapse, scan cap |
| E2E-06 | Service-worker restart mid-navigation; cache persists |
| E2E-07 | Failure modes: 4 errors × open and closed |
| E2E-08 | Settings, allowlist, history, and clear-data actions |
| E2E-09 | Incognito behavior |
| E2E-10 | Block-race harness: at least 200 mixed cold and warm navigations |
| E2E-11 | About and first-run pages read shipped artifacts |
| PF-01 | Latency: cached, warm, and cold |
| PF-02 | Memory, CPU, and 1,000-navigation soak |
| SC-01 | Manifest permissions equal the approved list |
| SC-02 | CSP check; no remote code, `eval`, or inline scripts |
| SC-03 | Sender validation; tampered warning-page URL; non-web-accessible page |
| SC-04 | Hostile URL rendering fixtures |
| SC-05 | Network log shows zero outbound requests |
| SC-06 | Storage dump contains no path, query, fragment, or raw URL |
| AX-01 | axe and keyboard pass on all screens, light and dark |

## 13. Roadmap

Assumes 2 to 3 contributors over about 7 weeks. Adjust the dates, not the exit checks.

| Milestone | Weeks | Deliverables | Exit check |
| --- | --- | --- | --- |
| M0 Spike and profile | 1 | Profile D1 and write `PROVENANCE.md`; blocking spike (bare extension, at least 200 navigations); resolve decisions D-1 to D-3 | Shortcut baseline known; spike result recorded; final permission list drafted |
| M1 Data | 1-2 | Build E1 and E2; clean D1; freeze splits | ML-08 passes |
| M2 Model | 2-3 | Python features, 25-run benchmark, calibration, gates evaluated | Honest baseline report; targets re-baselined if needed |
| M3 Port | 3-4 | TypeScript port, model export, parity | G-5 passes |
| M4 Extension core | 4-5 | Pipeline, cache, allowlist, interstitial, override, failure policy | E2E-01 to E2E-03, E2E-05 to E2E-07, E2E-10 |
| M5 UI | 5-6 | Popup, options, about, first-run, history | AX-01, E2E-08, E2E-09, E2E-11 |
| M6 Hardening | 6-7 | Security tests, performance runs, adversarial suite, model card, README | All gates recorded; traceability green |
| M7 Release | 7 | Release candidate and demo; set the default enforcement mode from G-3 | Definition of Done met |

**Cut order if time slips:** FR-23, then FR-19, FR-18, FR-17, FR-11.

**Definition of Done:** all P0 FRs pass; gates G-1 to G-8 are recorded with their results (a failed gate triggers its stated consequence); traceability script is green; `PROVENANCE.md` is complete; the model card is generated from shipped artifacts; the README explains install, run, retrain, and test.

## 14. Risks

| ID | Risk | Mitigation |
| --- | --- | --- |
| R-01 | Dataset shortcuts cause false blocks on real deep links | E1 set, grouped evaluation, shortcut audit, warn-only fallback |
| R-02 | E1 or E2 cannot be built in time | Ship in `warn_only` and label the build a research beta; G-3 unverified means no blocking by default |
| R-03 | The interstitial loses the race against page load | M0 spike; fall back to a neutral Verifying page, DNR session rules, or warn-only |
| R-04 | Python and TypeScript drift | Single feature spec, shared lists and PSL snapshot, golden vectors, PAR tests |
| R-05 | Service-worker cold start misses the latency budget | Small model, lazy parse, measure in PF-01, fall back to LR |
| R-06 | URL-only detection is easy to evade | Disclosed in the model card; v2 DOM signals |
| R-07 | Store review friction over permissions | Optional host access, written justification, minimal permission list |
| R-08 | Dataset license or provenance unclear (O-01) | Record in `PROVENANCE.md`; do not redistribute raw data in the repository |
| R-09 | Label noise and mixed phishing and malware classes | Spot-check, decision D-3, report E3 separately |
| R-10 | Base-rate effect: real traffic is overwhelmingly benign | Allowlist, conservative T\_block, warn-only default if G-3 fails |
| R-11 | Team capacity | Defined cut order (section 13) |

## 15. Assumptions, open decisions, change log

**Assumptions**

- A-1: Labels are Benign and Malicious; Malicious may include malware-style URLs, not only phishing.
- A-2: D1 was collected at one point in time and has no timestamps, so E2 is the only temporal check.
- A-3: PhishGuard is a working name.
- A-4: Python and library versions are pinned in the lockfile; v1.0 listed versions measured in its workspace, which carry over unless the lockfile says otherwise.

**Open decisions (need the team)**

| ID | Decision | Owner | Needed by |
| --- | --- | --- | --- |
| D-1 | Confirm D1's source, size, and terms of use (the counts here differ from v1.0's file) | TBD | M0 |
| D-2 | Who builds E1 and E2, and by when | TBD | M0 |
| D-3 | Keep malware-style rows in the malicious class, or filter to phishing only | TBD | M1 |
| D-4 | Distribution: unpacked demo or Chrome Web Store | TBD | M6 |
| D-5 | Final product name | TBD | M6 |
| D-6 | Owner of the brand list (6.2) | TBD | M2 |

**Change log**

- v2.0: Scope reduced to an on-device MVP; WHOIS and backend moved to v1.1; evaluation rebuilt around grouped splits, external sets, and 8 gates; added the feature list, normalization rules, reason codes, calibration procedure, export format, storage and messaging maps, UI copy, threat table, and roadmap.
- v1.0: Initial PRD.

## Appendix A. Seed lists (refine with data)

- **Hosting platforms** (never domain-allowlistable; a tenant host is trusted individually): 000webhostapp.com, sites.google.com, github.io, pages.dev, workers.dev, netlify.app, vercel.app, blogspot.com, weebly.com, wixsite.com, herokuapp.com, firebaseapp.com, web.app, glitch.me, duckdns.org, ngrok.io.
- **URL shorteners:** bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd, cutt.ly, rebrand.ly, shorturl.at.

## Appendix B. Repository layout

```
phishguard/
  data/        raw/ processed/ external/ PROVENANCE.md
  lists/       sensitive_words.json brands.json hosting.json shorteners.json psl.dat allowlist.json
  ml/          profile.py build_dataset.py features.py train.py evaluate.py export.py report/
  extension/   manifest.json src/sw/ src/lib/ src/pages/ public/model.bin model.manifest.json
  tests/       golden/ parity/ e2e/ perf/ security/
  tools/       trace.py spike/ api/
  README.md  thresholds.json  requirements.lock  package-lock.json
```
