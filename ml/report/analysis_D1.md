# PhishGuard — Pre-Chunk-6 Analysis Report

Generated: 2026-11-16T18:03:42.930295+00:00

---

## 1. Gate Scorecard (G-1 to G-8)

Numbers sourced exclusively from `ml/report/benchmark_D1.json` and this script's hold-out re-evaluation.

| Gate | Name | Rule (abbreviated) | Result | Key number(s) |
|------|------|--------------------|:------:|---------------|
| G-1 | Shortcut margin | grouped-test balanced_acc > shortcut_baseline + 5 pp… | ✅ PASS | model 0.9068 vs baseline 0.8425 → +6.43 pp |
| G-2 | Recall | recall >= 90% on D1 grouped hold-out; >= 80% on E2… | ❌ FAIL | D1 hold-out recall = 0.8668 |
| G-3 | Block FPR | FPR <= 0.5% on E1 hold-out with allowlist off (95% Wilson in… | ⏳ N/M | D1 FPR ref = 0.0531 (E1 required) |
| G-4 | Generalization gap | random-split minus grouped-split balanced_acc <= 5 pp… | ✅ PASS | max gap = 2.26 pp across 25 runs |
| G-5 | Python / TypeScript parity | risk within 1 point on 100% of dataset URLs and golden vecto… | ⏳ N/M | — |
| G-6 | Performance | inference p95 < 15 ms warm; end-to-end < 30 ms warm; cold st… | ⏳ N/M | — |
| G-7 | Calibration | ECE <= 0.05; Brier score reported… | ⏳ N/M | ECE (uncal) = 0.0146, Brier = 0.0603 |
| G-8 | Robustness | recall on adversarial suite drops <= 10 pp vs clean… | ⏳ N/M | — |

> [!NOTE]
> G-2 fails because best RF recall on the D1 grouped hold-out is 86.68%, below the 90% threshold. G-3, G-5, G-6, G-8 are not measurable — they require E1/E2, the TypeScript port, or the browser extension. G-7 cannot be declared pass/fail until Platt/isotonic calibration is applied in Chunk 6.

---

## 2. Finalist Model Selection

**CV criterion (finalist ranking):** Mean balanced accuracy across 5-fold StratifiedGroupKFold × 3 seeds (seeds 42, 43, 44) on training partition only.

**Selection basis:** CV mean balanced_accuracy (5-fold StratifiedGroupKFold x 3 seeds) among G-1-passing combinations.

**Hold-out (locked):** Hold-out (D1 test.csv) evaluated ONCE per combination (25 evaluations total). No hyper-parameter tuning on hold-out. Hold-out is locked — never re-used for selection, tuning, or any optimization decision.

**Hold-out evaluations:** 25 total (one per combination, never re-used for selection or tuning).

| Rank | Selector | Classifier | CV bal-acc mean±std | HO bal-acc | G-1 margin | G-4 gap |
|-----:|----------|-----------|--------------------:|----------:|-----------:|--------:|
| 1 | `rf_importance` | `rf` | 0.9123 ± 0.0111 | 0.9068 | +6.43 pp | 0.98 pp |
| 2 | `rfe_rf` | `rf` | 0.9121 ± 0.0108 | 0.9060 | +6.35 pp | 1.11 pp |
| 3 | `l1_lr` | `rf` | 0.9096 ± 0.0119 | 0.9018 | +5.93 pp | 1.12 pp |
| 4 | `mutual_info` | `rf` | 0.9027 ± 0.0098 | 0.9049 | +6.23 pp | 0.12 pp |
| 5 | `l1_lr` | `knn` | 0.9006 ± 0.0134 | 0.8989 | +5.64 pp | 0.53 pp |
| 6 | `rfe_rf` | `knn` | 0.8897 ± 0.0128 | 0.8949 | +5.24 pp | 0.58 pp |
| 7 | `rf_importance` | `knn` | 0.8894 ± 0.0129 | 0.8952 | +5.27 pp | 0.46 pp |

---

## 3. Error Analysis — Hold-out Slices

Re-trained on full training partition (seed 42, same pipeline as benchmark). Scheme, path, and hosting flags are **analysis metadata only** — never model features.

### RF (`rf_importance` selector, k=20)

- **Overall recall:** 0.8668
- **Overall FPR:** 0.0531
- **False negatives (missed malicious):** 87
- **Missed malicious that are bare homepages:** 75 / 87 (86.2%)

#### Recall and FPR by slice

| Slice | n | n_malicious | n_benign | Recall | FPR |
|-------|--:|------------:|---------:|-------:|----:|
| has_path=True | 452 | 431 | 21 | 0.9722 | 0.9524 |
| has_path=False | 1444 | 222 | 1222 | 0.6622 | 0.0376 |
| on_hosting_platform=True | 4 | 3 | 1 | 1.0000 | 0.0000 |
| on_hosting_platform=False | 1892 | 650 | 1242 | 0.8662 | 0.0531 |
| scheme_less=True | 942 | 191 | 751 | 0.6335 | 0.0586 |
| scheme_less=False | 954 | 462 | 492 | 0.9632 | 0.0447 |

#### Top 20 RF feature importances (selected features only)

| Rank | Feature | Importance |
|-----:|---------|----------:|
| 1 | `path_length` | 0.177540 |
| 2 | `path_entropy` | 0.112463 |
| 3 | `path_depth` | 0.076979 |
| 4 | `url_entropy` | 0.072575 |
| 5 | `url_length` | 0.070955 |
| 6 | `dot_count` | 0.057966 |
| 7 | `special_char_ratio` | 0.050341 |
| 8 | `registrable_domain_length` | 0.048048 |
| 9 | `tld_length` | 0.047089 |
| 10 | `special_char_count` | 0.044237 |
| 11 | `distinct_char_ratio` | 0.040221 |
| 12 | `letter_ratio` | 0.036671 |
| 13 | `max_consonant_run` | 0.034488 |
| 14 | `host_entropy` | 0.030919 |
| 15 | `host_bigram_distinct_count` | 0.022898 |
| 16 | `host_trigram_distinct_count` | 0.017878 |
| 17 | `longest_subdomain_label` | 0.016823 |
| 18 | `hostname_length` | 0.016436 |
| 19 | `digit_count` | 0.013860 |
| 20 | `max_digit_run` | 0.011612 |

### KNN (`l1_lr` selector, k=20)

- **Overall recall:** 0.8469
- **Overall FPR:** 0.0491
- **False negatives (missed malicious):** 100
- **Missed malicious that are bare homepages:** 97 / 100 (97.0%)

#### Recall and FPR by slice

| Slice | n | n_malicious | n_benign | Recall | FPR |
|-------|--:|------------:|---------:|-------:|----:|
| has_path=True | 452 | 431 | 21 | 0.9930 | 1.0000 |
| has_path=False | 1444 | 222 | 1222 | 0.5631 | 0.0327 |
| on_hosting_platform=True | 4 | 3 | 1 | 1.0000 | 0.0000 |
| on_hosting_platform=False | 1892 | 650 | 1242 | 0.8462 | 0.0491 |
| scheme_less=True | 942 | 191 | 751 | 0.5654 | 0.0453 |
| scheme_less=False | 954 | 462 | 492 | 0.9632 | 0.0549 |

---

## 4. HistGradientBoosting Reference Baseline

Trained on the same training partition with the same grouped 80/20 hold-out. **Not a deployment candidate** (no compatible TypeScript export path, uses all 50 features without selection).

| Metric | Value |
|--------|------:|
| Hold-out balanced accuracy | 0.9159 |
| Hold-out recall | 0.8882 |
| Hold-out FPR | 0.0563 |
| Shortcut baseline | 0.8425 |
| G-1 margin vs shortcut | +7.34 pp |

**Interpretation:** HGB is within 0.9 pp of the best RF candidate, suggesting the **feature set is the ceiling**, not the model family. Adding richer features (E1 deep links, WHOIS, visual) would likely improve all models equally.

---

## 5. Blocking items before Chunk 6

| Item | Blocker |
|------|---------|
| G-2 Recall | Best RF recall on D1 hold-out is **86.68%** (< 90%). Adding E1 deep-link training data may close the gap. |
| G-3 Block FPR | Requires E1 hold-out (at least 2,000 URLs from 800+ domains). |
| G-7 Calibration | Requires Platt/isotonic fitting on out-of-fold predictions. E1 needed for threshold tuning (T_block). |
| E1 | Collection date, source, and benign-label verification not yet recorded in `data/PROVENANCE.md`. |
| E2 | Cannot be collected without D1 collection date. |
