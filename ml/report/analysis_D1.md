# PhishGuard — Pre-Chunk-6 Analysis Report

Generated: 2026-11-17T09:58:30.431712+00:00

---

## 1. Gate Scorecard (G-1 to G-8)

Numbers sourced exclusively from `ml/report/benchmark_D1.json` and this script's hold-out re-evaluation.

| Gate | Name | Rule (abbreviated) | Result | Key number(s) |
|------|------|--------------------|:------:|---------------|
| G-1 | Shortcut margin | grouped-test balanced_acc > shortcut_baseline + 5 pp… | ✅ PASS | model 0.8758 vs baseline 0.8248 → +5.10 pp |
| G-2 | Recall | recall >= 90% on D1 grouped hold-out; >= 80% on E2… | ❌ FAIL | D1 hold-out recall = 0.8245 |
| G-3 | Block FPR | FPR <= 0.5% on E1 hold-out with allowlist off (95% Wilson in… | ⏳ N/M | D1 FPR ref = 0.0760 (E1 required) |
| G-4 | Generalization gap | random-split minus grouped-split balanced_acc <= 5 pp… | ✅ PASS | max gap = 1.41 pp across 25 runs |
| G-5 | Python / TypeScript parity | risk within 1 point on 100% of dataset URLs and golden vecto… | ⏳ N/M | — |
| G-6 | Performance | inference p95 < 15 ms warm; end-to-end < 30 ms warm; cold st… | ⏳ N/M | — |
| G-7 | Calibration | ECE <= 0.05; Brier score reported… | ⏳ N/M | ECE (uncal) = 0.0396, Brier = 0.0913 |
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
| 1 | `l1_lr` | `rf` | 0.8624 ± 0.0110 | 0.8758 | +5.10 pp | 1.41 pp |
| 2 | `l1_lr` | `lr` | 0.8562 ± 0.0158 | 0.8791 | +5.43 pp | 0.86 pp |

---

## 2b. Cross-Source Generalization Tests

| Direction | Train Set | Test Set | Bal Acc | Recall | FPR |
|-----------|----------:|---------:|--------:|-------:|----:|
| A -> B | 4218 | 4240 | 0.8033 | 0.9673 | 0.3607 |
| B -> A | 4240 | 4218 | 0.6014 | 0.5200 | 0.3171 |


---

## 3. Error Analysis — Hold-out Slices

Re-trained on full training partition (seed 42, same pipeline as benchmark). Scheme, path, and hosting flags are **analysis metadata only** — never model features.

### RF (`rf_importance` selector, k=20)

- **Overall recall:** 0.8245
- **Overall FPR:** 0.0760
- **False negatives (missed malicious):** 123
- **Missed malicious that are bare homepages:** 118 / 123 (95.9%)

#### Recall and FPR by slice

| Slice | n | n_malicious | n_benign | Recall (95% CI) | FPR (95% CI) |
|-------|--:|------------:|---------:|----------------:|-------------:|
| has_query=True | 119 | 117 | 2 | 0.9573 ([90.38%, 98.16%]) | 1.0000 ([34.24%, 100.00%]) |
| has_query=False | 1569 | 584 | 985 | 0.7979 ([76.35%, 82.85%]) | 0.0741 ([5.94%, 9.22%]) |
| has_path=True | 469 | 461 | 8 | 1.0000 ([99.17%, 100.00%]) | 1.0000 ([67.56%, 100.00%]) |
| has_path=False | 1219 | 240 | 979 | 0.4875 ([42.50%, 55.04%]) | 0.0684 ([5.42%, 8.60%]) |
| login_keywords=True | 131 | 125 | 6 | 0.9680 ([92.06%, 98.75%]) | 0.1667 ([3.01%, 56.35%]) |
| login_keywords=False | 1557 | 576 | 981 | 0.7934 ([75.84%, 82.45%]) | 0.0754 ([6.05%, 9.37%]) |
| google_hosted=True | 69 | 50 | 19 | 1.0000 ([92.87%, 100.00%]) | 0.0526 ([0.94%, 24.64%]) |
| google_hosted=False | 1619 | 651 | 968 | 0.8111 ([77.92%, 83.93%]) | 0.0764 ([6.13%, 9.49%]) |
| source=A_benign | 500 | 0 | 500 | — | 0.0460 ([3.08%, 6.81%]) |
| source=A_mal | 329 | 329 | 0 | 0.6748 ([62.24%, 72.31%]) | — |
| source=B_benign | 487 | 0 | 487 | — | 0.1068 ([8.24%, 13.73%]) |
| source=B_mal | 372 | 372 | 0 | 0.9570 ([93.13%, 97.34%]) | — |
| on_hosting_platform=True | 52 | 51 | 1 | 1.0000 ([93.00%, 100.00%]) | 0.0000 ([0.00%, 79.35%]) |
| on_hosting_platform=False | 1636 | 650 | 986 | 0.8108 ([77.89%, 83.90%]) | 0.0761 ([6.11%, 9.43%]) |
| scheme_less=True | 703 | 203 | 500 | 0.4729 ([40.54%, 54.15%]) | 0.0460 ([3.08%, 6.81%]) |
| scheme_less=False | 985 | 498 | 487 | 0.9679 ([94.85%, 98.01%]) | 0.1068 ([8.24%, 13.73%]) |

#### Top 20 RF feature importances (selected features only)

| Rank | Feature | Importance |
|-----:|---------|----------:|
| 1 | `path_length` | 0.118728 |
| 2 | `path_entropy` | 0.107564 |
| 3 | `path_depth` | 0.091680 |
| 4 | `url_entropy` | 0.087970 |
| 5 | `url_length` | 0.083855 |
| 6 | `tld_length` | 0.059044 |
| 7 | `distinct_char_ratio` | 0.052312 |
| 8 | `max_consonant_run` | 0.051019 |
| 9 | `special_char_count` | 0.049044 |
| 10 | `registrable_domain_length` | 0.048706 |
| 11 | `host_entropy` | 0.044620 |
| 12 | `host_bigram_distinct_count` | 0.033753 |
| 13 | `special_char_ratio` | 0.033402 |
| 14 | `letter_ratio` | 0.028371 |
| 15 | `host_trigram_distinct_count` | 0.025507 |
| 16 | `longest_subdomain_label` | 0.023587 |
| 17 | `hostname_length` | 0.018922 |
| 18 | `digit_count` | 0.017377 |
| 19 | `max_digit_run` | 0.013009 |
| 20 | `digit_ratio` | 0.011530 |

### KNN (`l1_lr` selector, k=20)

- **Overall recall:** 0.7874
- **Overall FPR:** 0.0405
- **False negatives (missed malicious):** 149
- **Missed malicious that are bare homepages:** 135 / 149 (90.6%)

#### Recall and FPR by slice

| Slice | n | n_malicious | n_benign | Recall (95% CI) | FPR (95% CI) |
|-------|--:|------------:|---------:|----------------:|-------------:|
| has_query=True | 119 | 117 | 2 | 0.8974 ([82.93%, 94.04%]) | 0.5000 ([9.45%, 90.55%]) |
| has_query=False | 1569 | 584 | 985 | 0.7654 ([72.94%, 79.80%]) | 0.0396 ([2.91%, 5.37%]) |
| has_path=True | 469 | 461 | 8 | 0.9957 ([98.43%, 99.88%]) | 1.0000 ([67.56%, 100.00%]) |
| has_path=False | 1219 | 240 | 979 | 0.3875 ([32.81%, 45.04%]) | 0.0327 ([2.32%, 4.58%]) |
| login_keywords=True | 131 | 125 | 6 | 0.9840 ([94.35%, 99.56%]) | 0.0000 ([0.00%, 39.03%]) |
| login_keywords=False | 1557 | 576 | 981 | 0.7448 ([70.76%, 77.87%]) | 0.0408 ([3.01%, 5.50%]) |
| google_hosted=True | 69 | 50 | 19 | 1.0000 ([92.87%, 100.00%]) | 0.1053 ([2.94%, 31.39%]) |
| google_hosted=False | 1619 | 651 | 968 | 0.7711 ([73.73%, 80.17%]) | 0.0393 ([2.87%, 5.34%]) |
| source=A_benign | 500 | 0 | 500 | — | 0.0180 ([0.95%, 3.39%]) |
| source=A_mal | 329 | 329 | 0 | 0.6201 ([56.65%, 67.08%]) | — |
| source=B_benign | 487 | 0 | 487 | — | 0.0637 ([4.52%, 8.89%]) |
| source=B_mal | 372 | 372 | 0 | 0.9355 ([90.58%, 95.63%]) | — |
| on_hosting_platform=True | 52 | 51 | 1 | 0.9412 ([84.08%, 97.98%]) | 0.0000 ([0.00%, 79.35%]) |
| on_hosting_platform=False | 1636 | 650 | 986 | 0.7754 ([74.17%, 80.58%]) | 0.0406 ([2.99%, 5.48%]) |
| scheme_less=True | 703 | 203 | 500 | 0.4138 ([34.83%, 48.25%]) | 0.0180 ([0.95%, 3.39%]) |
| scheme_less=False | 985 | 498 | 487 | 0.9398 ([91.53%, 95.75%]) | 0.0637 ([4.52%, 8.89%]) |

---

## 4. HistGradientBoosting Reference Baseline

Trained on the same training partition with the same grouped 80/20 hold-out. **Not a deployment candidate** (no compatible TypeScript export path, uses all 50 features without selection).

| Metric | Value |
|--------|------:|
| Hold-out balanced accuracy | 0.8834 |
| Hold-out recall | 0.8488 |
| Hold-out FPR | 0.0821 |
| Shortcut baseline | 0.8248 |
| G-1 margin vs shortcut | +5.86 pp |

**Interpretation:** HGB is within 0.8 pp of the best RF candidate, suggesting the **feature set is the ceiling**, not the model family. Adding richer features (E1 deep links, WHOIS, visual) would likely improve all models equally.

---

## 5. Blocking items before Chunk 6

| Item | Blocker |
|------|---------|
| G-2 Recall | Best RF recall on D1 hold-out is **86.68%** (< 90%). Adding E1 deep-link training data may close the gap. |
| G-3 Block FPR | Requires E1 hold-out (at least 2,000 URLs from 800+ domains). |
| G-7 Calibration | Requires Platt/isotonic fitting on out-of-fold predictions. E1 needed for threshold tuning (T_block). |
| E1 | Collection date, source, and benign-label verification not yet recorded in `data/PROVENANCE.md`. |
| E2 | Cannot be collected without D1 collection date. |
