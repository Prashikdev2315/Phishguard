# PhishGuard — Benchmark Report (Chunk 5)

Generated: 2026-11-17T09:48:09.240053+00:00

## Dataset

| Split | Rows | Malicious |
|-------|-----:|----------:|
| Train | 6,770 | 2,771 |
| Test  | 1,688 | 701 |

- Domain overlap (train ∩ test): **0** (ML-01 ✅)
- Shortcut baseline (balanced acc, N-13 deployable): **0.8248**

## Results — 25 combinations

| Selector | Classifier | k | CV bal-acc mean±std | HO bal-acc | HO recall | HO FPR | G-1 | G-4 |
|----------|-----------|--:|--------------------:|----------:|----------:|-------:|:---:|:---:|
| l1_lr | lr | 20 | 0.8562±0.0158 | 0.8791 | 0.8088 | 0.0507 | ✅ | ✅ |
| l1_lr | rf | 20 | 0.8624±0.0110 | 0.8758 | 0.8245 | 0.0729 | ✅ | ✅ |
| rfe_rf | rf | 20 | 0.8614±0.0119 | 0.8747 | 0.8274 | 0.0780 | ❌ | ✅ |
| rf_importance | rf | 20 | 0.8599±0.0118 | 0.8743 | 0.8245 | 0.0760 | ❌ | ✅ |
| l1_lr | knn | 20 | 0.8611±0.0144 | 0.8735 | 0.7874 | 0.0405 | ❌ | ✅ |
| rfe_rf | lr | 20 | 0.8531±0.0159 | 0.8725 | 0.8088 | 0.0638 | ❌ | ✅ |
| l1_lr | svm | 20 | 0.8598±0.0143 | 0.8696 | 0.7746 | 0.0355 | ❌ | ✅ |
| rf_importance | knn | 20 | 0.8568±0.0096 | 0.8686 | 0.7889 | 0.0517 | ❌ | ✅ |
| rfe_rf | knn | 20 | 0.8578±0.0091 | 0.8684 | 0.7874 | 0.0507 | ❌ | ✅ |
| rf_importance | lr | 20 | 0.8538±0.0168 | 0.8678 | 0.7974 | 0.0618 | ❌ | ✅ |
| rfe_rf | svm | 20 | 0.8580±0.0145 | 0.8656 | 0.7646 | 0.0334 | ❌ | ✅ |
| rf_importance | svm | 20 | 0.8578±0.0139 | 0.8636 | 0.7646 | 0.0375 | ❌ | ✅ |
| mutual_info | rf | 20 | 0.8455±0.0141 | 0.8622 | 0.8074 | 0.0831 | ❌ | ✅ |
| chi2 | rf | 20 | 0.8435±0.0146 | 0.8579 | 0.7917 | 0.0760 | ❌ | ✅ |
| mutual_info | knn | 20 | 0.8456±0.0138 | 0.8578 | 0.7703 | 0.0547 | ❌ | ✅ |
| mutual_info | lr | 20 | 0.8460±0.0160 | 0.8554 | 0.7575 | 0.0466 | ❌ | ✅ |
| chi2 | svm | 20 | 0.8359±0.0165 | 0.8465 | 0.7133 | 0.0203 | ❌ | ✅ |
| chi2 | knn | 20 | 0.8345±0.0213 | 0.8457 | 0.7461 | 0.0547 | ❌ | ✅ |
| chi2 | lr | 20 | 0.8336±0.0154 | 0.8444 | 0.7375 | 0.0486 | ❌ | ✅ |
| mutual_info | svm | 20 | 0.8390±0.0148 | 0.8368 | 0.6990 | 0.0253 | ❌ | ✅ |
| mutual_info | gnb | 20 | 0.8241±0.0150 | 0.8320 | 0.6904 | 0.0263 | ❌ | ✅ |
| chi2 | gnb | 20 | 0.8176±0.0169 | 0.8310 | 0.6904 | 0.0284 | ❌ | ✅ |
| rf_importance | gnb | 20 | 0.8219±0.0123 | 0.8305 | 0.7076 | 0.0466 | ❌ | ✅ |
| rfe_rf | gnb | 20 | 0.8224±0.0118 | 0.8258 | 0.7033 | 0.0517 | ❌ | ✅ |
| l1_lr | gnb | 20 | 0.8106±0.0184 | 0.8139 | 0.6633 | 0.0355 | ❌ | ✅ |

## Best model

- **Selector:** `l1_lr`
- **Classifier:** `rf`
- **Hold-out balanced accuracy:** 0.8758
- **G-1 margin:** +5.10 pp (threshold ≥ +5.00 pp)

Artifacts: `ml/models/best_model.joblib`, `ml/models/model.manifest.json`

## Gate summary

| Gate | Rule | Outcome |
|------|------|---------|
| G-1 Shortcut margin | balanced_acc > baseline + 5 pp | ✅ passes |
| G-4 Generalization gap | random − grouped ≤ 5 pp | ✅ passes |

_G-2, G-3, G-5 to G-8 require E1/E2 and are evaluated in Chunk 6._
