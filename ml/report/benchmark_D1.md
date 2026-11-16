# PhishGuard — Benchmark Report (Chunk 5)

Generated: 2026-11-16T08:57:48.554333+00:00

## Dataset

| Split | Rows | Malicious |
|-------|-----:|----------:|
| Train | 7,781 | 2,854 |
| Test  | 1,896 | 653 |

- Domain overlap (train ∩ test): **0** (ML-01 ✅)
- Shortcut baseline (balanced acc, N-13 deployable): **0.8425**

## Results — 25 combinations

| Selector | Classifier | k | CV bal-acc mean±std | HO bal-acc | HO recall | HO FPR | G-1 | G-4 |
|----------|-----------|--:|--------------------:|----------:|----------:|-------:|:---:|:---:|
| rf_importance | rf | 20 | 0.9123±0.0111 | 0.9068 | 0.8668 | 0.0531 | ✅ | ✅ |
| rfe_rf | rf | 20 | 0.9121±0.0108 | 0.9060 | 0.8683 | 0.0563 | ✅ | ✅ |
| mutual_info | rf | 20 | 0.9027±0.0098 | 0.9049 | 0.8652 | 0.0555 | ✅ | ✅ |
| l1_lr | rf | 20 | 0.9096±0.0119 | 0.9018 | 0.8591 | 0.0555 | ✅ | ✅ |
| l1_lr | knn | 20 | 0.9006±0.0134 | 0.8989 | 0.8469 | 0.0491 | ✅ | ✅ |
| rf_importance | knn | 20 | 0.8894±0.0129 | 0.8952 | 0.8331 | 0.0426 | ✅ | ✅ |
| rfe_rf | knn | 20 | 0.8897±0.0128 | 0.8949 | 0.8285 | 0.0386 | ✅ | ✅ |
| mutual_info | knn | 20 | 0.8785±0.0107 | 0.8915 | 0.8224 | 0.0394 | ❌ | ✅ |
| l1_lr | svm | 20 | 0.8844±0.0135 | 0.8897 | 0.8285 | 0.0491 | ❌ | ✅ |
| rfe_rf | svm | 20 | 0.8911±0.0135 | 0.8827 | 0.8208 | 0.0555 | ❌ | ✅ |
| rf_importance | svm | 20 | 0.8910±0.0126 | 0.8815 | 0.8208 | 0.0579 | ❌ | ✅ |
| chi2 | rf | 20 | 0.8809±0.0106 | 0.8741 | 0.8254 | 0.0772 | ❌ | ✅ |
| mutual_info | svm | 20 | 0.8728±0.0149 | 0.8740 | 0.7979 | 0.0499 | ❌ | ✅ |
| l1_lr | lr | 20 | 0.8745±0.0120 | 0.8729 | 0.7948 | 0.0491 | ❌ | ✅ |
| rf_importance | lr | 20 | 0.8709±0.0142 | 0.8684 | 0.7810 | 0.0442 | ❌ | ✅ |
| rfe_rf | lr | 20 | 0.8710±0.0141 | 0.8676 | 0.7810 | 0.0459 | ❌ | ✅ |
| mutual_info | lr | 20 | 0.8621±0.0177 | 0.8637 | 0.7764 | 0.0491 | ❌ | ✅ |
| chi2 | knn | 20 | 0.8481±0.0141 | 0.8474 | 0.7504 | 0.0555 | ❌ | ✅ |
| chi2 | svm | 20 | 0.8315±0.0177 | 0.8367 | 0.6983 | 0.0249 | ❌ | ✅ |
| chi2 | lr | 20 | 0.8326±0.0176 | 0.8359 | 0.6983 | 0.0265 | ❌ | ✅ |
| mutual_info | gnb | 20 | 0.8291±0.0158 | 0.8237 | 0.6692 | 0.0217 | ❌ | ✅ |
| chi2 | gnb | 20 | 0.8212±0.0175 | 0.8228 | 0.6891 | 0.0434 | ❌ | ✅ |
| l1_lr | gnb | 20 | 0.8123±0.0194 | 0.8179 | 0.6600 | 0.0241 | ❌ | ✅ |
| rf_importance | gnb | 20 | 0.8230±0.0185 | 0.8162 | 0.6830 | 0.0507 | ❌ | ✅ |
| rfe_rf | gnb | 20 | 0.8237±0.0162 | 0.8161 | 0.6845 | 0.0523 | ❌ | ✅ |

## Best model

- **Selector:** `rf_importance`
- **Classifier:** `rf`
- **Hold-out balanced accuracy:** 0.9068
- **G-1 margin:** +0.0643 pp (threshold ≥ +0.05)

Artifacts: `ml/models/best_model.joblib`, `ml/models/model.manifest.json`

## Gate summary

| Gate | Rule | Outcome |
|------|------|---------|
| G-1 Shortcut margin | balanced_acc > baseline + 5 pp | ✅ passes |
| G-4 Generalization gap | random − grouped ≤ 5 pp | ✅ passes |

_G-2, G-3, G-5 to G-8 require E1/E2 and are evaluated in Chunk 6._
