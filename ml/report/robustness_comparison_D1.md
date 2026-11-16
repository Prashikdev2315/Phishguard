# D1 Robustness Mitigation Comparison

The comparison uses the existing block threshold (`T=0.70`) and unchanged gate
definitions. The four adversarial transforms were applied to both labels and
only to grouped-CV training rows; no validation or hold-out rows were
augmented.

| Metric / gate | Before | After symmetric augmentation |
|---|---:|---:|
| Balanced accuracy | 0.899165 | 0.891624 |
| Recall at T=0.70 | 0.836141 | 0.816233 |
| FPR at T=0.70 | 0.037812 | 0.032985 |
| G-1 | PASS | NOT_REEVALUATED |
| G-2 | FAIL | FAIL |
| G-4 | PASS | NOT_REEVALUATED |
| G-7 | PASS | PASS |
| G-8 worst recall drop | 0.116386 | 0.323124 |

After augmentation, the individual recall drops were:

| Transform | Recall drop |
|---|---:|
| `benign_path_token` | 0.289433 |
| `brand_subdomain` | 0.021440 |
| `hyphen_digit_host` | -0.026034 |
| `long_path` | 0.323124 |

The mitigation is rejected: it improves the brand-subdomain slice and lowers
FPR, but fails the unchanged G-2 and G-8 requirements and introduces severe
path-padding regressions. G-1 and G-4 were not recomputed by this focused
augmentation experiment; their prior benchmark results remain unchanged
evidence, not new post-mitigation measurements.

The current D1 data does not support claiming a 90% recall solution. Further
progress requires an E1 hold-out and more diverse malicious sources, especially
malicious URLs with padded paths and benign URLs containing path tokens.
