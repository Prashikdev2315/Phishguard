# PhishGuard — data/PROVENANCE.md
# Dataset Provenance Record

Fields marked **TODO** must be filled by the team before M2.
Do not guess or invent them.

---

## D1 — Primary dataset

| Field | Value |
|-------|-------|
| Filename | `Combined_Benign_Malicious_Dataset_CORRECTED.csv` |
| SHA-256 | *(see profile_D1.json → source_sha256 — computed by ml/profile.py)* |
| Total rows | 11,000 |
| Benign rows | 6,500 |
| Malicious rows | 4,500 |
| Columns | `URL`, `type` |
| **Source / origin** | **TODO** — record where this file came from (paper, Kaggle, lab collection, etc.) |
| **License / terms of use** | **TODO** — confirm redistribution rights; do not commit raw data to a public repo until confirmed (PRD open decision D-1) |
| **Collection date / date range** | **TODO** — record when URLs were collected; needed to establish temporal boundary for E2 |
| **Labeling method** | **TODO** — record how Benign/Malicious labels were assigned |
| Profile generated at | *(see profile_D1.json → generated_at)* |
| PSL snapshot used | `lists/psl.dat` if present, else minimal built-in fallback (see profile_D1.json → psl_source) |

### Profiling results (Chunk 2, read-only)

All numbers computed by `ml/profile.py`. See `ml/report/profile_D1.json` and
`ml/report/profile_D1.md` for full details.

| Metric | Value |
|--------|-------|
| Exact duplicates | 152 |
| Normalized duplicates | 153 |
| Cross-class normalized duplicates | 0 |
| Scheme-less rows | 5,060 (Benign: 4,000 / 61.5%, Malicious: 1,060 / 23.6%) |
| Non-ASCII URL rows | 1 (leading U+00A0, stripped cleanly by N-01) |
| Punycode hostname rows | 4 |
| IP-host rows | 119 |
| Normalization errors | 0 |
| Shortcut baseline (deployable features, N-13) | 85.26% |
| Shortcut baseline (with is_https) | 85.26% |
| Gate G-1 risk (shortcut baseline ≥ 95%)? | **No** — safe to proceed |

### Manual label spot-check (required before M2)

- Review sample written to `data/review_sample.csv` (100 rows per class, seed 42)
- **TODO** — spot-check these rows and record the error rate below

| Field | Value |
|-------|-------|
| Rows checked | TODO |
| Label errors found | TODO |
| Error rate | TODO |
| Checked by | TODO |
| Checked on | TODO |

---

## E1 — Benign deep-link set (Chunk 3)

**TODO** — built by the team in Chunk 3.

| Field | Value |
|-------|-------|
| Source | Tranco-ranked sites, sitemap or crawled inner-page URLs |
| Target size | ≥ 2,000 URLs from ≥ 800 domains |
| Split rule | Half joins training, half is FPR hold-out (split by domain) |
| Built by | TODO |
| Built on | TODO |
| SHA-256 | TODO |

---

## E2 — Fresh phishing set (Chunk 3)

**TODO** — built by the team in Chunk 3.

| Field | Value |
|-------|-------|
| Source | PhishTank or OpenPhish, collected AFTER D1 collection date |
| Target size | ≥ 500 verified phishing URLs |
| Domains | None overlapping with D1 |
| Feed terms checked? | TODO |
| Built by | TODO |
| Built on | TODO |
| SHA-256 | TODO |

---

## E3 — Malware stress set

| Field | Value |
|-------|-------|
| Description | Second dataset: 428 benign + ~23k malware-style URLs |
| Role | Recall stress test only — NEVER used for training or threshold selection |
| SHA-256 | TODO |
| Source | TODO |

---

## Race harness spike (FR-09)

**TODO** — run `tools/spike/race_harness.py` and record the verdict here.

| Field | Value |
|-------|-------|
| Runs | TODO (target: ≥ 200) |
| Interstitial rate | TODO |
| Verdict | TODO (PASS / WARN / FAIL) |
| Full results | `docs/SPIKE_RESULTS.md` |

---

## Default allowlist (Chunk 2)

| Field | Value |
|-------|-------|
| Source | Tranco top-5000 (TODO: record snapshot date and URL) |
| Exclusions | Hosting platforms (lists/hosting.json), URL shorteners (lists/shorteners.json), domains malicious in D1 |
| Generated in | Chunk 2 by `ml/profile.py` |
| File | `lists/allowlist.json` |
| Status | PLACEHOLDER — full list generated in Chunk 2 |

---

*This file is maintained manually. All computed values come from generated
artifacts; do not hard-code or guess them.*
