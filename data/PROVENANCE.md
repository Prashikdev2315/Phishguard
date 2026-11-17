# PhishGuard â€” data/PROVENANCE.md
# Dataset Provenance Record

Fields marked **TODO** must be filled by the team before M2.
Do not guess or invent them.

---

## D1 â€” Primary dataset

| Field | Value |
|-------|-------|
| Filename | `Combined_Benign_Malicious_Dataset_CORRECTED.csv` |
| SHA-256 | *(see profile_D1.json â†’ source_sha256 â€” computed by ml/profile.py)* |
| Total rows | 11,000 |
| Benign rows | 6,500 |
| Malicious rows | 4,500 |
| Columns | `URL`, `type` |
| **Source / origin** | Unknown ? original download URL unavailable. |
| **License / terms of use** | Unknown ? not verified. |
| **Collection date / date range** | Unknown ? original metadata unavailable. |
| **Labeling method** | Unknown ? original documentation unavailable. |
| Profile generated at | *(see profile_D1.json â†’ generated_at)* |
| PSL snapshot used | `lists/psl.dat` if present, else minimal built-in fallback (see profile_D1.json â†’ psl_source) |

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
| Gate G-1 risk (shortcut baseline â‰¥ 95%)? | **No** â€” safe to proceed |

### Manual label spot-check (required before M2)

- Review sample: `data/review_sample_chunk3.csv` (200 rows, 100 per class).
- **Status: NOT COMPLETED** ? 0 of 200 independently reviewed.

| Field | Value |
|-------|-------|
| Rows checked | 0 of 200 |
| Label errors found | Not determined |
| Error rate | Not calculated |
| Checked by | Not performed |
| Checked on | Not performed |

---


## E1 — Benign deep-link candidate set (Chunk E)

**Status: IN PROGRESS — Tranco external list validated; dry-run executed; awaiting user approval for full crawl.**

| Field | Value |
|-------|-------|
| Source | Tranco Top 1M (`data/external/tranco.csv`) |
| List ID | `unknown, will add` |
| Download date | 2026-11-17 |
| Row count | 1,000,000 domains (ranks 1 to 1,000,000, no header) |
| SHA-256 | `7b6e83d59c444a722f8868a4aa83768fa1cca9f8b5a0cc20fbee085c2bad4d6f` |
| Collection targets | ≥ 5,000 benign URLs from ≥ 1,500 domains, ≤ 5 URLs/domain |
| Rank bands | 1-1k, 1k-10k, 10k-100k, 100k-1M |
| Quotas | Path ≥ 50%, Query ≥ 20%, Login/Account ≥ 10%, Indian sites/lang ≥ 10% |
| Discovery methods | Sitemaps, homepage links, 1-level links, 26 curated seed domains |
| Crawl constraints | Respect robots.txt, 1 req/sec/host, public pages only |
| D1 exclusion | All 5,669 D1 registrable domains strictly excluded (0 overlap) |
| Adult domain exclusion | Domains with adult TLDs (.xxx, .adult, .porn, .sex) or adult industry/escort keywords are excluded; stratified sampling resamples replacement domains from the exact same rank band. **Known bias:** E1 has intentional zero coverage of adult/escort web properties. |

---

## E2 — Fresh phishing set (Chunk E)

**Status: MISSING — Not provided yet.**
- As instructed, no synthetic, fabricated, or substitute data has been created.
- `build_dataset.py`, `evaluate.py`, and `evaluate_e1.py` support the E2-optional path.
- When E2 is absent, the E2 temporal split, `e2_holdout`, and the E2 half of gate G-2 are explicitly reported as `"not measurable (E2 missing)"`, never as pass or fail.

---

---

## E3 â€” Malware stress set

| Field | Value |
|-------|-------|
| Description | Second dataset: 428 benign + ~23k malware-style URLs |
| Role | Recall stress test only â€” NEVER used for training or threshold selection |
| SHA-256 | TODO |
| Source | TODO |

---

## Race harness spike (FR-09)

**Status: PASS - 200 navigation runs completed.**

| Field | Value |
|-------|-------|
| Runs | 200 |
| Cold runs | 40/40 - 100% interstitial |
| Warm runs | 160/160 - 100% interstitial |
| Overall interstitial rate | 100% (200/200) |
| Target page committed | 0 |
| Playwright route interceptions | 197 |
| Route no-fetch | 3 |
| Verdict | PASS |
| Full results | `docs/SPIKE_RESULTS.md` |

Note: Route counts represent Playwright interceptions fulfilled from memory,
not confirmed live-origin network requests. The test confirms that all
200 navigations ended on the warning interstitial.

---

## Default allowlist (Chunk 2)

| Field | Value |
|-------|-------|
| Source | Tranco top-5000 (TODO: record snapshot date and URL) |
| Exclusions | Hosting platforms (lists/hosting.json), URL shorteners (lists/shorteners.json), domains malicious in D1 |
| Generated in | Chunk 2 by `ml/profile.py` |
| File | `lists/allowlist.json` |
| Status | PLACEHOLDER â€” full list generated in Chunk 2 |

---

*This file is maintained manually. All computed values come from generated
artifacts; do not hard-code or guess them.*
