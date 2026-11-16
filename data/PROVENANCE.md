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


## E1 â€” Benign deep-link candidate set (Chunk 3)

**Structural validation: PASS.** Independent benign-label verification and source-term review remain pending.

| Field | Value |
|-------|-------|
| Source | Tranco `top-1m.csv`; inner-page URLs obtained from public sitemaps |
| Tranco file | `data/raw/E1/tranco/top-1m.csv` |
| Local file modification time | 2026-11-15 19:45:22 (local time; not proof of snapshot date) |
| Tranco snapshot ID / download URL | Unknown ? metadata unavailable. |
| Collection method | Sitemap-based URL discovery; robots.txt permissions checked |
| D1 exclusion | All 5,644 D1 registrable domains excluded |
| Old/new candidate domain overlap | 0 |
| URLs accepted | 2,591 |
| Registrable domains | 866 |
| Training URLs / domains | 1,296 / 433 |
| Holdout URLs / domains | 1,295 / 433 |
| Train/holdout domain overlap | 0 |
| D1/E1 domain overlap | 0 |
| Maximum URLs per domain | 3 |
| Rejected URLs | 0 |
| Split rule | SHA-256 of `phishguard-e1-v1|domain`, ranked midpoint |
| Built by | TODO â€” record responsible team member |
| Built on | 2026-11-16 |
| Source terms / permissions reviewed? | PARTIAL ? robots.txt rules checked; Tranco upstream licences and individual site terms not fully verified. Redistribution not approved. |
| Benign-label verification | Preliminary 100-URL audit: 41 supported candidates, 53 uncertain, 6 flagged; full verification pending. |
| Input SHA-256 | `18a66bd7182af50731ff38252261f4862daf635b4101ff41d5e319074e0c4576` |
| Training SHA-256 | `0894fbe621ee8705345e40faf86c8d3c419d36ed2fa2da70d5fdb182fdce690c` |
| Holdout SHA-256 | `737f78c2b01c0b41a073955958379dead53a90353c85ee01831629e0cb026548` |
| Report SHA-256 | `1a427b134c958825d16e439ddee8e8a20eff429eac4c6f30da323e26d764a09c` |
| Structural builder status | PASS |

---

### E1 sample evidence review

A preliminary public-web evidence review was performed on 100 sampled URLs.

| Result | Count |
|---|---:|
| Supported benign candidates | 41 |
| Uncertain | 53 |
| Flagged ? exclude pending further review | 6 |
| Total sampled | 100 |

This is not a security-reputation clearance or verification of all E1 URLs.
Uncertain and flagged records must not be treated as confirmed benign.
Full source-term and benign-label verification remains pending.

## E2 â€” Fresh phishing set (Chunk 3)

**Status: BLOCKED** ? D1 collection date is unknown; temporal ordering cannot be established.

| Field | Value |
|-------|-------|
| Source | PhishTank or OpenPhish, collected AFTER D1 collection date |
| Target size | â‰¥ 500 verified phishing URLs |
| Domains | None overlapping with D1 |
| Feed terms checked? | TODO |
| Built by | TODO |
| Built on | TODO |
| SHA-256 | TODO |

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
