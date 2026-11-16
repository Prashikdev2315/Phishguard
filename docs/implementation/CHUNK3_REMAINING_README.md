# PhishGuard Chunk 3 — E1/E2 intake and validation

This patch adds `ml/build_external.py`. It does not fabricate evaluation URLs or claim E1/E2 complete without real source data.

## E1 input
Create a CSV with a `URL` column (optional `source` column). Populate it with genuine inner-page URLs from Tranco-ranked domains using an approved sitemap/crawl process. Keep 1–3 URLs per domain. Then run:

```powershell
python -m ml.build_external e1 --input data/raw/E1_candidates.csv --root .
```

The builder normalizes URLs using the existing N-01–N-13 normalizer, removes duplicates and homepages, caps at 3 URLs/domain, requires >=2,000 URLs and >=800 domains, and assigns whole domains deterministically to E1_training.csv or E1_holdout.csv. It fails closed and does not publish partial output if minimums are unmet.

## E2 input
Create a CSV with columns `URL,source,collected_at,verified`. `source` must be `PhishTank` or `OpenPhish`; `collected_at` must be an ISO date; `verified` must be true only when the feed/source verification supports that label. Run only after the D1 collection date is established from evidence:

```powershell
python -m ml.build_external e2 --input data/raw/E2_candidates.csv --root . --d1-date YYYY-MM-DD
```

The builder rejects unverified rows, unsupported feeds, records not newer than D1, duplicates and registrable domains present in cleaned D1. It requires >=500 accepted records. Do not guess D1's collection date.

## Important limitations
- E1/E2 still require genuine source data, feed terms review, collection logs and evidence.
- E1 target is >=2,000 URLs from >=800 domains; its split is by registrable domain, never by row.
- E2 is evaluation only and must never enter training or threshold tuning.
- Complete `data/PROVENANCE.md` manually using evidence. Unknown D1 source/license/date/labeling method and D-3 remain blockers.
- Manual label review of the 100-per-class sample is a human task; record actual findings, not assumptions.

## Tests
```powershell
python -m pytest tests/test_build_external.py -v
```
