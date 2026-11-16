# PhishGuard Chunk 3 — D1 build implementation

## Files in this patch
- `ml/build_dataset.py`: D1 cleaning, N-13 normalization reuse, duplicate removal,
  per-class registrable-domain cap, manual-review sample, grouped hold-out,
  random-stratified comparison split, and 5-fold grouped-CV index manifest.
- `tests/test_build_dataset.py`: four tests for deduplication, label conflicts,
  domain caps, and grouped-split leakage.
- `data/reports/*` and `data/splits/*.json`: reports produced from the uploaded D1 CSV.
  No raw URLs or dataset CSV files are included in this patch.

## Apply to your cloned repository
Extract this ZIP into the repository root, preserving folders, or copy the files
to the matching folders.

Place your original dataset locally at:
`data/raw/Combined_Benign_Malicious_Dataset_CORRECTED.csv`

Then, from the repository root with the project virtual environment active, run:

```powershell
python -m ml.build_dataset --dataset data/raw/Combined_Benign_Malicious_Dataset_CORRECTED.csv --root .
python -m pytest tests/ -v
```

The build creates:
- `data/processed/D1_cleaned.csv`
- `data/splits/train.csv`
- `data/splits/test.csv`
- `data/splits/random_stratified/train.csv`
- `data/splits/random_stratified/test.csv`
- `data/splits/cv_folds.json`
- `data/splits/split_manifest.json`
- `data/review_sample_chunk3.csv`
- `data/reports/cleaning_report.json`
- `data/reports/concentration_report.json`
- `data/reports/dataset_summary.md`

## Important limitations / approvals still required
1. D1 source origin, license, collection date and labeling method are still TODO
   in `data/PROVENANCE.md`. Confirm these with the dataset owner.
2. The PRD open decision D-3 asks whether malware-style records remain in the
   `Malicious` class. This implementation preserves the supplied labels; it
   does not decide that question.
3. Rows without a registrable domain are written to
   `data/reports/D1_without_registrable_domain.csv` for review and excluded from
   grouped modelling data.
4. E1 and E2 are not fabricated or generated from D1. They still require genuine,
   dated, independently sourced external datasets and their own validation.
5. Do not commit raw or derived dataset CSVs until the dataset license and
   redistribution terms are confirmed.

The grouped hold-out uses the first fold of `StratifiedGroupKFold(n_splits=5)`
with seed 42, giving an approximately 80/20 domain-grouped split. The random
stratified split is provided only as a comparison baseline.
