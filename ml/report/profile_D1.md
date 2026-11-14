# PhishGuard — D1 Dataset Profile

**Generated:** 2026-11-14T23:20:18.001772Z
**Source file:** `Combined_Benign_Malicious_Dataset_CORRECTED.csv`
**SHA-256:** `429d6048d1e53b244789c5649914b340017687415ba11ad8897617fcc7eac38f`
**PSL source:** `C:\Users\dell\Desktop\7th sem\cyber security\Project\phishguard\lists\psl.dat`

---

## 1. Row counts

| Class | Count |
|-------|-------|
| Benign | 6,500 |
| Malicious | 4,500 |
| **Total** | **11,000** |

- Null URLs: **0**
- Null labels: **0**
- Exact duplicates (same URL+class): **152**
- Normalized duplicates (same norm_url+class): **153**
- Cross-class normalized duplicates: **0** (same normalized URL in both classes)

---

## 2. URL anomalies

| Anomaly | Count |
|---------|-------|
| Scheme-less (no http/https prefix) | 5,060 |
| Non-ASCII characters | 1 |
| Punycode / IDN hostnames | 4 |
| IP-address hosts | 119 |
| Normalization errors | 0 |

### Non-ASCII URLs

| # | Label | URL (repr, first 120 chars) |
|---|-------|-----------------------------|
| 1 | Malicious | `'\xa0http://www.isatechnology.com/training/49zvkrPOeNa346BZfzRNtmmpCNcRmGQHwN9bDIZ7aqABWR/'` |

> **Note:** The leading U+00A0 (non-breaking space) is stripped by N-01 before any other processing. The URL itself normalizes without error.

### Normalization-error URLs

*None — 0 normalization errors. The U+00A0-prefixed URL (Malicious, row above) normalizes cleanly via N-01.*

---

## 2b. Scheme distribution per class

| Class | Total | Scheme-less | % | HTTP (explicit) | % | HTTPS (explicit) | % |
|-------|-------|-------------|---|-----------------|---|------------------|---|
| Benign | 6,500 | 4,000 | 61.5% | 13 | 0.2% | 2,487 | 38.3% |
| Malicious | 4,500 | 1,060 | 23.6% | 2,829 | 62.9% | 611 | 13.6% |

> **Scheme-less skew:** Benign URLs are scheme-less at a much higher rate than Malicious.
> After N-02 prepends `http://`, `is_https=False` becomes artificially correlated with Benign.
> See `docs/ASSUMPTIONS.md` A-13 for proposed mitigations and the pending decision on N-02.

## 2c. Top scheme-less URL patterns per class

Pattern buckets: `bare_domain` (no slash, no query), `domain_path`, `domain_query`, `domain_path_query`.

### Benign

| Pattern | Count |
|---------|-------|
| `bare_domain` | 4,000 |

### Malicious

| Pattern | Count |
|---------|-------|
| `bare_domain` | 1,043 |
| `domain_path` | 17 |


---

## 3. URL length statistics (normalized, valid rows only)

| Metric | Benign | Malicious |
|--------|--------|-----------|
| mean | 27.03 | 69.71 |
| median | 25.0 | 59.0 |
| min | 11 | 15 |
| max | 281 | 779 |
| p95 | 44.0 | 170.0 |

---

## 4. Top 20 registrable domains per class

### Benign

| Rank | Domain | Count |
|------|--------|-------|
| 1 | microsoft.com | 221 |
| 2 | apple.com | 173 |
| 3 | tiktokcdn.com | 100 |
| 4 | google.com | 80 |
| 5 | azure.com | 70 |
| 6 | com.akadns.net | 66 |
| 7 | office.com | 58 |
| 8 | office.net | 53 |
| 9 | tiktokv.com | 42 |
| 10 | yahoo.com | 39 |
| 11 | live.com | 34 |
| 12 | facebook.com | 29 |
| 13 | tiktokcdn-us.com | 29 |
| 14 | aaplimg.com | 25 |
| 15 | bytefcdn-oversea.com | 25 |
| 16 | webex.com | 23 |
| 17 | worldfcdn2.com | 23 |
| 18 | msedge.net | 22 |
| 19 | tmall.com | 22 |
| 20 | googleusercontent.com | 21 |

### Malicious

| Rank | Domain | Count |
|------|--------|-------|
| 1 | 000webhostapp.com | 641 |
| 2 | 9779.info | 186 |
| 3 | google.com | 116 |
| 4 | beget.tech | 48 |
| 5 | pastehtml.com | 43 |
| 6 | alexanderperfumery.com | 21 |
| 7 | grasslandhotel.com.vn | 20 |
| 8 | hrdeptselfservice.com | 20 |
| 9 | saralaska.org | 17 |
| 10 | tanlaonline.com | 15 |
| 11 | pubyun.com | 14 |
| 12 | arvixeshared.com | 13 |
| 13 | club-liner.de | 13 |
| 14 | hc360.com | 12 |
| 15 | 3cf.ru | 12 |
| 16 | chinesevie.com | 12 |
| 17 | moretonenterprises.co.uk | 12 |
| 18 | xpj5988.com | 11 |
| 19 | esy.es | 11 |
| 20 | webnode.com | 11 |

### Domains appearing in BOTH classes (25 total)

| Domain |
|--------|
| alicdn.com |
| aliyun.com |
| baidu.com |
| bit.ly |
| blogspot.com.br |
| bootstrapcdn.com |
| cnzz.com |
| comcast.net |
| facebook.com |
| fonts.googleapis.com |
| free.fr |
| google.com |
| interia.pl |
| libero.it |
| maps.googleapis.com |
| qq.com |
| rb.gy |
| sapo.pt |
| secureserver.net |
| storage.googleapis.com |
| t.co |
| videodownloadconverter.com |
| weebly.com |
| youku.com |
| youtube.com |

---

## 5. Bare homepage share

A row is a 'bare homepage' if its path is empty or '/' and there is no query string.

| Class | Share |
|-------|-------|
| Benign | 98.7% |
| Malicious | 27.0% |

---

## 6. Hosting platform share

Platforms checked: `lists/hosting.json` (3 entries evaluated)

| Class | On hosting platform | Total | Share |
|-------|---------------------|-------|-------|
| Benign | 4 | 6,500 | 0.06% |
| Malicious | 656 | 4,500 | 14.58% |

---

## 7. Shortcut rule (illustrative)

> **Rule:** url_length <= 40 AND is_https → Benign

| Metric | Value |
|--------|-------|
| Accuracy | 62.34% |
| True Positives (Benign, correctly) | 2,428 |
| False Positives (Malicious, wrongly Benign) | 71 |
| False Negatives (Benign, wrongly Malicious) | 4,072 |
| True Negatives (Malicious, correctly) | 4,429 |

*Shortcut rule; not a model. Used to illustrate dataset separability.*

---

## 8. Shortcut baseline (PRD §7.2 step 4)

> Depth-2 decision tree on deployable features (scheme-stripped url_length, has_path, and TLD one-hot). 80/20 grouped split by registrable_domain, seed 42.

| Parameter | Value |
|-----------|-------|
| Split | 80/20 grouped by registrable_domain |
| Seed | 42 |
| Max depth | 2 |
| Hot TLDs (≥ 30 rows) | 27 |
| Train size | 8,780 |
| Test size | 2,220 |
| Group overlap | 0 (OK: True) |

### **Shortcut baseline (deployable features): 85.26%**
- *Features:* scheme-stripped url_length, has_path, TLD one-hot (N-13)
- *Comparison with is_https included:* **85.26%**

> [!NOTE]
> Shortcut baseline 85.26% < 95%. Data is not trivially shortcut-separable. Proceed to Chunk 3.

*Deployable baseline uses scheme-stripped length, has_path, and TLD (is_https dropped per N-13). Comparison baseline with is_https included for audit. If baseline reaches ≥ 95% balanced accuracy, PRD §7.2 step 4 requires stopping before model work.*

---

## 9. Review sample

Written to `C:\Users\dell\Desktop\7th sem\cyber security\Project\phishguard\data\review_sample.csv`.

| Class | Rows sampled |
|-------|-------------|
| Benign | 100 |
| Malicious | 100 |

**Manual action required:** spot-check these rows for label correctness and record the error rate in `data/PROVENANCE.md`.

---

*Profile is read-only. No data was modified. Cleaning is Chunk 3.*