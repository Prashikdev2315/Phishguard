#!/usr/bin/env python3
"""Validate and freeze PhishGuard Chunk 3 E1/E2 external evaluation sets.

Inputs must be collected from genuine sources. This tool never fabricates URLs.
E1 CSV: URL column (optional source column).
E2 CSV: URL, source, collected_at (ISO date), verified (true/false).
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ml.normalize import normalize


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read_csv(path: Path) -> List[dict]:
    with path.open('r', encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def norm_record(raw: str) -> Tuple[Optional[str], Optional[str]]:
    r = normalize(raw or '')
    if r.error or not r.registrable_domain:
        return None, None
    return r.normalized, r.registrable_domain


def write_csv(path: Path, rows: List[dict], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)


def build_e1(input_path: Path, root: Path, minimum_urls: int = 2000,
             minimum_domains: int = 800) -> dict:
    source = read_csv(input_path)
    if not source or 'URL' not in source[0]:
        raise ValueError('E1 input must be a CSV with a URL column.')
    by_domain: Dict[str, List[dict]] = {}
    rejected = Counter(); seen = set()
    for row in source:
        url, domain = norm_record(row.get('URL', ''))
        if not url or not domain:
            rejected['invalid_or_no_registrable_domain'] += 1; continue
        if (url, domain) in seen:
            rejected['duplicate'] += 1; continue
        seen.add((url, domain))
        # E1 must be a real inner-page URL, not a homepage/root URL.
        n = normalize(row['URL'])
        if not n.path or n.path == '/':
            rejected['homepage_not_inner_page'] += 1; continue
        by_domain.setdefault(domain, []).append({'URL': url, 'registrable_domain': domain,
                                                  'source': row.get('source', 'unspecified')})
    # Enforce 1–3 URLs per domain deterministically.
    selected = []
    for domain in sorted(by_domain):
        selected.extend(sorted(by_domain[domain], key=lambda x: x['URL'])[:3])
    domains = sorted({r['registrable_domain'] for r in selected})
    if len(selected) < minimum_urls or len(domains) < minimum_domains:
        raise ValueError('E1 insufficient: %d URLs from %d domains; require >=%d URLs and >=%d domains. No partial E1 published.' %
                         (len(selected), len(domains), minimum_urls, minimum_domains))
    # Stable, balanced domain-level split: no domain appears in both partitions.
    # Sort domains by their SHA-256 hash, then divide into two nearly equal groups.
    ranked_domains = sorted(
        domains,
        key=lambda d: hashlib.sha256(
            ('phishguard-e1-v1|' + d).encode()
        ).digest()
    )

    midpoint = len(ranked_domains) // 2
    train_domains = ranked_domains[:midpoint]
    hold_domains = ranked_domains[midpoint:]

    train_set = set(train_domains)
    hold_set = set(hold_domains)
    train = [r for r in selected if r['registrable_domain'] in train_set]
    hold = [r for r in selected if r['registrable_domain'] in hold_set]
    out = root / 'data' / 'external'
    write_csv(out / 'E1_training.csv', train, ['URL','registrable_domain','source'])
    write_csv(out / 'E1_holdout.csv', hold, ['URL','registrable_domain','source'])
    report = {'dataset':'E1','input_file':str(input_path),'input_sha256':sha256(input_path),
              'urls_accepted':len(selected),'domains':len(domains),'training_urls':len(train),
              'training_domains':len(train_set),'holdout_urls':len(hold),'holdout_domains':len(hold_set),
              'domain_overlap':len(train_set & hold_set),'max_urls_per_domain':3,
              'rejected':dict(rejected),'split':'sha256(phishguard-e1-v1|domain) ranked midpoint; balanced domain-level split',
              'status':'PASS' if len(selected)>=minimum_urls and len(domains)>=minimum_domains and not (train_set & hold_set) else 'FAIL'}
    (root/'data'/'reports'/'E1_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


def build_e2(input_path: Path, root: Path, d1_collection_date: str,
             minimum_urls: int = 500) -> dict:
    cutoff = date.fromisoformat(d1_collection_date)
    source = read_csv(input_path)
    required = {'URL','source','collected_at','verified'}
    if not source or not required.issubset(source[0]):
        raise ValueError('E2 CSV requires columns: URL, source, collected_at, verified.')
    d1_path = root/'data'/'processed'/'D1_cleaned.csv'
    if not d1_path.exists():
        raise FileNotFoundError('Build D1 first: data/processed/D1_cleaned.csv')
    d1_domains = set()
    for row in read_csv(d1_path):
        _, d = norm_record(row.get('URL',''))
        if d: d1_domains.add(d)
    accepted, rejected, seen = [], Counter(), set()
    allowed_sources = {'phishtank','openphish'}
    for row in source:
        url, domain = norm_record(row.get('URL',''))
        src = (row.get('source') or '').strip().lower()
        try: collected = date.fromisoformat((row.get('collected_at') or '')[:10])
        except ValueError: collected = None
        verified = (row.get('verified') or '').strip().lower() in {'1','true','yes','verified'}
        if not url or not domain: rejected['invalid_or_no_domain'] += 1; continue
        if src not in allowed_sources: rejected['unapproved_source'] += 1; continue
        if not verified: rejected['not_verified'] += 1; continue
        if collected is None or collected <= cutoff: rejected['not_after_d1_or_bad_date'] += 1; continue
        if domain in d1_domains: rejected['domain_overlaps_d1'] += 1; continue
        if (url,domain) in seen: rejected['duplicate'] += 1; continue
        seen.add((url,domain))
        accepted.append({'URL':url,'registrable_domain':domain,'source':src,'collected_at':collected.isoformat()})
    accepted.sort(key=lambda r:(r['collected_at'],r['registrable_domain'],r['URL']))
    if len(accepted) < minimum_urls:
        raise ValueError('E2 insufficient: %d verified eligible URLs; require >=%d. No partial E2 published.' % (len(accepted),minimum_urls))
    out=root/'data'/'external'/'E2_phishing.csv'
    write_csv(out,accepted,['URL','registrable_domain','source','collected_at'])
    report={'dataset':'E2','input_file':str(input_path),'input_sha256':sha256(input_path),
            'd1_collection_date':cutoff.isoformat(),'accepted_urls':len(accepted),
            'unique_domains':len({r['registrable_domain'] for r in accepted}),
            'd1_domain_overlap':0,'source_counts':dict(Counter(r['source'] for r in accepted)),
            'rejected':dict(rejected),'status':'PASS'}
    (root/'data'/'reports'/'E2_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    e1=sub.add_parser('e1'); e1.add_argument('--input',required=True); e1.add_argument('--root',default='.'); e1.add_argument('--minimum-urls',type=int,default=2000); e1.add_argument('--minimum-domains',type=int,default=800)
    e2=sub.add_parser('e2'); e2.add_argument('--input',required=True); e2.add_argument('--root',default='.'); e2.add_argument('--d1-date',required=True,help='D1 collection date YYYY-MM-DD from provenance'); e2.add_argument('--minimum-urls',type=int,default=500)
    a=p.parse_args(); root=Path(a.root).resolve(); inp=Path(a.input).resolve()
    try:
        result=build_e1(inp,root,a.minimum_urls,a.minimum_domains) if a.command=='e1' else build_e2(inp,root,a.d1_date,a.minimum_urls)
        print(json.dumps(result,indent=2)); return 0
    except Exception as exc:
        print('ERROR: '+str(exc),file=sys.stderr); return 2

if __name__=='__main__': raise SystemExit(main())
