#!/usr/bin/env python3
"""
tools/collect_e1.py — E1 benign URL collector for PhishGuard (Chunk 5c).

Reads data/external/tranco.csv (standard Tranco format: rank,domain),
samples domains stratified by rank band, then crawls each homepage and sitemap
to collect:
  - Up to 2-3 homepage deep links (source: homepage_link)
  - Up to 2 sitemap deep links (source: sitemap)
  - Up to 1 login/account-style path if found (source: login_page)
Respects robots.txt, 1 request/second/host, 10 s timeout, and user-agent string.

Outputs:
  data/external/E1_candidates.csv   — URL, domain, rank, collection_date, source
  data/reports/e1_crawl_summary.json — crawl summary (attempted, blocked, URLs/domain)
  data/reports/e1_crawl_summary.md  — markdown summary
  data/external/tranco_meta.json    — provenance

Usage:
    python -m tools.collect_e1 [--tranco data/external/tranco.csv]
                                [--out data/external/E1_candidates.csv]
                                [--sample-per-band 100,300,400]
                                [--max-domains 50]
                                [--seed 42]
                                [--resume]
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import logging
import os
import pathlib
import random
import sys
import time
import urllib.parse
import urllib.request
import urllib.robotparser
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("PHISHGUARD_ENV", "development")

from ml.psl import get_psl  # noqa: E402

LOGGER = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

USER_AGENT = "PhishGuard-E1Research/1.0 (academic; contact: project-maintainer)"
REQUEST_TIMEOUT = 10          # seconds per request
RATE_LIMIT_SECONDS = 1.0      # min seconds between requests to the same host
MIN_TOTAL_DOMAINS = 800

DEFAULT_SAMPLE = [100, 300, 400]

LOGIN_KEYWORDS = (
    "login", "signin", "sign-in", "log-in", "account",
    "auth", "portal", "session", "myaccount", "my-account",
    "user/login", "admin/login", "auth/login", "users/sign_in",
    "oauth", "sso"
)


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Minimal HTML <a href> extractor using stdlib only."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "a":
            for name, val in attrs:
                if name == "href" and val:
                    self.links.append(val.strip())


def extract_links(html: str) -> List[str]:
    extractor = _LinkExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.links


# ---------------------------------------------------------------------------
# Sitemap XML parser
# ---------------------------------------------------------------------------

def parse_sitemap(data: bytes) -> Tuple[List[str], List[str]]:
    """Extract page URLs and nested sitemap locations from XML (or gzipped XML)."""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError:
            return [], []
    try:
        root = ET.fromstring(data)
    except Exception:
        return [], []

    tag = root.tag.rsplit("}", 1)[-1].lower()
    locations = [
        elem.text.strip()
        for elem in root.iter()
        if elem.tag.rsplit("}", 1)[-1].lower() == "loc" and elem.text
    ]

    if tag == "sitemapindex":
        return [], locations[:20]
    if tag == "urlset":
        return locations, []
    return [], []


# ---------------------------------------------------------------------------
# Robots.txt and rate limiting
# ---------------------------------------------------------------------------

_robots_cache: Dict[str, Optional[urllib.robotparser.RobotFileParser]] = {}
_robots_sitemaps: Dict[str, List[str]] = {}
_last_request_time: Dict[str, float] = {}


def _rate_limit(host: str) -> None:
    """Enforce 1 request/second per host."""
    now = time.monotonic()
    last = _last_request_time.get(host, 0.0)
    wait = RATE_LIMIT_SECONDS - (now - last)
    if wait > 0:
        time.sleep(wait)
    _last_request_time[host] = time.monotonic()


def get_robots_and_sitemaps(host: str) -> Tuple[Optional[urllib.robotparser.RobotFileParser], List[str]]:
    """Fetch and parse robots.txt, returning (RobotFileParser, list_of_sitemap_urls)."""
    if host in _robots_cache:
        return _robots_cache[host], _robots_sitemaps.get(host, [])

    robots_url = f"https://{host}/robots.txt"
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(robots_url)
    sitemaps: List[str] = []

    try:
        _rate_limit(host)
        req = urllib.request.Request(robots_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            content = resp.read().decode("utf-8", errors="replace")

        lines = content.splitlines()
        rp.parse(lines)
        for line in lines:
            if line.strip().lower().startswith("sitemap:"):
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    sm = parts[1].strip()
                    if sm.startswith("http://") or sm.startswith("https://"):
                        sitemaps.append(sm)

        _robots_cache[host] = rp
        _robots_sitemaps[host] = sitemaps
        return rp, sitemaps
    except Exception:
        _robots_cache[host] = None
        _robots_sitemaps[host] = []
        return None, []


def can_crawl(url: str) -> bool:
    """Return True if robots.txt permits crawling the given URL."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    rp, _ = get_robots_and_sitemaps(host)
    if rp is None:
        return False
    return rp.can_fetch(USER_AGENT, url)


# ---------------------------------------------------------------------------
# HTTP fetch helpers
# ---------------------------------------------------------------------------

def fetch_url(url: str, only_html: bool = True) -> Optional[str]:
    """Fetch URL and return body as text, or None on failure."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    _rate_limit(host)
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            ct = resp.headers.get("Content-Type", "")
            if only_html and ("html" not in ct.lower() and ct):
                return None
            raw = resp.read(1 << 20)  # max 1 MB
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def fetch_bytes(url: str) -> Optional[bytes]:
    """Fetch URL and return body as raw bytes, or None on failure."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    _rate_limit(host)
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/xml,application/xml,application/x-gzip,*/*;q=0.8",
            },
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read(2 << 20)  # max 2 MB
        return raw
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PSL registrable domain
# ---------------------------------------------------------------------------

_psl = None

def _get_psl_once():
    global _psl
    if _psl is None:
        _psl = get_psl()
    return _psl


def registrable_domain(hostname: str) -> Optional[str]:
    """Return registrable domain (eTLD+1) for a hostname, or None."""
    psl = _get_psl_once()
    try:
        return psl.registrable_domain(hostname)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Login / Account detection
# ---------------------------------------------------------------------------

def is_login_like(url: str) -> bool:
    """Return True if path or query has login/account keywords."""
    p = urllib.parse.urlparse(url)
    path = p.path.lower()
    query = p.query.lower()
    return any(k in path or k in query for k in LOGIN_KEYWORDS)


# ---------------------------------------------------------------------------
# Domain collector
# ---------------------------------------------------------------------------

def collect_domain_urls(
    domain: str,
    rank: int,
    d1_domains: Set[str],
) -> Tuple[List[Tuple[str, str]], str]:
    """
    Collect diverse inner-page URLs for a single domain.
    Returns ([(url, source), ...], status_string)
    Where source is 'homepage_link', 'sitemap', or 'login_page'.
    """
    homepage = f"https://{domain}/"

    # Skip D1 domains
    reg = registrable_domain(domain)
    if reg and reg in d1_domains:
        return [], "skipped_d1"

    # Check robots.txt for homepage
    rp, sitemaps_from_robots = get_robots_and_sitemaps(domain)
    if rp is None or not rp.can_fetch(USER_AGENT, homepage):
        return [], "blocked_robots"

    # 1. Fetch homepage
    html = fetch_url(homepage, only_html=True)
    if not html:
        return [], "failed_fetch"

    base_reg = reg or domain
    raw_links = extract_links(html)

    # Filter homepage links
    homepage_candidates: List[str] = []
    seen_urls: Set[str] = set()

    for href in raw_links:
        try:
            abs_url = urllib.parse.urljoin(homepage, href)
        except Exception:
            continue
        p = urllib.parse.urlparse(abs_url)
        if p.scheme != "https":
            continue
        link_reg = registrable_domain(p.netloc)
        if not link_reg or link_reg != base_reg:
            continue
        path = p.path.rstrip("/")
        if not path:
            continue
        clean = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
        if clean not in seen_urls:
            seen_urls.add(clean)
            homepage_candidates.append(clean)

    # 2. Check sitemaps
    sitemap_candidates: List[str] = []
    sitemap_urls_to_try = list(sitemaps_from_robots)
    if not sitemap_urls_to_try:
        sitemap_urls_to_try.append(f"https://{domain}/sitemap.xml")

    for sm_url in sitemap_urls_to_try[:2]:
        if rp.can_fetch(USER_AGENT, sm_url):
            sm_data = fetch_bytes(sm_url)
            if sm_data:
                urls, nested = parse_sitemap(sm_data)
                # If sitemapindex, try first nested sitemap
                if not urls and nested:
                    sub_sm = nested[0]
                    if rp.can_fetch(USER_AGENT, sub_sm):
                        sub_data = fetch_bytes(sub_sm)
                        if sub_data:
                            urls, _ = parse_sitemap(sub_data)

                for u in urls:
                    p = urllib.parse.urlparse(u)
                    if p.scheme != "https":
                        continue
                    if registrable_domain(p.netloc) != base_reg:
                        continue
                    if not p.path.rstrip("/"):
                        continue
                    clean = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
                    if clean not in seen_urls:
                        seen_urls.add(clean)
                        sitemap_candidates.append(clean)
                if sitemap_candidates:
                    break

    # 3. Categorize into sources: login_page, sitemap, homepage_link
    selected: List[Tuple[str, str]] = []
    all_candidates = [(u, "sitemap") for u in sitemap_candidates] + [(u, "homepage") for u in homepage_candidates]

    # Up to 1 login/account-style path
    login_matches = [u for u, src in all_candidates if is_login_like(u)]
    selected_login: Optional[str] = None
    if login_matches:
        selected_login = login_matches[0]
        selected.append((selected_login, "login_page"))

    # Up to 2 sitemap URLs (excluding login)
    sitemap_filtered = [u for u in sitemap_candidates if u != selected_login and not is_login_like(u)]
    sitemap_filtered.sort(key=lambda u: len(urllib.parse.urlparse(u).path.split("/")), reverse=True)
    for u in sitemap_filtered[:2]:
        selected.append((u, "sitemap"))

    # Up to 2 (or 3 if no sitemap URLs) homepage links (varied depth, excluding login/sitemap)
    already_selected_urls = {u for u, s in selected}
    hp_filtered = [u for u in homepage_candidates if u not in already_selected_urls and not is_login_like(u)]

    by_depth: Dict[int, List[str]] = {}
    for u in hp_filtered:
        d = len([seg for seg in urllib.parse.urlparse(u).path.split("/") if seg])
        by_depth.setdefault(d, []).append(u)

    max_hp = 3 if len([s for _, s in selected if s == "sitemap"]) == 0 else 2
    hp_selected: List[str] = []
    for d in sorted(by_depth.keys()):
        if len(hp_selected) >= max_hp:
            break
        hp_selected.append(by_depth[d][0])

    for u in hp_selected:
        selected.append((u, "homepage_link"))

    if not selected:
        return [], "no_links"

    return selected, "ok"


# ---------------------------------------------------------------------------
# Tranco loading and stratified sampling
# ---------------------------------------------------------------------------

def load_tranco(path: pathlib.Path) -> Tuple[List[Tuple[int, str]], Optional[str], Optional[str]]:
    """Load Tranco CSV (rank,domain)."""
    rows: List[Tuple[int, str]] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        for line in reader:
            if not line:
                continue
            if line[0].strip().lower() in ("rank", "#"):
                continue
            try:
                rank = int(line[0].strip())
                domain = line[1].strip().lower()
                if domain and rank > 0:
                    rows.append((rank, domain))
            except (ValueError, IndexError):
                continue

    list_id: Optional[str] = None
    list_date: Optional[str] = None
    meta_path = path.parent / "tranco_meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            list_id = meta.get("list_id")
            list_date = meta.get("list_date")
        except Exception:
            pass

    return rows, list_id, list_date


def stratified_sample(
    rows: List[Tuple[int, str]],
    band_sizes: List[int],
    seed: int,
) -> List[Tuple[int, str]]:
    """Stratified sample across rank bands: 1-1k, 1k-10k, 10k-100k."""
    bands = [
        [(r, d) for r, d in rows if 1 <= r <= 1_000],
        [(r, d) for r, d in rows if 1_001 <= r <= 10_000],
        [(r, d) for r, d in rows if 10_001 <= r <= 100_000],
    ]
    rng = random.Random(seed)
    sampled: List[Tuple[int, str]] = []
    for i, (band, n) in enumerate(zip(bands, band_sizes)):
        available = min(n, len(band))
        chosen = rng.sample(band, available)
        sampled.extend(chosen)
    sampled.sort(key=lambda x: x[0])
    return sampled


def load_d1_domains(root: pathlib.Path) -> Set[str]:
    """Load registrable domains present in D1_cleaned.csv."""
    d1_path = root / "data" / "processed" / "D1_cleaned.csv"
    if not d1_path.exists():
        return set()
    domains: Set[str] = set()
    with d1_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            reg = row.get("registrable_domain", "").strip()
            if reg:
                domains.add(reg)
    return domains


def load_checkpoint(checkpoint_path: pathlib.Path) -> Set[int]:
    if not checkpoint_path.exists():
        return set()
    done: Set[int] = set()
    with checkpoint_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.isdigit():
                done.add(int(line))
    return done


def append_checkpoint(checkpoint_path: pathlib.Path, rank: int) -> None:
    with checkpoint_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{rank}\n")


# ---------------------------------------------------------------------------
# Main collection orchestrator
# ---------------------------------------------------------------------------

def collect(
    tranco_path: pathlib.Path,
    out_path: pathlib.Path,
    band_sizes: List[int],
    seed: int,
    resume: bool,
    max_domains: Optional[int],
    root: pathlib.Path,
) -> dict:
    if not tranco_path.exists():
        LOGGER.error(
            "Tranco CSV not found at %s. Download from https://tranco-list.eu/ and place it there.",
            tranco_path,
        )
        sys.exit(1)

    LOGGER.info("Loading Tranco list from %s ...", tranco_path)
    rows, list_id, list_date = load_tranco(tranco_path)
    d1_domains = load_d1_domains(root)
    sampled = stratified_sample(rows, band_sizes, seed)

    if max_domains is not None and max_domains > 0:
        LOGGER.info("Applying --max-domains limit: capping sample at %d domains.", max_domains)
        sampled = sampled[:max_domains]

    checkpoint_path = out_path.parent / ".e1_checkpoint.txt"
    done_ranks = load_checkpoint(checkpoint_path) if resume else set()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not (resume and out_path.exists())
    out_fh = out_path.open("a" if resume else "w", encoding="utf-8", newline="")
    writer = csv.writer(out_fh)
    if write_header:
        writer.writerow(["URL", "domain", "rank", "collection_date", "source"])

    total_written = 0
    domains_attempted = 0
    domains_succeeded = 0
    domains_blocked = 0
    domains_failed_fetch = 0
    domains_skipped_d1 = 0
    domains_no_links = 0
    urls_by_source: Dict[str, int] = {"homepage_link": 0, "sitemap": 0, "login_page": 0}
    urls_per_domain_list: List[dict] = []
    collection_date = datetime.now(timezone.utc).date().isoformat()

    for rank, domain in sampled:
        if rank in done_ranks:
            continue

        domains_attempted += 1
        LOGGER.info("Crawling rank=%d domain=%s (%d/%d) ...", rank, domain, domains_attempted, len(sampled))

        try:
            urls_with_sources, status = collect_domain_urls(domain, rank, d1_domains)
        except Exception as exc:
            LOGGER.debug("Error crawling %s: %s", domain, exc)
            urls_with_sources, status = [], "failed_fetch"

        if status == "ok" and urls_with_sources:
            domains_succeeded += 1
            for url, src in urls_with_sources:
                writer.writerow([url, domain, rank, collection_date, src])
                total_written += 1
                urls_by_source[src] = urls_by_source.get(src, 0) + 1
            out_fh.flush()
            urls_per_domain_list.append({
                "domain": domain,
                "rank": rank,
                "count": len(urls_with_sources),
                "sources": [s for _, s in urls_with_sources],
            })
        elif status == "blocked_robots":
            domains_blocked += 1
        elif status == "skipped_d1":
            domains_skipped_d1 += 1
        elif status == "failed_fetch":
            domains_failed_fetch += 1
        elif status == "no_links":
            domains_no_links += 1

        append_checkpoint(checkpoint_path, rank)

    out_fh.close()

    dist: Dict[str, int] = {"0": domains_attempted - domains_succeeded, "1": 0, "2": 0, "3": 0, "4": 0, "5+": 0}
    for item in urls_per_domain_list:
        c = item["count"]
        if c >= 5:
            dist["5+"] += 1
        else:
            dist[str(c)] = dist.get(str(c), 0) + 1

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "tranco_path": str(tranco_path),
        "tranco_list_id": list_id,
        "tranco_list_date": list_date,
        "seed": seed,
        "band_sizes": band_sizes,
        "max_domains_option": max_domains,
        "domains_sampled": len(sampled),
        "domains_attempted": domains_attempted,
        "domains_succeeded": domains_succeeded,
        "domains_blocked_robots": domains_blocked,
        "domains_failed_fetch": domains_failed_fetch,
        "domains_skipped_d1": domains_skipped_d1,
        "domains_no_links": domains_no_links,
        "total_urls_collected": total_written,
        "urls_by_source": urls_by_source,
        "urls_per_domain_distribution": dist,
        "urls_per_domain": urls_per_domain_list,
        "output_file": str(out_path),
    }

    rep_dir = root / "data" / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)
    summary_json_path = rep_dir / "e1_crawl_summary.json"
    summary_json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    md_lines = [
        "# PhishGuard — E1 Crawl Summary Report",
        "",
        f"Generated: {summary['generated_at_utc']}",
        "",
        "## Overview",
        "",
        f"- **Tranco List:** `{list_id or 'unknown'}` ({list_date or 'unknown'})",
        f"- **Domains Attempted:** {domains_attempted:,}",
        f"- **Domains Succeeded (≥1 URL):** {domains_succeeded:,}",
        f"- **Domains Blocked (robots.txt):** {domains_blocked:,}",
        f"- **Domains Failed (fetch/timeout):** {domains_failed_fetch:,}",
        f"- **Domains Skipped (in D1):** {domains_skipped_d1:,}",
        f"- **Total URLs Collected:** {total_written:,}",
        "",
        "## URLs by Source",
        "",
        "| Source | Count | Share (%) |",
        "|--------|------:|----------:|",
    ]
    for src_name, count in urls_by_source.items():
        pct = (count / total_written * 100) if total_written > 0 else 0.0
        md_lines.append(f"| `{src_name}` | {count:,} | {pct:.1f}% |")

    md_lines += [
        "",
        "## URLs per Domain Distribution",
        "",
        "| URLs Collected | Number of Domains |",
        "|----------------|------------------:|",
    ]
    for k, v in dist.items():
        md_lines.append(f"| {k} | {v:,} |")

    summary_md_path = rep_dir / "e1_crawl_summary.md"
    summary_md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    meta_path = out_path.parent / "tranco_meta.json"
    meta_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    LOGGER.info("Crawl summary written to %s and %s", summary_json_path, summary_md_path)
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect E1 benign URLs from Tranco list via HTML links and sitemaps."
    )
    parser.add_argument(
        "--tranco",
        default=str(ROOT / "data" / "external" / "tranco.csv"),
        help="Path to Tranco CSV (rank,domain). Default: data/external/tranco.csv",
    )
    parser.add_argument(
        "--out",
        default=str(ROOT / "data" / "external" / "E1_candidates.csv"),
        help="Output CSV path. Default: data/external/E1_candidates.csv",
    )
    parser.add_argument(
        "--sample-per-band",
        default="100,300,400",
        help="Comma-separated sample counts for bands 1-1k, 1k-10k, 10k-100k. Default: 100,300,400",
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=None,
        help="Maximum number of domains to attempt. Default: None (all sampled)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for stratified sampling. Default: 42",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from checkpoint (append to existing output file).",
    )
    args = parser.parse_args()

    try:
        band_sizes = [int(x.strip()) for x in args.sample_per_band.split(",")]
    except ValueError:
        parser.error("--sample-per-band must be comma-separated integers, e.g. 100,300,400")
        return

    if len(band_sizes) != 3:
        parser.error("--sample-per-band requires exactly 3 values.")

    collect(
        tranco_path=pathlib.Path(args.tranco),
        out_path=pathlib.Path(args.out),
        band_sizes=band_sizes,
        seed=args.seed,
        resume=args.resume,
        max_domains=args.max_domains,
        root=ROOT,
    )


if __name__ == "__main__":
    main()
