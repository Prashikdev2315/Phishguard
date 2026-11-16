#!/usr/bin/env python3
"""
tools/collect_e1.py — E1 benign URL collector for PhishGuard.

Reads data/external/tranco.csv (standard Tranco format: rank,domain),
samples 800+ domains stratified by rank band, then crawls each homepage
to collect up to 3 same-registrable-domain https:// links with a
non-empty path, respecting robots.txt and rate limits.

Output:
  data/external/E1_candidates.csv   — URL, domain, rank, collection_date
  data/external/tranco_meta.json    — provenance (list ID/date, run timestamp)

Usage:
    python -m tools.collect_e1 [--tranco data/external/tranco.csv]
                                [--out data/external/E1_candidates.csv]
                                [--sample-per-band 100,300,400]
                                [--seed 42]
                                [--resume]
"""
from __future__ import annotations

import argparse
import csv
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
MAX_LINKS_PER_DOMAIN = 3
MIN_TOTAL_DOMAINS = 800

# Default band sizes (1-1k, 1k-10k, 10k-100k)
DEFAULT_SAMPLE = [100, 300, 400]


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
# Robots.txt helper
# ---------------------------------------------------------------------------

_robots_cache: Dict[str, urllib.robotparser.RobotFileParser] = {}
_last_request_time: Dict[str, float] = {}


def _rate_limit(host: str) -> None:
    """Enforce 1 request/second per host."""
    now = time.monotonic()
    last = _last_request_time.get(host, 0.0)
    wait = RATE_LIMIT_SECONDS - (now - last)
    if wait > 0:
        time.sleep(wait)
    _last_request_time[host] = time.monotonic()


def can_crawl(url: str) -> bool:
    """Return True if robots.txt permits crawling the given URL."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    base = f"{parsed.scheme}://{host}"
    robots_url = base + "/robots.txt"

    if host not in _robots_cache:
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        try:
            _rate_limit(host)
            req = urllib.request.Request(robots_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                content = resp.read().decode("utf-8", errors="replace")
            rp.parse(content.splitlines())
        except Exception:
            # Cannot fetch robots.txt → skip domain entirely (conservative)
            _robots_cache[host] = None  # type: ignore[assignment]
            return False
        _robots_cache[host] = rp

    rp = _robots_cache.get(host)
    if rp is None:
        return False
    return rp.can_fetch(USER_AGENT, url)


# ---------------------------------------------------------------------------
# HTTP fetch helper
# ---------------------------------------------------------------------------

def fetch_url(url: str) -> Optional[str]:
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
            # Respect content type — only parse text/html
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct.lower() and ct:
                return None
            raw = resp.read(1 << 20)  # max 1 MB
        return raw.decode("utf-8", errors="replace")
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
# Domain link collector
# ---------------------------------------------------------------------------

def collect_links_for_domain(domain: str, rank: int, d1_domains: Set[str]) -> List[str]:
    """
    Crawl https://domain/ and return up to 3 https links with:
      - same registrable domain as `domain`
      - non-empty, non-root path
      - varied depth (prefer diversity across depth-1, depth-2, depth-3+)
    Returns empty list if robots.txt unavailable or domain in D1.
    """
    homepage = f"https://{domain}/"

    # Skip D1 domains
    reg = registrable_domain(domain)
    if reg and reg in d1_domains:
        LOGGER.debug("Skipping D1 domain: %s", domain)
        return []

    # Check robots.txt
    if not can_crawl(homepage):
        return []

    html = fetch_url(homepage)
    if not html:
        return []

    raw_links = extract_links(html)

    # Resolve relative links and filter
    base_reg = reg or domain
    seen: Set[str] = set()
    by_depth: Dict[int, List[str]] = {}  # depth -> list of candidate URLs

    for href in raw_links:
        try:
            abs_url = urllib.parse.urljoin(homepage, href)
        except Exception:
            continue

        p = urllib.parse.urlparse(abs_url)

        # Must be https
        if p.scheme != "https":
            continue

        # Same registrable domain
        link_reg = registrable_domain(p.netloc)
        if not link_reg or link_reg != base_reg:
            continue

        # Non-empty, non-root path
        path = p.path.rstrip("/")
        if not path or path == "":
            continue

        # Clean URL (drop fragment, keep query)
        clean = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
        if clean in seen:
            continue
        seen.add(clean)

        # Compute depth = number of non-empty path segments
        depth = len([seg for seg in p.path.split("/") if seg])
        by_depth.setdefault(depth, []).append(clean)

    # Pick URLs with varied depth: one from each depth level up to MAX_LINKS_PER_DOMAIN
    result: List[str] = []
    for depth in sorted(by_depth.keys()):
        if len(result) >= MAX_LINKS_PER_DOMAIN:
            break
        candidates = by_depth[depth]
        result.append(candidates[0])  # first seen at this depth

    return result[:MAX_LINKS_PER_DOMAIN]


# ---------------------------------------------------------------------------
# Tranco loading and stratified sampling
# ---------------------------------------------------------------------------

def load_tranco(path: pathlib.Path) -> Tuple[List[Tuple[int, str]], Optional[str], Optional[str]]:
    """
    Load Tranco CSV. Standard format: rank,domain (no header, or with header).
    Returns ([(rank, domain), ...], list_id, list_date).
    list_id/list_date are read from tranco_meta.json if present alongside the CSV,
    otherwise None.
    """
    rows: List[Tuple[int, str]] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        for line in reader:
            if not line:
                continue
            # Skip header rows like "rank,domain"
            if line[0].strip().lower() in ("rank", "#"):
                continue
            try:
                rank = int(line[0].strip())
                domain = line[1].strip().lower()
                if domain and rank > 0:
                    rows.append((rank, domain))
            except (ValueError, IndexError):
                continue

    # Try loading metadata from sibling json
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
    """
    Stratified sample across rank bands:
      band 0: ranks   1 –   1,000   → band_sizes[0] domains
      band 1: ranks 1,001 – 10,000  → band_sizes[1] domains
      band 2: ranks 10,001 – 100,000 → band_sizes[2] domains
    """
    bands = [
        [(r, d) for r, d in rows if 1 <= r <= 1_000],
        [(r, d) for r, d in rows if 1_001 <= r <= 10_000],
        [(r, d) for r, d in rows if 10_001 <= r <= 100_000],
    ]
    rng = random.Random(seed)
    sampled: List[Tuple[int, str]] = []
    for i, (band, n) in enumerate(zip(bands, band_sizes)):
        available = min(n, len(band))
        if available < n:
            LOGGER.warning(
                "Band %d has only %d domains (requested %d); using all.",
                i, available, n,
            )
        chosen = rng.sample(band, available)
        sampled.extend(chosen)
    sampled.sort(key=lambda x: x[0])
    return sampled


# ---------------------------------------------------------------------------
# D1 domain exclusion
# ---------------------------------------------------------------------------

def load_d1_domains(root: pathlib.Path) -> Set[str]:
    """Load all registrable domains already present in D1_cleaned.csv."""
    d1_path = root / "data" / "processed" / "D1_cleaned.csv"
    if not d1_path.exists():
        LOGGER.warning("D1_cleaned.csv not found at %s — no D1 exclusion applied.", d1_path)
        return set()

    domains: Set[str] = set()
    with d1_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            reg = row.get("registrable_domain", "").strip()
            if reg:
                domains.add(reg)
    LOGGER.info("Loaded %d D1 registrable domains for exclusion.", len(domains))
    return domains


# ---------------------------------------------------------------------------
# Checkpoint (resume support)
# ---------------------------------------------------------------------------

def load_checkpoint(checkpoint_path: pathlib.Path) -> Set[int]:
    """Return set of already-processed ranks."""
    if not checkpoint_path.exists():
        return set()
    done: Set[int] = set()
    with checkpoint_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.isdigit():
                done.add(int(line))
    LOGGER.info("Checkpoint: %d ranks already processed.", len(done))
    return done


def append_checkpoint(checkpoint_path: pathlib.Path, rank: int) -> None:
    with checkpoint_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{rank}\n")


# ---------------------------------------------------------------------------
# Main collection loop
# ---------------------------------------------------------------------------

def collect(
    tranco_path: pathlib.Path,
    out_path: pathlib.Path,
    band_sizes: List[int],
    seed: int,
    resume: bool,
    root: pathlib.Path,
) -> None:
    if not tranco_path.exists():
        LOGGER.error(
            "Tranco CSV not found at %s. "
            "Download from https://tranco-list.eu/ and place it there.",
            tranco_path,
        )
        sys.exit(1)

    LOGGER.info("Loading Tranco list from %s ...", tranco_path)
    rows, list_id, list_date = load_tranco(tranco_path)
    LOGGER.info("Loaded %d Tranco entries.", len(rows))

    d1_domains = load_d1_domains(root)

    sampled = stratified_sample(rows, band_sizes, seed)
    LOGGER.info(
        "Sampled %d domains across bands %s (seed=%d).",
        len(sampled), band_sizes, seed,
    )

    # Write / append checkpoint
    checkpoint_path = out_path.parent / ".e1_checkpoint.txt"
    done_ranks = load_checkpoint(checkpoint_path) if resume else set()

    # Write output CSV header if starting fresh
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not (resume and out_path.exists())
    out_fh = out_path.open("a" if resume else "w", encoding="utf-8", newline="")
    writer = csv.writer(out_fh)
    if write_header:
        writer.writerow(["URL", "domain", "rank", "collection_date"])

    total_written = 0
    skipped = 0
    failed = 0
    collection_date = datetime.now(timezone.utc).date().isoformat()

    for rank, domain in sampled:
        if rank in done_ranks:
            LOGGER.debug("Skipping already-processed rank %d (%s).", rank, domain)
            continue

        LOGGER.info("Crawling rank=%d domain=%s ...", rank, domain)
        try:
            links = collect_links_for_domain(domain, rank, d1_domains)
        except Exception as exc:
            LOGGER.debug("Error on %s: %s", domain, exc)
            links = []
            failed += 1

        if not links:
            skipped += 1
        else:
            for url in links:
                writer.writerow([url, domain, rank, collection_date])
                total_written += 1
            out_fh.flush()

        append_checkpoint(checkpoint_path, rank)

    out_fh.close()

    LOGGER.info(
        "Done. URLs written=%d, domains skipped/no-links=%d, domains failed=%d.",
        total_written, skipped, failed,
    )

    # Write provenance
    meta = {
        "tranco_path": str(tranco_path),
        "tranco_list_id": list_id,
        "tranco_list_date": list_date,
        "collection_run_utc": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "band_sizes": band_sizes,
        "domains_sampled": len(sampled),
        "urls_collected": total_written,
        "domains_skipped_no_links_or_robots": skipped,
        "domains_failed_fetch": failed,
        "d1_domains_excluded": len(d1_domains),
        "output_file": str(out_path),
    }
    meta_path = out_path.parent / "tranco_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Provenance written to %s", meta_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect E1 benign URLs from Tranco list via HTML link crawling."
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

    total = sum(band_sizes)
    if total < MIN_TOTAL_DOMAINS:
        LOGGER.warning(
            "Total sample %d < minimum %d. Consider increasing --sample-per-band.",
            total, MIN_TOTAL_DOMAINS,
        )

    collect(
        tranco_path=pathlib.Path(args.tranco),
        out_path=pathlib.Path(args.out),
        band_sizes=band_sizes,
        seed=args.seed,
        resume=args.resume,
        root=ROOT,
    )


if __name__ == "__main__":
    main()
