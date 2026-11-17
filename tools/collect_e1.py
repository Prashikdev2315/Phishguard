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
import re
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

USER_AGENT = "PhishGuard-E1Research/1.0 (+https://github.com/phishguard-project/phishguard; academic research; 1 req/sec/host)"
REQUEST_TIMEOUT = 8           # seconds per request
RATE_LIMIT_SECONDS = 1.0      # min seconds between requests to the same host
MAX_RETRIES = 1               # hard cap on HTTP attempts (1 attempt, no retry loops)
MIN_TOTAL_DOMAINS = 1500
MIN_TOTAL_URLS = 5000
MAX_PER_DOMAIN = 5

DEFAULT_SAMPLE = [500, 750, 750, 750]

LOGIN_TOKEN_PATTERN = re.compile(
    r"(?:^|[/_.\?&#=\-])(login|signin|sign-in|log-in|signup|sign-up|register|account|accounts|myaccount|my-account|auth|sso|oauth)(?:$|[/_.\?&#=\-])",
    re.I,
)

LOGIN_KEYWORDS = (
    "login", "signin", "sign-in", "log-in", "account",
    "auth", "portal", "session", "myaccount", "my-account",
    "user/login", "admin/login", "auth/login", "users/sign_in",
    "oauth", "sso", "signup", "sign-up", "register", "join",
    "enroll", "user/register", "profile",
)

EXCLUDED_MARKETING_PATTERN = re.compile(
    r"/(?:features|blog|news|legals|legal|terms|privacy|docs|documentation|pricing|about|marketing|products)/",
    re.I,
)

ADULT_TLDS = (".xxx", ".adult", ".porn", ".sex")
ADULT_KEYWORDS = (
    "porn", "xxx", "escort", "fatalmodel", "camgirl", "nsfw",
    "erotic", "fetish", "stripchat", "chaturbate", "adultwork",
    "redtube", "youporn", "xhamster", "xnxx", "xvideos", "onlyfans",
)

INDIAN_TLDS = (
    ".in", ".co.in", ".gov.in", ".org.in", ".net.in", ".ac.in",
    ".edu.in", ".res.in", ".nic.in", ".mil.in"
)

INDIAN_DOMAINS = {
    "flipkart.com", "paytm.com", "zomato.com", "swiggy.com", "myntra.com",
    "bookmyshow.com", "makemytrip.com", "naukri.com", "irctc.co.in", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "incometax.gov.in", "uidai.gov.in",
    "hotstar.com", "jio.com", "airtel.in", "timesofindia.indiatimes.com",
    "indiatimes.com", "ndtv.com", "thehindu.com", "hindustantimes.com",
    "moneycontrol.com", "zerodha.com", "groww.in", "upstox.com"
}

INDIAN_LANG_INDICATORS = (
    "/hi/", "/ta/", "/te/", "/bn/", "/mr/", "/gu/", "/kn/", "/ml/", "/pa/",
    "/hindi/", "/tamil/", "/telugu/", "/bengali/", "/marathi/", "/gujarati/",
    "hi.wikipedia.org", "ta.wikipedia.org", "te.wikipedia.org", "bn.wikipedia.org",
    "mr.wikipedia.org", "gu.wikipedia.org", "kn.wikipedia.org", "ml.wikipedia.org",
    "pa.wikipedia.org", "hl=hi", "hl=ta", "hl=te", "hl=bn", "hl=mr", "lang=hi",
)

SEED_LIST: Dict[str, List[str]] = {
    "youtube.com": [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com/results?search_query=cybersecurity",
        "https://www.youtube.com/account",
    ],
    "flipkart.com": [
        "https://www.flipkart.com/search?q=laptop",
        "https://www.flipkart.com/apple-iphone-13-midnight-128-gb/p/itmca5553dd3f76f",
        "https://www.flipkart.com/account/login?ret=/",
    ],
    "amazon.in": [
        "https://www.amazon.in/s?k=books",
        "https://www.amazon.in/dp/B08L5VJY37",
        "https://www.amazon.in/ap/signin?openid.mode=checkid_setup",
    ],
    "google.com": [
        "https://www.google.com/search?q=phishing+detection",
        "https://www.google.com/maps/@28.6139,77.2090,13z",
        "https://docs.google.com/document/u/0/",
    ],
    "wikipedia.org": [
        "https://en.wikipedia.org/wiki/Computer_security",
        "https://en.wikipedia.org/w/index.php?search=machine+learning",
        "https://en.wikipedia.org/w/index.php?title=Special:UserLogin",
    ],
    "github.com": [
        "https://github.com/search?q=security",
        "https://github.com/login",
        "https://github.com/settings/profile",
    ],
    "irctc.co.in": [
        "https://www.irctc.co.in/nget/train-search",
        "https://www.irctc.co.in/nget/profile/user-login",
        "https://www.irctc.co.in/nget/profile/user-registration",
    ],
    "sbi.co.in": [
        "https://retail.onlinesbi.sbi/retail/login.htm",
        "https://sbi.co.in/web/personal-banking/accounts",
        "https://sbi.co.in/web/quick-links",
    ],
    "paytm.com": [
        "https://paytm.com/recharge",
        "https://paytm.com/care/ticket",
        "https://tickets.paytm.com/flights/",
    ],
    "myntra.com": [
        "https://www.myntra.com/men-tshirts",
        "https://www.myntra.com/login",
        "https://www.myntra.com/checkout/cart",
    ],
    "zomato.com": [
        "https://www.zomato.com/delivery",
        "https://www.zomato.com/users/profile",
        "https://www.zomato.com/partner_with_us",
    ],
    "swiggy.com": [
        "https://www.swiggy.com/restaurants",
        "https://www.swiggy.com/my-account",
        "https://www.swiggy.com/checkout",
    ],
    "hdfcbank.com": [
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://www.hdfcbank.com/personal/ways-to-bank/online-banking/net-banking",
        "https://www.hdfcbank.com/personal/save/accounts",
    ],
    "icicibank.com": [
        "https://infinity.icicibank.com/corp/AuthenticationController",
        "https://www.icicibank.com/personal-banking/accounts/savings-account",
        "https://www.icicibank.com/search?q=fixed+deposit",
    ],
    "linkedin.com": [
        "https://www.linkedin.com/login",
        "https://www.linkedin.com/feed/",
        "https://www.linkedin.com/search/results/all/?keywords=security",
    ],
    "instagram.com": [
        "https://www.instagram.com/accounts/login/",
        "https://www.instagram.com/explore/",
        "https://www.instagram.com/accounts/emailsignup/",
    ],
    "facebook.com": [
        "https://www.facebook.com/login/",
        "https://www.facebook.com/r.php",
        "https://www.facebook.com/watch/",
    ],
    "x.com": [
        "https://x.com/login",
        "https://x.com/i/flow/signup",
        "https://x.com/explore",
    ],
    "microsoft.com": [
        "https://login.microsoftonline.com/",
        "https://www.microsoft.com/en-us/store/b/home",
        "https://account.microsoft.com/account",
    ],
    "apple.com": [
        "https://appleid.apple.com/sign-in",
        "https://www.apple.com/shop/buy-iphone",
        "https://support.apple.com/en-us",
    ],
    "netflix.com": [
        "https://www.netflix.com/login",
        "https://www.netflix.com/signup",
        "https://www.netflix.com/browse",
    ],
    "bookmyshow.com": [
        "https://in.bookmyshow.com/explore/movies",
        "https://in.bookmyshow.com/my-profile",
        "https://in.bookmyshow.com/cinemas",
    ],
    "makemytrip.com": [
        "https://www.makemytrip.com/flights/",
        "https://www.makemytrip.com/hotels/",
        "https://www.makemytrip.com/account/login",
    ],
    "naukri.com": [
        "https://www.naukri.com/nlogin/login",
        "https://www.naukri.com/it-jobs",
        "https://www.naukri.com/account/createaccount",
    ],
    "incometax.gov.in": [
        "https://eportal.incometax.gov.in/iec/foservices/#/login",
        "https://www.incometax.gov.in/iec/foportal/",
        "https://eportal.incometax.gov.in/iec/foservices/#/pre-login/register",
    ],
    "uidai.gov.in": [
        "https://myaadhaar.uidai.gov.in/",
        "https://uidai.gov.in/en/my-aadhaar/get-aadhaar.html",
        "https://appointments.uidai.gov.in/bookappointment.aspx",
    ],
}


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
# Login / Account and Content detection
# ---------------------------------------------------------------------------

def is_adult_domain(domain: str) -> bool:
    """Return True if domain matches adult TLDs or adult content keywords."""
    d = domain.lower()
    if any(d.endswith(tld) for tld in ADULT_TLDS):
        return True
    parts = re.split(r"[.-]", d)
    return any(k in parts or k in d for k in ADULT_KEYWORDS)


def is_login_like(url: str) -> bool:
    """Return True if normalized decoded path, query, or fragment contains login/account tokens.

    Based on the normalized decoded URL string that feature computation uses,
    with boundary matching so 'sso' does not match 'associate', 'portal' does not
    match 'foportal', and fragment routes like '#/login' are evaluated.
    """
    try:
        from ml.normalize import normalize
        r = normalize(url)
        p = urllib.parse.urlsplit(r.decoded_url)
        target = p.path + ("?" + p.query if p.query else "") + ("#" + p.fragment if p.fragment else "")
        return bool(LOGIN_TOKEN_PATTERN.search(target))
    except Exception:
        p = urllib.parse.urlsplit(url)
        target = p.path + ("?" + p.query if p.query else "") + ("#" + p.fragment if p.fragment else "")
        return bool(LOGIN_TOKEN_PATTERN.search(target))


def is_actual_login_page(url: str) -> bool:
    """Strict check for assigning the 'login_page' crawler source tag.

    Requires an explicit login/signup token while excluding marketing, feature,
    documentation, and legal agreement pages.
    """
    if not is_login_like(url):
        return False
    p = urllib.parse.urlsplit(url)
    path = p.path.lower()
    if EXCLUDED_MARKETING_PATTERN.search(path):
        return False
    return True


def is_indian(url: str, domain: Optional[str] = None) -> bool:
    """Return True if URL is from an Indian site or in an Indian language."""
    p = urllib.parse.urlparse(url)
    host = p.netloc.lower()
    if domain and any(domain.endswith(tld) for tld in INDIAN_TLDS):
        return True
    if any(host.endswith(tld) for tld in INDIAN_TLDS):
        return True
    reg = registrable_domain(host)
    if reg and reg in INDIAN_DOMAINS:
        return True
    full = url.lower()
    return any(ind in full for ind in INDIAN_LANG_INDICATORS)


# ---------------------------------------------------------------------------
# Domain collector
# ---------------------------------------------------------------------------

def collect_domain_urls(
    domain: str,
    rank: int,
    d1_domains: Set[str],
) -> Tuple[List[Tuple[str, str]], str]:
    """
    Collect diverse inner-page URLs for a single domain (up to 5 URLs).
    Returns ([(url, source), ...], status_string)
    Where source is 'homepage_link', 'sitemap', 'login_page', or 'one_level_link'.
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

    # Up to 1 actual login/account-style path
    login_matches = [u for u, src in all_candidates if is_actual_login_page(u)]
    selected_login: Optional[str] = None
    if login_matches:
        selected_login = login_matches[0]
        selected.append((selected_login, "login_page"))

    # Up to 2 sitemap URLs (excluding login)
    sitemap_filtered = [u for u in sitemap_candidates if u != selected_login and not is_actual_login_page(u)]
    sitemap_filtered.sort(key=lambda u: len(urllib.parse.urlparse(u).path.split("/")), reverse=True)
    for u in sitemap_filtered[:2]:
        selected.append((u, "sitemap"))

    # Up to 2 homepage links (varied depth, excluding login/sitemap)
    already_selected_urls = {u for u, s in selected}
    hp_filtered = [u for u in homepage_candidates if u not in already_selected_urls and not is_actual_login_page(u)]

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

    # 4. One-level link following if fewer than 5 URLs selected
    if len(selected) < 5 and hp_selected:
        for candidate_url in hp_selected[:1]:
            if len(selected) >= 5:
                break
            if rp and not rp.can_fetch(USER_AGENT, candidate_url):
                continue
            sub_html = fetch_url(candidate_url, only_html=True)
            if not sub_html:
                continue
            sub_links = extract_links(sub_html)
            for href in sub_links:
                if len(selected) >= 5:
                    break
                try:
                    abs_url = urllib.parse.urljoin(candidate_url, href)
                except Exception:
                    continue
                p = urllib.parse.urlparse(abs_url)
                if p.scheme != "https":
                    continue
                if registrable_domain(p.netloc) != base_reg:
                    continue
                path = p.path.rstrip("/")
                if not path:
                    continue
                clean = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
                if clean not in seen_urls:
                    seen_urls.add(clean)
                    selected.append((clean, "one_level_link"))

    # If still fewer than 5, fill from remaining homepage or sitemap candidates
    if len(selected) < 5:
        already = {u for u, _ in selected}
        for u in homepage_candidates + sitemap_candidates:
            if u not in already:
                already.add(u)
                selected.append((u, "homepage_link"))
                if len(selected) >= 5:
                    break

    selected = selected[:5]

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
    """Stratified sample across rank bands: 1-1k, 1k-10k, 10k-100k, and optionally 100k-1M.

    Adult-content domains are excluded and resampled within the same rank band
    so stratification holds. Every skipped adult domain is logged.
    """
    if len(band_sizes) == 4:
        band_defs = [
            (1, 1_000, "1-1k"),
            (1_001, 10_000, "1k-10k"),
            (10_001, 100_000, "10k-100k"),
            (100_001, 1_000_000, "100k-1M"),
        ]
    else:
        band_defs = [
            (1, 1_000, "1-1k"),
            (1_001, 10_000, "1k-10k"),
            (10_001, 100_000, "10k-100k"),
        ]
    rng = random.Random(seed)
    sampled: List[Tuple[int, str]] = []

    for (lo, hi, band_name), n in zip(band_defs, band_sizes):
        raw_band = [(r, d) for r, d in rows if lo <= r <= hi]
        clean_band: List[Tuple[int, str]] = []
        for r, d in raw_band:
            if is_adult_domain(d):
                LOGGER.info("Skipping adult domain rank=%d domain=%s in band %s (reason: adult_content_denylist)", r, d, band_name)
            else:
                clean_band.append((r, d))

        available = min(n, len(clean_band))
        chosen = rng.sample(clean_band, available)
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

def evaluate_quotas(records: List[dict]) -> dict:
    """Evaluate E1 quota compliance.
    Quotas:
    - total_urls >= 5,000
    - total_domains >= 1,500
    - max_per_domain <= 5
    - with_path >= 50%
    - with_query >= 20%
    - login_like >= 10%
    - indian_site_or_lang >= 10%
    """
    total_urls = len(records)
    domains = {r["domain"] for r in records if r.get("domain")}
    total_domains = len(domains)

    from collections import Counter
    domain_counts = Counter(r["domain"] for r in records if r.get("domain"))
    max_per_domain = max(domain_counts.values()) if domain_counts else 0

    with_path = 0
    with_query = 0
    with_login = 0
    with_indian = 0

    for r in records:
        u = r.get("URL", "")
        p = urllib.parse.urlparse(u)
        path = p.path.rstrip("/")
        if path:
            with_path += 1
        if p.query:
            with_query += 1
        if is_login_like(u):
            with_login += 1
        if is_indian(u, r.get("domain")):
            with_indian += 1

    path_share = (with_path / total_urls) if total_urls > 0 else 0.0
    query_share = (with_query / total_urls) if total_urls > 0 else 0.0
    login_share = (with_login / total_urls) if total_urls > 0 else 0.0
    indian_share = (with_indian / total_urls) if total_urls > 0 else 0.0

    return {
        "total_urls": {"actual": total_urls, "target": MIN_TOTAL_URLS, "status": "PASS" if total_urls >= MIN_TOTAL_URLS else "FAIL"},
        "total_domains": {"actual": total_domains, "target": MIN_TOTAL_DOMAINS, "status": "PASS" if total_domains >= MIN_TOTAL_DOMAINS else "FAIL"},
        "max_per_domain": {"actual": max_per_domain, "target": MAX_PER_DOMAIN, "status": "PASS" if max_per_domain <= MAX_PER_DOMAIN else "FAIL"},
        "path_share": {"actual": round(path_share, 4), "target": 0.50, "status": "PASS" if path_share >= 0.50 else "FAIL"},
        "query_share": {"actual": round(query_share, 4), "target": 0.20, "status": "PASS" if query_share >= 0.20 else "FAIL"},
        "login_share": {"actual": round(login_share, 4), "target": 0.10, "status": "PASS" if login_share >= 0.10 else "FAIL"},
        "indian_share": {"actual": round(indian_share, 4), "target": 0.10, "status": "PASS" if indian_share >= 0.10 else "FAIL"},
    }


def collect(
    tranco_path: pathlib.Path,
    out_path: pathlib.Path,
    band_sizes: List[int],
    seed: int,
    resume: bool,
    max_domains: Optional[int],
    root: pathlib.Path,
    include_seed_list: bool = True,
) -> dict:
    d1_domains = load_d1_domains(root)

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
    urls_by_source: Dict[str, int] = {
        "homepage_link": 0, "sitemap": 0, "login_page": 0,
        "one_level_link": 0, "seed_list": 0
    }
    urls_per_domain_list: List[dict] = []
    collected_records: List[dict] = []
    collection_date = datetime.now(timezone.utc).date().isoformat()

    checkpoint_path = out_path.parent / ".e1_checkpoint.txt"
    done_ranks = load_checkpoint(checkpoint_path) if resume else set()

    # 1. Inject seed list if enabled and not already checkpointed
    if include_seed_list and (0 not in done_ranks):
        LOGGER.info("Processing seed list (%d domains)...", len(SEED_LIST))
        for s_dom, s_urls in sorted(SEED_LIST.items()):
            reg = registrable_domain(s_dom) or s_dom
            if reg in d1_domains:
                LOGGER.info("Seed domain %s in D1, skipping.", s_dom)
                continue
            curated = s_urls[:MAX_PER_DOMAIN]
            for u in curated:
                writer.writerow([u, s_dom, 0, collection_date, "seed_list"])
                total_written += 1
                urls_by_source["seed_list"] = urls_by_source.get("seed_list", 0) + 1
                collected_records.append({"URL": u, "domain": s_dom, "source": "seed_list"})
            out_fh.flush()
            domains_succeeded += 1
            urls_per_domain_list.append({
                "domain": s_dom,
                "rank": 0,
                "count": len(curated),
                "sources": ["seed_list"] * len(curated),
            })
        append_checkpoint(checkpoint_path, 0)

    # 2. Sample and crawl Tranco list if present
    sampled: List[Tuple[int, str]] = []
    list_id: Optional[str] = None
    list_date: Optional[str] = None

    if tranco_path.exists():
        LOGGER.info("Loading Tranco list from %s ...", tranco_path)
        rows, list_id, list_date = load_tranco(tranco_path)
        sampled = stratified_sample(rows, band_sizes, seed)

        if max_domains is not None and max_domains > 0:
            LOGGER.info("Applying --max-domains limit: capping sample at %d domains.", max_domains)
            sampled = sampled[:max_domains]

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
                    collected_records.append({"URL": url, "domain": domain, "source": src})
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
    else:
        LOGGER.warning("Tranco CSV not found at %s. Crawl skipped.", tranco_path)

    out_fh.close()

    dist: Dict[str, int] = {"0": domains_attempted - (domains_succeeded - len(SEED_LIST) if include_seed_list else domains_succeeded), "1": 0, "2": 0, "3": 0, "4": 0, "5+": 0}
    for item in urls_per_domain_list:
        c = item["count"]
        if c >= 5:
            dist["5+"] += 1
        else:
            dist[str(c)] = dist.get(str(c), 0) + 1

    quotas = evaluate_quotas(collected_records)

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
        "quotas": quotas,
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
        "## Quota Compliance",
        "",
        "| Quota | Target | Actual | Status |",
        "|---|---|---|---|",
        f"| Total URLs | ≥ {quotas['total_urls']['target']} | {quotas['total_urls']['actual']} | {quotas['total_urls']['status']} |",
        f"| Total Domains | ≥ {quotas['total_domains']['target']} | {quotas['total_domains']['actual']} | {quotas['total_domains']['status']} |",
        f"| Max per Domain | ≤ {quotas['max_per_domain']['target']} | {quotas['max_per_domain']['actual']} | {quotas['max_per_domain']['status']} |",
        f"| Has Path | ≥ {quotas['path_share']['target']*100:.0f}% | {quotas['path_share']['actual']*100:.1f}% | {quotas['path_share']['status']} |",
        f"| Has Query | ≥ {quotas['query_share']['target']*100:.0f}% | {quotas['query_share']['actual']*100:.1f}% | {quotas['query_share']['status']} |",
        f"| Login / Account | ≥ {quotas['login_share']['target']*100:.0f}% | {quotas['login_share']['actual']*100:.1f}% | {quotas['login_share']['status']} |",
        f"| Indian Sites / Languages | ≥ {quotas['indian_share']['target']*100:.0f}% | {quotas['indian_share']['actual']*100:.1f}% | {quotas['indian_share']['status']} |",
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
        default="500,750,750,750",
        help="Comma-separated sample counts for rank bands (3 bands: 1-1k, 1k-10k, 10k-100k; or 4 bands: 1-1k, 1k-10k, 10k-100k, 100k-1M). Default: 500,750,750,750",
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
    parser.add_argument(
        "--no-seed-list",
        action="store_true",
        help="Do not include the 26 seed list domains.",
    )
    args = parser.parse_args()

    try:
        band_sizes = [int(x.strip()) for x in args.sample_per_band.split(",")]
    except ValueError:
        parser.error("--sample-per-band must be comma-separated integers, e.g. 500,750,750,750")
        return

    if len(band_sizes) not in (3, 4):
        parser.error("--sample-per-band requires 3 or 4 values.")

    collect(
        tranco_path=pathlib.Path(args.tranco),
        out_path=pathlib.Path(args.out),
        band_sizes=band_sizes,
        seed=args.seed,
        resume=args.resume,
        max_domains=args.max_domains,
        root=ROOT,
        include_seed_list=not args.no_seed_list,
    )


if __name__ == "__main__":
    main()
