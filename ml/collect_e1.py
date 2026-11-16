#!/usr/bin/env python3
"""Collect genuine E1 inner-page candidates from Tranco domains.

Uses public sitemaps, checks robots.txt permissions, applies request limits,
and supports resumable collection. This produces candidates, not an accepted
E1 dataset. Domains present in the D1 exclusion list are skipped.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.robotparser import RobotFileParser

from ml.normalize import normalize


UA = (
    "PhishGuard-E1Research/1.0 "
    "(academic research; sitemap-only; contact: project-maintainer)"
)

TIMEOUT = 4
MAX_BYTES = 8 * 1024 * 1024


def fetch(url: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch a URL safely with a bounded response size."""

    try:
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None, "invalid_url"

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": UA,
                "Accept": "application/xml,text/xml,*/*",
            },
        )

        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            data = response.read(MAX_BYTES + 1)

            if len(data) > MAX_BYTES:
                return None, "response_too_large"

            return data, None

    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        socket.timeout,
        TimeoutError,
        OSError,
        ValueError,
    ) as exc:
        return None, type(exc).__name__


def read_tranco(path: Path, limit: int) -> List[str]:
    """Read the first `limit` ranked domains from Tranco CSV."""

    domains = []

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        for row in csv.reader(file):
            if not row:
                continue

            candidate = (
                row[1].strip()
                if len(row) > 1 and row[0].strip().isdigit()
                else row[0].strip()
            )

            if candidate.lower() in {"domain", "domains", "website"}:
                continue

            if (
                "." not in candidate
                or "/" in candidate
                or " " in candidate
            ):
                continue

            domains.append(candidate.lower().rstrip("."))

            if len(domains) >= limit:
                break

    return domains


def get_robots(domain: str):
    """Retrieve robots.txt and construct a permission parser."""

    robots_url = "https://" + domain + "/robots.txt"
    body, _ = fetch(robots_url)

    if body is None:
        return None, []

    lines = body.decode("utf-8", "replace").splitlines()

    parser = RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(lines)

    sitemap_locations = []

    for line in lines:
        if line.lower().startswith("sitemap:"):
            location = line.split(":", 1)[1].strip()
            absolute = urllib.parse.urljoin(robots_url, location)
            parsed = urllib.parse.urlparse(absolute)

            if parsed.scheme in ("http", "https") and parsed.netloc:
                sitemap_locations.append(absolute)

    return parser, list(dict.fromkeys(sitemap_locations))


def parse_sitemap(data: bytes) -> Tuple[List[str], List[str]]:
    """Extract page URLs and nested sitemap locations."""

    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError:
            return [], []

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return [], []

    tag = root.tag.rsplit("}", 1)[-1].lower()

    locations = [
        element.text.strip()
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1].lower() == "loc"
        and element.text
    ]

    if tag == "sitemapindex":
        return [], locations[:50]

    if tag == "urlset":
        return locations, []

    return [], []


def collect_domain(domain: str, max_urls: int) -> List[str]:
    """Collect permitted, genuine inner-page URLs from one domain."""

    found = []
    seen = set()
    visited = set()

    robots, sitemap_queue = get_robots(domain)

    # If robots.txt cannot be retrieved, do not crawl this domain.
    if robots is None:
        return found

    # Use the conventional sitemap location only when none is declared.
    if not sitemap_queue:
        sitemap_queue = ["https://" + domain + "/sitemap.xml"]

    queue = list(sitemap_queue)

    while queue and len(found) < max_urls and len(visited) < 20:
        sitemap = queue.pop(0)

        if sitemap in visited:
            continue

        visited.add(sitemap)

        sitemap_url = urllib.parse.urljoin(
            "https://" + domain + "/",
            sitemap,
        )

        parsed = urllib.parse.urlparse(sitemap_url)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue

        # Check permission before fetching the sitemap.
        if not robots.can_fetch(UA, sitemap_url):
            continue

        data, _ = fetch(sitemap_url)

        if data is None:
            continue

        urls, nested = parse_sitemap(data)

        # Resolve nested sitemap locations relative to their parent.
        for item in nested:
            absolute = urllib.parse.urljoin(sitemap_url, item)

            if absolute not in visited and len(queue) < 50:
                queue.append(absolute)

        for url in urls:
            if len(found) >= max_urls:
                break

            absolute = urllib.parse.urljoin(sitemap_url, url)
            parsed_url = urllib.parse.urlparse(absolute)

            if parsed_url.scheme not in ("http", "https"):
                continue

            if not parsed_url.hostname:
                continue

            # Only accept pages belonging to this domain or its subdomains.
            host = parsed_url.hostname.lower().rstrip(".")
            base = domain.lower().rstrip(".")

            if host != base and not host.endswith("." + base):
                continue

            # Exclude homepages.
            if parsed_url.path in ("", "/") and not parsed_url.query:
                continue

            # Respect robots.txt for discovered pages.
            if not robots.can_fetch(UA, absolute):
                continue

            # Avoid fragments and duplicates.
            clean_url = urllib.parse.urldefrag(absolute)[0]

            if clean_url not in seen:
                seen.add(clean_url)
                found.append(clean_url)

    return found


def get_registrable_domain(value: str) -> Optional[str]:
    """Return the PSL-based registrable domain, or None if invalid."""

    try:
        result = normalize(value)
        domain = result.registrable_domain
        return domain.lower() if domain else None
    except Exception:
        return None


def load_existing(output: Path):
    """Read existing candidate URLs and successful registrable domains."""

    urls = set()
    domains = set()

    if not output.exists():
        return urls, domains

    with output.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            url = (row.get("URL") or "").strip()

            if not url:
                continue

            urls.add(url)

            registrable_domain = get_registrable_domain(url)
            if registrable_domain:
                domains.add(registrable_domain)

    return urls, domains


def load_excluded_domains(path: Path) -> Set[str]:
    """Load D1 registrable domains that must never enter E1."""

    if not path.exists():
        raise FileNotFoundError(
            "D1 exclusion file not found: %s" % path
        )

    excluded = set()

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if "registrable_domain" not in (reader.fieldnames or []):
            raise ValueError(
                "Exclusion file must contain a registrable_domain column"
            )

        for row in reader:
            domain = (row.get("registrable_domain") or "").strip().lower()
            if domain:
                excluded.add(domain)

    return excluded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--tranco",
        default="data/raw/E1/tranco/top-1m.csv",
    )

    parser.add_argument(
        "--output",
        default="data/raw/E1/E1_candidates.csv",
    )

    parser.add_argument(
        "--exclude-domains",
        default="data/raw/E1/d1_excluded_domains.csv",
        help="CSV containing D1 registrable domains to exclude",
    )

    parser.add_argument(
        "--max-domains",
        type=int,
        default=3000,
        help="Number of top Tranco rows to load",
    )

    parser.add_argument(
        "--max-urls-per-domain",
        type=int,
        choices=[1, 2, 3],
        default=3,
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from the saved checkpoint",
    )

    parser.add_argument(
        "--start-rank",
        type=int,
        default=1,
        help="Starting Tranco rank when no checkpoint exists",
    )

    args = parser.parse_args()

    if args.delay < 1:
        parser.error("--delay must be at least 1 second")

    if args.start_rank < 1:
        parser.error("--start-rank must be at least 1")

    if args.max_domains < 1:
        parser.error("--max-domains must be at least 1")

    tranco_path = Path(args.tranco)
    output = Path(args.output)
    exclusion_path = Path(args.exclude_domains)

    checkpoint = output.with_suffix(".checkpoint")

    if not tranco_path.exists():
        parser.error("Tranco file not found: %s" % tranco_path)

    try:
        excluded_domains = load_excluded_domains(exclusion_path)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))

    domains = read_tranco(tranco_path, args.max_domains)

    if not domains:
        parser.error("No Tranco domains found")

    output.parent.mkdir(parents=True, exist_ok=True)

    existing_urls, existing_domains = load_existing(output)

    print("D1 domains excluded:", len(excluded_domains))
    print("Existing candidate URLs:", len(existing_urls))
    print("Existing candidate registrable domains:", len(existing_domains))

    start_rank = args.start_rank

    if args.resume and checkpoint.exists():
        try:
            start_rank = int(
                checkpoint.read_text(encoding="utf-8").strip()
            )
        except ValueError:
            parser.error("Invalid checkpoint file")

    if start_rank > len(domains):
        print("All requested Tranco ranks have already been processed.")
        return 0

    file_mode = "a" if output.exists() else "w"

    new_count = 0
    new_domains = 0
    skipped_d1 = 0
    skipped_existing = 0

    with output.open(
        file_mode,
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["URL", "source"],
        )

        if file_mode == "w":
            writer.writeheader()

        for index in range(start_rank - 1, len(domains)):
            rank = index + 1
            domain = domains[index]

            registrable_domain = get_registrable_domain(domain)

            if not registrable_domain:
                checkpoint.write_text(str(rank + 1), encoding="utf-8")
                continue

            if registrable_domain in excluded_domains:
                skipped_d1 += 1
                checkpoint.write_text(str(rank + 1), encoding="utf-8")
                continue

            if registrable_domain in existing_domains:
                skipped_existing += 1
                checkpoint.write_text(str(rank + 1), encoding="utf-8")
                continue

            try:
                urls = collect_domain(
                    domain,
                    args.max_urls_per_domain,
                )
            except Exception as exc:
                print(
                    "Skipped %s: %s" % (domain, type(exc).__name__),
                    flush=True,
                )
                urls = []

            added = 0

            for url in urls:
                if url in existing_urls:
                    continue

                url_domain = get_registrable_domain(url)

                # Recheck every discovered URL before writing it.
                if (
                    not url_domain
                    or url_domain in excluded_domains
                    or url_domain != registrable_domain
                ):
                    continue

                writer.writerow(
                    {
                        "URL": url,
                        "source": "Tranco-ranked domain sitemap",
                    }
                )

                existing_urls.add(url)
                added += 1
                new_count += 1

            file.flush()

            if added:
                existing_domains.add(registrable_domain)
                new_domains += 1

            # Save the next rank after every processed domain.
            checkpoint.write_text(
                str(rank + 1),
                encoding="utf-8",
            )

            print(
                "Tried %d/%d; new URLs: %d; "
                "new successful domains: %d; total URLs: %d; "
                "D1 domains skipped: %d"
                % (
                    rank,
                    len(domains),
                    new_count,
                    new_domains,
                    len(existing_urls),
                    skipped_d1,
                ),
                flush=True,
            )

            time.sleep(args.delay)

    print("\nCollection finished.")
    print("New URLs collected:", new_count)
    print("New successful domains:", new_domains)
    print("D1 Tranco domains skipped:", skipped_d1)
    print("Already-collected domains skipped:", skipped_existing)
    print("Total unique candidate URLs:", len(existing_urls))
    print("Total candidate registrable domains:", len(existing_domains))
    print("Output:", output)
    print("Checkpoint:", checkpoint)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
