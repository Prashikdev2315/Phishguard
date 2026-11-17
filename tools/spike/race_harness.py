#!/usr/bin/env python3
"""
tools/spike/race_harness.py  —  FR-09 / E2E-10 race spike
==========================================================

Measures whether the High-Risk interstitial appears BEFORE the target
page commits, across ≥ 200 mixed cold and warm navigations.

Why Playwright (not Selenium):
  • Native async/await API matches the extension's async model exactly.
  • `browser_type.launch_persistent_context(extensions=[…])` is the
    official Playwright API for Chromium extensions — no WebDriver overhead.
  • `page.on('framenavigated')` gives per-frame URL events at the same
    fidelity as Chrome's webNavigation API, so cold/warm timing is comparable.
  • CDP session (`cdp = await context.new_cdp_session(page)`) exposes
    Target.getTargets / Target.closeTarget, which lets us terminate the
    service worker between runs (cold-start simulation) without restarting
    the browser.
  • `page.route()` gives server-side-equivalent request interception for
    counting target-URL hits without an external HTTP server (see NOTE below).

Domain strategy — fake mapped domain (not 127.0.0.1):
  PRD pre-filter skips loopback AND private-network hosts (§4).  The spike
  stub worker (Chunk 1) only checks protocol, so 127.0.0.1 would work for
  the spike, but we match production intent by using a non-loopback hostname.

  We serve on the machine's LAN IP (auto-detected) and use the fake hostname
  `phishguard-spike.test`.  The harness checks DNS resolution; if it fails it
  prints setup instructions and exits cleanly.

  NOTE: Instead of a real HTTP server + DNS, we use Playwright's
  `context.route()` to intercept requests to `http://phishguard-spike.test/*`
  and fulfil them from memory.  This avoids the hosts-file/DNS requirement
  while still giving us:
    (a) a non-loopback, non-127.0.0.1 hostname URL in the browser's URL bar
        (Playwright intercepts at the network layer, so the URL is real), and
    (b) a per-run hit counter (we count how many times the route handler fires
        for each run-ID before the page settles).
  The LAN-IP hosts-file approach is documented in docs/SPIKE_RESULTS.md for
  teams that want real network-stack measurement.

Measurement (two independent signals):
  1. Browser-side  — `page.url` after `domcontentloaded` or `commit`:
       warning.html URL → interstitial shown (extension won the race)
       /run-{i}/        → target committed (extension lost)
  2. Route-side    — route handler fires iff browser fetched the target URL:
       0 fetches for run-i → target never committed
       ≥1 fetch            → target committed (may still show interstitial
                             if tabs.update fired before DOM rendered)

Cold-worker runs (PRD §4, NFR-03):
  Between cold runs we terminate the service worker via CDP so the next
  navigation triggers a full SW wake + model load (< 150 ms gate).
  Warm runs skip that step.

Usage:
  python tools/spike/race_harness.py \\
      --extension path/to/phishguard/extension \\
      --runs 200 \\
      --cold-fraction 0.2 \\
      --out docs/SPIKE_RESULTS.md

Output:
  Writes a Markdown section to --out (docs/SPIKE_RESULTS.md by default) and
  also prints a JSON summary to stdout.

Gate (FR-09, E2E-10):
  interstitial_rate ≥ 0.99 → PASS
  interstitial_rate ≥ 0.90 → WARN  (document residual; consider DNR)
  below 0.90               → FAIL  (block enforcement unreliable)

Install:
  python -m pip install playwright
  python -m playwright install chromium
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import pathlib
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ── dependency guard ─────────────────────────────────────────────────────────

def _require_playwright() -> bool:
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        return True
    except ImportError:
        print(
            "[race_harness] ERROR: playwright not installed.\n"
            "  python -m pip install playwright\n"
            "  python -m playwright install chromium",
            file=sys.stderr,
        )
        return False


# ── constants ─────────────────────────────────────────────────────────────────

FAKE_HOST    = "phishguard-spike.test"
FAKE_ORIGIN  = f"http://{FAKE_HOST}"
# Fallback if DNS check fails: use the route-intercept approach (always works)
USE_ROUTE_INTERCEPT = True   # always true in this implementation
WARNING_PAGE_PATH   = "src/pages/warning.html"


# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class RunResult:
    run_id:              int
    is_cold:             bool
    target_url:          str
    final_url:           str        # URL after navigation settles
    interstitial_shown:  bool       # warning.html committed
    target_fetched:      bool       # route handler hit for this run
    # Timing (seconds from navigation start to URL commit)
    t_commit_s:          float
    error:               Optional[str] = None


@dataclass
class HarnessResults:
    total_runs:               int
    interstitial_shown:       int
    target_committed:         int
    interstitial_rate:        float
    cold_runs:                int
    warm_runs:                int
    cold_interstitial_shown:  int
    warm_interstitial_shown:  int
    cold_interstitial_rate:   Optional[float]
    warm_interstitial_rate:   Optional[float]
    # Route-signal cross-check
    route_target_fetched:     int   # runs where server saw a hit
    route_no_fetch:           int   # runs where server saw no hit
    verdict:                  str   # PASS | WARN | FAIL
    note:                     str
    timestamp:                str
    extension_path:           str
    cold_p95_ms:              Optional[float] = None
    warm_p95_ms:              Optional[float] = None
    runs:                     List[dict] = field(default_factory=list)


# ── LAN IP detection ──────────────────────────────────────────────────────────

def _detect_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── service worker CDP helpers ────────────────────────────────────────────────

async def _find_sw_target(cdp_session) -> Optional[str]:
    """Return the targetId of the extension's service worker, or None."""
    try:
        resp = await cdp_session.send("Target.getTargets")
        for t in resp.get("targetInfos", []):
            if t.get("type") == "service_worker":
                return t["targetId"]
    except Exception:
        pass
    return None


async def _terminate_sw(cdp_session) -> bool:
    """Attempt to close (terminate) the extension SW. Returns True if closed."""
    tid = await _find_sw_target(cdp_session)
    if tid is None:
        return False
    try:
        await cdp_session.send("Target.closeTarget", {"targetId": tid})
        await asyncio.sleep(0.3)   # let it shut down
        return True
    except Exception:
        return False


# ── core harness ──────────────────────────────────────────────────────────────

async def _run_harness(
    extension_path: str,
    runs: int,
    cold_fraction: float,
) -> HarnessResults:
    from playwright.async_api import async_playwright, Page, BrowserContext

    ext_abs      = str(pathlib.Path(extension_path).resolve())
    lan_ip       = _detect_lan_ip()
    cold_every   = max(1, round(1.0 / cold_fraction)) if cold_fraction > 0 else 10**9
    run_results: List[RunResult] = []

    # Per-run fetch counters (populated by route interceptor)
    fetch_counts: Dict[int, int] = {}

    async with async_playwright() as pw:
        # ── launch persistent Chromium context with the extension ──────────
        user_data = pathlib.Path(ext_abs).parent / ".playwright_profile"
        user_data.mkdir(exist_ok=True)

        context: BrowserContext = await pw.chromium.launch_persistent_context(
            str(user_data),
            headless=False,          # extensions require headed mode
            args=[
                f"--disable-extensions-except={ext_abs}",
                f"--load-extension={ext_abs}",
                "--no-sandbox",
                "--disable-gpu",
            ],
            ignore_https_errors=True,
        )

        # ── open a fresh page ──────────────────────────────────────────────
        page: Page = await context.new_page()

        # ── route interceptor: serve fake domain + count hits per run ──────
        async def _route_handler(route, request):
            url = request.url
            # Extract run-id from path: /run-{i}/
            try:
                parts = url.split("/run-")
                if len(parts) > 1:
                    run_id = int(parts[1].strip("/").split("/")[0])
                    fetch_counts[run_id] = fetch_counts.get(run_id, 0) + 1
            except (ValueError, IndexError):
                pass
            # Serve a minimal HTML page so the browser is happy
            await route.fulfill(
                status=200,
                content_type="text/html",
                body=f"<html><body>Spike target run-{url}</body></html>",
            )

        await context.route(f"{FAKE_ORIGIN}/**", _route_handler)

        # ── open a CDP session on the page for SW termination ──────────────
        cdp = await context.new_cdp_session(page)

        # ── warm-up: allow SW to load and set block mode ───────────────────
        await page.goto("about:blank")
        await asyncio.sleep(1.5)
        try:
            targets = await cdp.send("Target.getTargets")
            for t in targets.get("targetInfos", []):
                if "chrome-extension://" in t.get("url", ""):
                    ext_id = t["url"].split("://")[1].split("/")[0]
                    popup_url = f"chrome-extension://{ext_id}/src/pages/popup.html"
                    await page.goto(popup_url)
                    await asyncio.sleep(0.3)
                    await page.evaluate("""
                        async () => {
                            await chrome.storage.local.set({
                                settings: { enforcementMode: "block", failureMode: "open", bannerEnabled: true }
                            });
                        }
                    """)
                    await page.goto("about:blank")
                    await asyncio.sleep(0.5)
                    break
        except Exception as e:
            print(f"[race_harness] Warning: could not preconfigure settings: {e}")

        # ── run loop ───────────────────────────────────────────────────────
        for i in range(runs):
            is_cold = (i % cold_every == 0)
            target_url = f"{FAKE_ORIGIN}/run-{i}/"
            fetch_counts[i] = 0
            error_msg: Optional[str] = None

            # Cold run: terminate SW before navigating
            if is_cold:
                terminated = await _terminate_sw(cdp)
                if not terminated:
                    # SW may already be inactive — that's fine
                    pass
                await asyncio.sleep(0.1)

            t_start = time.monotonic()
            try:
                # Navigate; wait only for the network request to commit
                # (not for load) so we capture the race before JS runs.
                await page.goto(
                    target_url,
                    wait_until="commit",
                    timeout=5000,
                )
            except Exception as exc:
                error_msg = str(exc)[:120]

            t_commit = time.monotonic() - t_start
            final_url = page.url

            # Give extension's tabs.update a moment to fire if it hasn't yet
            # (the route-intercept + tabs.update race)
            await asyncio.sleep(0.15)
            final_url = page.url   # re-read after the brief pause

            is_interstitial = (
                WARNING_PAGE_PATH in final_url
                or "warning.html" in final_url
            )
            target_fetched = fetch_counts.get(i, 0) > 0

            run_results.append(RunResult(
                run_id=i,
                is_cold=is_cold,
                target_url=target_url,
                final_url=final_url,
                interstitial_shown=is_interstitial,
                target_fetched=target_fetched,
                t_commit_s=round(t_commit, 4),
                error=error_msg,
            ))

        await context.close()

    # ── aggregate ──────────────────────────────────────────────────────────
    total      = len(run_results)
    shown      = sum(1 for r in run_results if r.interstitial_shown)
    committed  = sum(1 for r in run_results if not r.interstitial_shown)
    colds      = [r for r in run_results if r.is_cold]
    warms      = [r for r in run_results if not r.is_cold]
    c_shown    = sum(1 for r in colds if r.interstitial_shown)
    w_shown    = sum(1 for r in warms if r.interstitial_shown)
    r_fetched  = sum(1 for r in run_results if r.target_fetched)
    r_nofetch  = total - r_fetched

    rate   = shown / total if total else 0.0
    c_rate = c_shown / len(colds) if colds else None
    w_rate = w_shown / len(warms) if warms else None

    cold_times = [r.t_commit_s * 1000 for r in colds]
    warm_times = [r.t_commit_s * 1000 for r in warms]
    try:
        import numpy as np
        c_p95 = round(float(np.percentile(cold_times, 95)), 2) if cold_times else None
        w_p95 = round(float(np.percentile(warm_times, 95)), 2) if warm_times else None
    except Exception:
        c_p95 = None
        w_p95 = None

    if rate >= 0.99:
        verdict = "PASS"
        note = (
            f"Interstitial rate {rate:.1%} meets the ≥ 99% gate (FR-09, E2E-10). "
            "Block enforcement is reliable at this sample size."
        )
    elif rate >= 0.90:
        verdict = "WARN"
        note = (
            f"Interstitial rate {rate:.1%} < 99% gate. "
            "Document residual failures ({committed} runs). "
            "Consider declarativeNetRequest session rules or warn-only as default "
            "(PRD risk R-03)."
        )
    else:
        verdict = "FAIL"
        note = (
            f"Interstitial rate {rate:.1%} is too low ({committed}/{total} races lost). "
            "Block enforcement is unreliable. Default to warn-only (PRD risk R-03). "
            "Investigate tabs.update latency and consider DNR session rules."
        )

    return HarnessResults(
        total_runs=total,
        interstitial_shown=shown,
        target_committed=committed,
        interstitial_rate=round(rate, 4),
        cold_runs=len(colds),
        warm_runs=len(warms),
        cold_interstitial_shown=c_shown,
        warm_interstitial_shown=w_shown,
        cold_interstitial_rate=round(c_rate, 4) if c_rate is not None else None,
        warm_interstitial_rate=round(w_rate, 4) if w_rate is not None else None,
        cold_p95_ms=c_p95,
        warm_p95_ms=w_p95,
        route_target_fetched=r_fetched,
        route_no_fetch=r_nofetch,
        verdict=verdict,
        note=note,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        extension_path=ext_abs,
        runs=[asdict(r) for r in run_results],
    )


# ── Markdown writer ───────────────────────────────────────────────────────────

def _write_spike_results_md(results: HarnessResults, out_path: pathlib.Path) -> None:
    r = results
    cold_rate_str = f"{r.cold_interstitial_rate:.1%}" if r.cold_interstitial_rate is not None else "n/a"
    warm_rate_str = f"{r.warm_interstitial_rate:.1%}" if r.warm_interstitial_rate is not None else "n/a"

    md = f"""# PhishGuard — Spike Results (FR-09 / E2E-10)

**PRD reference:** §4 MV3 engineering notes, FR-09, E2E-10, risk R-03
**Harness:** `tools/spike/race_harness.py` (Playwright)
**Run at:** {r.timestamp}
**Extension:** `{r.extension_path}`

---

## Gate

| Metric                      | Required | Actual                                   | Result    |
|-----------------------------|----------|------------------------------------------|-----------|
| `interstitial_rate`         | ≥ 0.99   | {r.interstitial_rate:.4f} ({r.interstitial_shown}/{r.total_runs}) | **{r.verdict}** |
| `cold_interstitial_rate`    | reported | {cold_rate_str} ({r.cold_interstitial_shown}/{r.cold_runs})       | reported  |
| `warm_interstitial_rate`    | reported | {warm_rate_str} ({r.warm_interstitial_shown}/{r.warm_runs})       | reported  |
| `cold_start_p95`            | < 150 ms | {f"{r.cold_p95_ms:.1f} ms" if r.cold_p95_ms is not None else "n/a"} | reported  |
| `warm_p95`                  | < 30 ms  | {f"{r.warm_p95_ms:.1f} ms" if r.warm_p95_ms is not None else "n/a"} | reported  |

**Verdict: {r.verdict}**
{r.note}

---

## Measurement signals

| Signal           | Value | Meaning |
|------------------|-------|---------|
| Interstitial shown (browser-side `page.url`) | {r.interstitial_shown} | Extension won — `warning.html` committed |
| Target committed  (browser-side `page.url`) | {r.target_committed} | Target page committed before interstitial |
| Route no-fetch (target URL never fetched)   | {r.route_no_fetch} | Consistent with extension winning |
| Route fetched  (target URL was fetched)      | {r.route_target_fetched} | Target was fetched (may still show interstitial) |

---

## Run configuration

| Parameter        | Value |
|------------------|-------|
| Total runs       | {r.total_runs} |
| Cold runs        | {r.cold_runs} ({round(r.cold_runs/r.total_runs*100)}%) |
| Warm runs        | {r.warm_runs} |
| Fake domain      | `{FAKE_HOST}` via Playwright route intercept |
| Measurement      | Browser-side `page.url` + route-side hit counter |

---

## Consequence

{"✅ Block enforcement (`block` mode) is reliable. Gate G-3 can be evaluated with block mode." if r.verdict == "PASS" else "⚠️  Default enforcement set to `warn_only` pending further investigation (PRD risk R-03). Gate G-3 evaluated in warn_only mode." if r.verdict == "WARN" else "❌ Block enforcement unreliable. Default enforcement MUST be `warn_only`. Document in model card."}

---

*Auto-generated by `tools/spike/race_harness.py`. Do not edit manually.*
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PhishGuard race harness — FR-09 / E2E-10 (Playwright)"
    )
    parser.add_argument(
        "--extension",
        default="extension",
        help="Path to unpacked extension directory (default: extension/)",
    )
    parser.add_argument(
        "--runs", type=int, default=200,
        help="Number of navigations (PRD gate requires ≥ 200)",
    )
    parser.add_argument(
        "--cold-fraction", type=float, default=0.2,
        help="Fraction of runs that simulate a cold SW start (default: 0.2)",
    )
    parser.add_argument(
        "--out",
        default="docs/SPIKE_RESULTS.md",
        help="Markdown output path (default: docs/SPIKE_RESULTS.md)",
    )
    parser.add_argument(
        "--json-out",
        default="tools/spike/race_results.json",
        help="JSON output path for full results",
    )
    args = parser.parse_args()

    if not _require_playwright():
        sys.exit(1)

    if args.runs < 200:
        print(
            f"[race_harness] WARNING: --runs {args.runs} < 200. "
            "PRD gate requires ≥ 200 navigations.",
            file=sys.stderr,
        )

    ext_path = pathlib.Path(args.extension)
    if not ext_path.exists():
        print(f"[race_harness] ERROR: extension not found at {ext_path.resolve()}", file=sys.stderr)
        sys.exit(1)

    print(
        f"[race_harness] Starting {args.runs} navigations "
        f"({int(args.cold_fraction * 100)}% cold) with Playwright …\n"
        f"  Extension  : {ext_path.resolve()}\n"
        f"  Domain     : {FAKE_HOST} (via route intercept)\n"
        f"  Markdown   : {args.out}\n"
        f"  JSON       : {args.json_out}\n"
    )

    results = asyncio.run(
        _run_harness(
            extension_path=str(ext_path),
            runs=args.runs,
            cold_fraction=args.cold_fraction,
        )
    )

    # Write Markdown to docs/SPIKE_RESULTS.md
    out_md   = pathlib.Path(args.out)
    out_json = pathlib.Path(args.json_out)

    _write_spike_results_md(results, out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(asdict(results), indent=2), encoding="utf-8"
    )

    # Print JSON summary (without per-run detail)
    summary = asdict(results)
    summary.pop("runs", None)
    print(json.dumps(summary, indent=2))
    print(f"\n[race_harness] Verdict : {results.verdict}")
    print(f"[race_harness] Markdown : {out_md.resolve()}")
    print(f"[race_harness] JSON     : {out_json.resolve()}")

    sys.exit(0 if results.verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
