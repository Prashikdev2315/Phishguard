"""Launch Chrome / Playwright Chromium with PhishGuard extension loaded.

Usage:
    python tools/launch_extension.py [--browser playwright|chrome]
"""

import argparse
import asyncio
import os
import pathlib
import sys

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXT_PATH = str((ROOT / "extension").resolve())
assert (pathlib.Path(EXT_PATH) / "manifest.json").is_file(), f"manifest.json missing at {EXT_PATH}"

async def launch_playwright_async():
    from playwright.async_api import async_playwright

    user_data = ROOT / ".playwright_profile_interactive"
    user_data.mkdir(exist_ok=True)

    print(f"[Launcher] Starting Chromium with PhishGuard...")
    print(f"[Launcher] Extension directory: {EXT_PATH}")

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(user_data),
            headless=False,
            args=[
                f"--disable-extensions-except={EXT_PATH}",
                f"--load-extension={EXT_PATH}",
                "--no-sandbox",
                "--disable-gpu",
                "--no-first-run",
            ],
            ignore_https_errors=True,
        )

        page = context.pages[0] if context.pages else await context.new_page()

        # Offline test routes so browser works without external network
        async def _safe_route(route, request):
            html = """<!doctype html>
<html>
<head><title>Safe Site - Wikipedia</title><style>body{font-family:sans-serif;padding:30px;line-height:1.6;}</style></head>
<body>
  <h1>Safe Site: Wikipedia</h1>
  <p>This is a simulated safe site (http://www.wikipedia.org/).</p>
  <p>Click the <b>PhishGuard icon</b> in your browser extension toolbar to verify it shows <b>Safe (low risk)</b>.</p>
  <p><a href="http://phishguard.local/">← Back to PhishGuard Test Dashboard</a></p>
</body>
</html>"""
            await route.fulfill(status=200, content_type="text/html", body=html)

        async def _phish_route(route, request):
            html = """<!doctype html>
<html>
<head><title>High Risk Target</title></head>
<body>
  <h1>Suspicious Phishing Target</h1>
  <p>If PhishGuard is in block mode, you should not see this page unless overridden.</p>
  <p><a href="http://phishguard.local/">← Back to Test Dashboard</a></p>
</body>
</html>"""
            await route.fulfill(status=200, content_type="text/html", body=html)

        await context.route("http://www.wikipedia.org/**", _safe_route)
        await context.route("https://www.wikipedia.org/**", _safe_route)
        await context.route("http://phishguard-spike.test/**", _phish_route)

        # Allow service worker time to boot
        await page.goto("about:blank")
        await asyncio.sleep(1.5)

        # Retrieve extension ID
        cdp = await context.new_cdp_session(page)
        targets = await cdp.send("Target.getTargets")
        ext_id = None
        for t in targets.get("targetInfos", []):
            if "chrome-extension://" in t.get("url", ""):
                ext_id = t["url"].split("://")[1].split("/")[0]
                break

        dashboard_html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishGuard Local Test Dashboard</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }}
    .container {{ max-width: 720px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); }}
    h1 {{ color: #38bdf8; margin-top: 0; font-size: 1.8rem; }}
    p {{ color: #94a3b8; font-size: 1rem; line-height: 1.6; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 0.85rem; }}
    .badge-success {{ background: #065f46; color: #6ee7b7; }}
    .card {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin: 16px 0; }}
    .card h3 {{ margin-top: 0; color: #f1f5f9; }}
    a.button {{ display: inline-block; background: #0284c7; color: white; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; margin-top: 8px; }}
    a.button:hover {{ background: #0369a1; }}
    a.button.danger {{ background: #dc2626; }}
    a.button.danger:hover {{ background: #b91c1c; }}
    a.button.secondary {{ background: #334155; }}
    a.button.secondary:hover {{ background: #475569; }}
    .hint {{ font-size: 0.85rem; color: #64748b; margin-top: 8px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ PhishGuard Local Test Dashboard</h1>
    <p><span class="badge badge-success">Extension Loaded</span> Extension ID: <code>{ext_id or 'olkokgomhbnimpkbhidkabofjgfcnhbj'}</code></p>
    <p>PhishGuard is running live in this browser window. You can test all extension features below:</p>
    
    <div class="card">
      <h3>1. Test Safe Site Navigation (Popup Check)</h3>
      <p>Visit simulated Wikipedia. Open the PhishGuard popup from the toolbar puzzle icon to confirm it rates the domain as <b>Safe</b>.</p>
      <a class="button" href="http://www.wikipedia.org/">Visit Safe Site (wikipedia.org)</a>
    </div>

    <div class="card">
      <h3>2. Test High-Risk Interstitial & 30-min Override</h3>
      <p>Visit a simulated phishing target. If enforcementMode is 'block', PhishGuard redirects to the <b>Deceptive site blocked</b> warning page.</p>
      <a class="button danger" href="http://phishguard-spike.test/login/verify-account">Visit High-Risk Phishing Fixture</a>
      <div class="hint">On the warning page, click "I understand the risks, proceed" to test the 30-minute bypass.</div>
    </div>

    <div class="card">
      <h3>3. Extension Pages</h3>
      <p>Directly inspect the extension options, allowlist manager, and first-run experience:</p>
      <a class="button secondary" href="chrome-extension://{ext_id}/src/pages/options.html" target="_blank">Open Settings / Options Page</a>
      &nbsp;
      <a class="button secondary" href="chrome-extension://{ext_id}/src/pages/first_run.html" target="_blank">Open First-Run Onboarding</a>
    </div>
  </div>
</body>
</html>"""

        async def _dashboard_route(route, request):
            await route.fulfill(status=200, content_type="text/html", body=dashboard_html)

        await context.route("http://phishguard.local/**", _dashboard_route)

        # Navigate to the test dashboard
        await page.goto("http://phishguard.local/")

        print("\n" + "=" * 60)
        print("   PHISHGUARD INTERACTIVE CHROMIUM BROWSER RUNNING")
        print("=" * 60)
        print(f"Extension ID: {ext_id}")
        print("A Chromium window has opened on your screen with the Test Dashboard.")
        print("Close the Chromium browser window when you are done testing.\n")

        # Keep browser alive until user closes all pages/window
        try:
            while context.pages:
                await asyncio.sleep(0.5)
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Launch browser with PhishGuard loaded.")
    parser.add_argument("--browser", choices=["playwright", "chrome"], default="playwright")
    args = parser.parse_args()

    asyncio.run(launch_playwright_async())

if __name__ == "__main__":
    main()
