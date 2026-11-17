import asyncio
import pathlib
import time
from playwright.async_api import async_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXT_PATH = str((ROOT / "extension").resolve())
assert (pathlib.Path(EXT_PATH) / "manifest.json").is_file(), f"Manifest file missing at {EXT_PATH}"

async def test_e2e():
    user_data = ROOT / ".playwright_profile_test"
    user_data.mkdir(exist_ok=True)
    
    async with async_playwright() as pw:
        context = await pw.chromium.launch_persistent_context(
            str(user_data),
            headless=False,
            args=[
                f"--disable-extensions-except={EXT_PATH}",
                f"--load-extension={EXT_PATH}",
                "--no-sandbox",
                "--disable-gpu",
            ],
            ignore_https_errors=True,
        )
        page = await context.new_page()
        
        # Intercept fake domains
        async def _safe_route(route, request):
            await route.fulfill(status=200, content_type="text/html", body="<html><body>Safe page content</body></html>")
        await context.route("http://www.wikipedia.org/**", _safe_route)

        async def _high_risk_route(route, request):
            await route.fulfill(status=200, content_type="text/html", body="<html><body>Evil Phishing Target</body></html>")
        await context.route("http://phishguard-spike.test/**", _high_risk_route)
        
        # Give SW time to boot
        await page.goto("about:blank")
        await asyncio.sleep(2.0)
        
        # Get extension ID from service worker target
        cdp = await context.new_cdp_session(page)
        targets = await cdp.send("Target.getTargets")
        ext_id = None
        for t in targets.get("targetInfos", []):
            if "chrome-extension://" in t.get("url", ""):
                ext_id = t["url"].split("://")[1].split("/")[0]
                break
        print(f"[E2E] Found extension ID: {ext_id}")
        assert ext_id is not None, "Extension service worker target not found"
        
        # Open extension popup to enable block mode for testing
        popup_url = f"chrome-extension://{ext_id}/src/pages/popup.html"
        await page.goto(popup_url)
        await asyncio.sleep(0.5)
        # Set settings enforcementMode to "block"
        await page.evaluate("""
            async () => {
                await chrome.storage.local.set({
                    settings: { enforcementMode: "block", failureMode: "open", bannerEnabled: true }
                });
            }
        """)
        print("[E2E] Settings set to enforcementMode='block'")

        # ── Test 1: Safe navigation untouched ───────────────────────────
        print("\n[E2E] Test 1: Navigating to safe site...")
        await page.goto("http://www.wikipedia.org/")
        await asyncio.sleep(1.0)
        print(f"[E2E] Current URL: {page.url}")
        content = await page.content()
        assert "Safe page content" in content, "Safe page content was not loaded!"
        assert "warning.html" not in page.url, "Safe navigation was unexpectedly blocked!"
        print("[E2E] PASS: Safe navigation untouched.")

        # ── Test 2: Fixture High-Risk navigation shows interstitial ──────
        print("\n[E2E] Test 2: Navigating to High-Risk fixture site...")
        high_risk_url = "http://phishguard-spike.test/login/verify-account"
        try:
            await page.goto(high_risk_url, wait_until="commit", timeout=5000)
        except Exception:
            pass
        await asyncio.sleep(1.0)
        print(f"[E2E] Current URL after High-Risk nav: {page.url}")
        assert "warning.html" in page.url, f"Expected interstitial warning.html, got {page.url}"
        assert "token=" in page.url, "Warning page URL does not contain token"
        
        # Verify interstitial contents
        heading = await page.locator("h1").text_content()
        print(f"[E2E] Interstitial heading: {heading.strip()}")
        assert "Deceptive site blocked" in heading, "Warning page heading text mismatch"
        print("[E2E] PASS: High-Risk navigation redirected to interstitial.")

        # ── Test 3: Override works for 30 min on exact URL ──────────────
        print("\n[E2E] Test 3: Testing override proceed...")
        # First click toggle button to reveal proceed section
        toggle_btn = page.locator("#btn-proceed-toggle")
        await toggle_btn.click()
        await asyncio.sleep(0.3)

        # Check risk-check checkbox
        checkbox = page.locator("#risk-check")
        await checkbox.check()

        # Wait for FR-10 1-second friction timer to expire
        await asyncio.sleep(1.3)
        proceed_btn = page.locator("#btn-proceed")
        assert await proceed_btn.is_enabled(), "Proceed button should be enabled after 1s delay"

        # Click proceed
        await proceed_btn.click()
        await asyncio.sleep(1.5)
        print(f"[E2E] URL after clicking proceed: {page.url}")
        assert "phishguard-spike.test" in page.url, f"Failed to override to target URL, got {page.url}"
        page_content = await page.content()
        assert "Evil Phishing Target" in page_content, "Target page not loaded after proceed override"

        # Re-navigate to exact URL: should NOT block because override is active
        print("[E2E] Re-navigating to exact URL during 30-min override window...")
        await page.goto(high_risk_url, wait_until="commit")
        await asyncio.sleep(1.0)
        print(f"[E2E] Current URL on re-navigation: {page.url}")
        assert "warning.html" not in page.url, "URL was blocked despite active 30-min override!"
        assert "Evil Phishing Target" in await page.content(), "Page not accessible under override"
        print("[E2E] PASS: Override allows navigation for 30 min on the exact URL.")
        
        await context.close()
        print("\n[E2E] ALL PLAYWRIGHT E2E ASSERTIONS PASSED!")

if __name__ == "__main__":
    asyncio.run(test_e2e())
