import asyncio
import pathlib
from playwright.async_api import async_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXT_PATH = str((ROOT / "extension").resolve())
assert (pathlib.Path(EXT_PATH) / "manifest.json").is_file(), f"Manifest file missing at {EXT_PATH}"

async def validate_chunk10_ui():
    user_data = ROOT / ".playwright_profile_ui_test"
    if user_data.exists():
        import shutil
        shutil.rmtree(user_data, ignore_errors=True)
    user_data.mkdir(exist_ok=True)

    print("==================================================")
    print("       PHISHGUARD CHUNK 10 STRICT UI VALIDATION   ")
    print("==================================================")

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
            await route.fulfill(status=200, content_type="text/html", body="<html><body>Wikipedia Safe Home</body></html>")
        await context.route("http://www.wikipedia.org/**", _safe_route)

        async def _high_risk_route(route, request):
            await route.fulfill(status=200, content_type="text/html", body="<html><body>Evil Phishing Target</body></html>")
        await context.route("http://phishguard-spike.test/**", _high_risk_route)

        # Allow SW to boot
        await page.goto("about:blank")
        await asyncio.sleep(2.0)

        # Get extension ID
        cdp = await context.new_cdp_session(page)
        targets = await cdp.send("Target.getTargets")
        ext_id = None
        for t in targets.get("targetInfos", []):
            if "chrome-extension://" in t.get("url", ""):
                ext_id = t["url"].split("://")[1].split("/")[0]
                break
        print(f"[UI-TEST] Detected Extension ID: {ext_id}")
        assert ext_id is not None, "Extension service worker target not found"

        # ─────────────────────────────────────────────────────────────
        # 1. VALIDATE POPUP ON SAFE SITE
        # ─────────────────────────────────────────────────────────────
        print("\n--- 1. Testing Popup on Safe Site ---")
        tab1 = await context.new_page()
        await tab1.goto("http://www.wikipedia.org/")
        await asyncio.sleep(1.0)

        # Open popup page
        popup = await context.new_page()
        await popup.goto(f"chrome-extension://{ext_id}/src/pages/popup.html")
        await asyncio.sleep(0.5)
        debug_session = await popup.evaluate("async () => await chrome.storage.session.get(null)")
        debug_local = await popup.evaluate("async () => await chrome.storage.local.get(null)")
        print(f"  [DEBUG SESSION STORAGE]: {debug_session}")
        print(f"  [DEBUG LOCAL STORAGE]: {debug_local}")

        popup_state = (await popup.locator("#state-label").text_content()).strip()
        popup_host = (await popup.locator("#host").text_content()).strip()
        popup_score = (await popup.locator("#score").text_content()).strip()
        popup_trust_disabled = await popup.locator("#trust").is_disabled()

        print(f"  Popup State: {popup_state}")
        print(f"  Popup Host: {popup_host}")
        print(f"  Popup Risk Score: {popup_score}")
        print(f"  Trust Button Disabled (expected True for Safe): {popup_trust_disabled}")

        assert "Safe" in popup_state, f"Expected Safe state in popup, got {popup_state}"
        assert "wikipedia.org" in popup_host, f"Expected wikipedia.org in host, got {popup_host}"
        assert int(popup_score) <= 34, f"Safe score should be <= 34, got {popup_score}"
        assert popup_trust_disabled is True, "Trust button should be disabled for Safe sites"
        print("  ✓ Popup correctly renders Safe state, score, and disabled trust button.")

        # ─────────────────────────────────────────────────────────────
        # 2. VALIDATE POPUP ON HIGH-RISK SITE
        # ─────────────────────────────────────────────────────────────
        print("\n--- 2. Testing Popup on High-Risk Site (warn_only mode) ---")
        # Ensure warn_only mode
        await popup.evaluate("""
            async () => {
                await chrome.storage.local.set({
                    settings: { enforcementMode: "warn_only", failureMode: "open", bannerEnabled: true }
                });
            }
        """)
        tab2 = await context.new_page()
        await tab2.goto("http://phishguard-spike.test/login/verify-account")
        await asyncio.sleep(1.0)

        await popup.goto(f"chrome-extension://{ext_id}/src/pages/popup.html")
        await asyncio.sleep(0.5)

        hr_state = (await popup.locator("#state-label").text_content()).strip()
        hr_score = (await popup.locator("#score").text_content()).strip()
        hr_reasons = await popup.locator("#reasons li").all_text_contents()
        hr_trust_disabled = await popup.locator("#trust").is_disabled()

        print(f"  Popup State: {hr_state}")
        print(f"  Popup Risk Score: {hr_score}")
        print(f"  Popup Reasons: {hr_reasons}")
        print(f"  Trust Button Disabled (expected False for High-Risk): {hr_trust_disabled}")

        assert "High-Risk" in hr_state, f"Expected High-Risk state, got {hr_state}"
        assert int(hr_score) >= 70, f"High-risk score should be >= 70, got {hr_score}"
        assert len(hr_reasons) > 0 and hr_reasons[0] != "Waiting for the scan.", "Expected reason codes in popup"
        assert hr_trust_disabled is False, "Trust button should be enabled for High-Risk sites"

        # Test "Trust this site" button
        print("  Testing 'Trust this site' button click...")
        await popup.locator("#trust").click()
        await asyncio.sleep(0.5)
        toast_msg = (await popup.locator("#toast").text_content()).strip()
        trust_btn_text = (await popup.locator("#trust").text_content()).strip()
        print(f"  Toast message: {toast_msg}")
        print(f"  Trust button text: {trust_btn_text}")
        assert "Domain added" in toast_msg, f"Expected toast 'Domain added', got '{toast_msg}'"
        assert trust_btn_text == "Trusted", f"Expected button text 'Trusted', got '{trust_btn_text}'"
        assert await popup.locator("#trust").is_disabled(), "Trust button should be disabled after trusting"
        print("  ✓ Trust button and toast confirmed.")

        # Test "Copy report" button
        print("  Testing 'Copy report' button click...")
        # Grant clipboard-read/write
        await context.grant_permissions(["clipboard-read", "clipboard-write"])
        await popup.locator("#copy").click()
        await asyncio.sleep(0.5)
        copy_toast = (await popup.locator("#toast").text_content()).strip()
        print(f"  Copy toast message: {copy_toast}")
        assert copy_toast == "Copied!", f"Expected 'Copied!', got '{copy_toast}'"
        print("  ✓ Copy report button verified.")

        # ─────────────────────────────────────────────────────────────
        # 3. VALIDATE OPTIONS / SETTINGS PAGE
        # ─────────────────────────────────────────────────────────────
        print("\n--- 3. Testing Options / Settings Page ---")
        options = await context.new_page()
        await options.goto(f"chrome-extension://{ext_id}/src/pages/options.html")
        await asyncio.sleep(0.5)

        # Check loaded data
        counters_text = (await options.locator("#counters").text_content()).strip()
        print(f"  Counters display: {counters_text}")
        assert "Scans:" in counters_text and "Blocks:" in counters_text, "Counters missing in options"

        # Check trusted domains list has phishguard-spike.test
        allowlist_items = await options.locator("#allowlist li").all_text_contents()
        print(f"  Current allowlist in UI: {allowlist_items}")
        assert any("phishguard-spike.test" in item for item in allowlist_items), "Expected phishguard-spike.test in allowlist"

        # Test form submission: adding a new custom domain
        print("  Adding domain 'my-secure-portal.org' via options form...")
        await options.locator("#allow-host").fill("my-secure-portal.org")
        await options.locator("#allow-form button[type=submit]").click()
        await asyncio.sleep(0.5)
        save_status = (await options.locator("#save-status").text_content()).strip()
        print(f"  Save status: {save_status}")
        assert "Domain added" in save_status, f"Expected 'Domain added', got '{save_status}'"

        updated_allowlist = await options.locator("#allowlist li").all_text_contents()
        print(f"  Updated allowlist: {updated_allowlist}")
        assert any("my-secure-portal.org" in item for item in updated_allowlist), "New domain not in allowlist"

        # Test multi-tenant hosting rejection (FR-08)
        print("  Testing rejection of hosting domain 'github.io'...")
        await options.locator("#allow-host").fill("github.io")
        await options.locator("#allow-form button[type=submit]").click()
        await asyncio.sleep(0.5)
        reject_status = (await options.locator("#save-status").text_content()).strip()
        print(f"  Hosting rejection status: {reject_status}")
        assert "cannot be allowlisted" in reject_status, f"Expected cannot be allowlisted, got '{reject_status}'"
        print("  ✓ Hosting domain rejection confirmed.")

        # Test removing domain
        print("  Removing 'my-secure-portal.org' via Remove button...")
        # Find the remove button for my-secure-portal.org
        remove_btn = options.locator("li", has_text="my-secure-portal.org").locator("button")
        await remove_btn.click()
        await asyncio.sleep(0.5)
        final_allowlist = await options.locator("#allowlist li").all_text_contents()
        print(f"  Allowlist after removal: {final_allowlist}")
        assert not any("my-secure-portal.org" in item for item in final_allowlist), "Removed domain still present"
        print("  ✓ Allowlist addition and removal verified.")

        # Test settings change: toggle enforcementMode to 'block'
        print("  Toggling enforcementMode to 'block'...")
        await options.locator("input[name=enforcement][value=block]").check()
        await asyncio.sleep(0.5)
        settings_status = (await options.locator("#save-status").text_content()).strip()
        assert settings_status == "Saved.", f"Expected 'Saved.', got '{settings_status}'"
        # Check actual storage
        stored_settings = await options.evaluate("async () => (await chrome.storage.local.get('settings')).settings")
        print(f"  Persisted settings in storage: {stored_settings}")
        assert stored_settings.get("enforcementMode") == "block", "enforcementMode not updated in storage"
        print("  ✓ Settings toggling and persistence verified.")

        # Test Clear Cache and Clear History
        print("  Testing clear-cache button...")
        await options.locator("#clear-cache").click()
        await asyncio.sleep(0.5)
        print("  ✓ Clear cache clicked without errors.")

        print("  Testing clear-history button...")
        await options.locator("#clear-history").click()
        await asyncio.sleep(0.5)
        history_rows = await options.locator("#history tr").count()
        print(f"  History rows after clear: {history_rows}")
        assert history_rows == 0, f"History should be empty after clear, got {history_rows} rows"
        print("  ✓ Clear history verified.")

        # ─────────────────────────────────────────────────────────────
        # 4. VALIDATE FIRST-RUN PAGE
        # ─────────────────────────────────────────────────────────────
        print("\n--- 4. Testing First-Run Onboarding Page ---")
        first_run = await context.new_page()
        await first_run.goto(f"chrome-extension://{ext_id}/src/pages/first_run.html")
        await asyncio.sleep(0.5)

        h1_text = (await first_run.locator("h1").text_content()).strip()
        assert "Welcome to PhishGuard" in h1_text, "First run header mismatch"

        # Check enforcement radio and save
        await first_run.locator("input[name=enforcement][value=warn_only]").check()
        await first_run.locator("#save").click()
        await asyncio.sleep(0.5)
        fr_status = (await first_run.locator("#status").text_content()).strip()
        print(f"  First-run save status: {fr_status}")
        assert "Settings saved" in fr_status, f"Expected 'Settings saved', got '{fr_status}'"
        print("  ✓ First-run onboarding page verified.")

        # ─────────────────────────────────────────────────────────────
        # 5. VALIDATE WARNING INTERSTITIAL CLOSED-FAILURE STATE
        # ─────────────────────────────────────────────────────────────
        print("\n--- 5. Testing Warning Interstitial (Failure Mode Closed) ---")
        warning_page = await context.new_page()
        await warning_page.goto(f"chrome-extension://{ext_id}/src/pages/warning.html?failure=1")
        await asyncio.sleep(0.5)

        failure_el = warning_page.locator("#failure")
        is_hidden = await failure_el.evaluate("el => el.classList.contains('hidden')")
        failure_text = (await failure_el.text_content()).strip()
        print(f"  Failure notice hidden: {is_hidden}")
        print(f"  Failure notice text: {failure_text}")
        assert not is_hidden, "Failure notice should be visible when ?failure=1"
        assert "could not verify the security" in failure_text, "Failure notice text mismatch"
        print("  ✓ FailureMode closed notice renders correctly.")

        await context.close()
        print("\n==================================================")
        print("   ALL CHUNK 10 UI VALIDATION CHECKS PASSED!      ")
        print("==================================================")

if __name__ == "__main__":
    asyncio.run(validate_chunk10_ui())
