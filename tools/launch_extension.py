"""Launch Chrome / Playwright Chromium with PhishGuard extension loaded.

Usage:
    python tools/launch_extension.py [--browser chrome|playwright]
"""

import argparse
import asyncio
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXT_PATH = (ROOT / "extension").resolve()
assert (EXT_PATH / "manifest.json").is_file(), f"manifest.json missing at {EXT_PATH}"

def launch_chrome():
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    chrome_bin = next((p for p in chrome_paths if os.path.isfile(p)), None)
    if not chrome_bin:
        print("[Launcher] Chrome executable not found, falling back to Playwright Chromium...")
        return launch_playwright()

    user_data = ROOT / ".chrome_dev_profile"
    user_data.mkdir(exist_ok=True)

    args = [
        chrome_bin,
        f"--user-data-dir={user_data}",
        f"--disable-extensions-except={EXT_PATH}",
        f"--load-extension={EXT_PATH}",
        "--no-first-run",
        "https://www.wikipedia.org",
    ]
    print(f"[Launcher] Launching Google Chrome with PhishGuard...")
    print(f"[Launcher] Extension directory: {EXT_PATH}")
    print(f"[Launcher] User profile: {user_data}")
    subprocess.Popen(args)
    print("[Launcher] Chrome launched successfully! Check your taskbar / screen.")

async def launch_playwright_async():
    from playwright.async_api import async_playwright

    user_data = ROOT / ".playwright_profile_interactive"
    user_data.mkdir(exist_ok=True)

    print(f"[Launcher] Launching Playwright Chromium with PhishGuard...")
    print(f"[Launcher] Extension directory: {EXT_PATH}")

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(user_data),
            headless=False,
            args=[
                f"--disable-extensions-except={EXT_PATH}",
                f"--load-extension={EXT_PATH}",
                "--no-first-run",
            ],
        )

        page = context.pages[0] if context.pages else await context.new_page()
        await page.goto("https://www.wikipedia.org")

        print("[Launcher] Chromium is running!")
        print("[Launcher] PhishGuard is loaded in the extension toolbar (top-right puzzle icon).")
        print("[Launcher] Keep this terminal open or close the browser window when done.")

        while context.pages:
            await asyncio.sleep(1)

def launch_playwright():
    asyncio.run(launch_playwright_async())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Launch browser with PhishGuard loaded.")
    parser.add_argument("--browser", choices=["chrome", "playwright"], default="chrome")
    args = parser.parse_args()

    if args.browser == "chrome":
        launch_chrome()
    else:
        launch_playwright()
