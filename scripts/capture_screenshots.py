#!/usr/bin/env python3
"""Capture README screenshots from the RUNNING dashboard with headless Chromium.

    streamlit run dashboard/app.py &          # serve the real app
    python scripts/capture_screenshots.py     # writes screenshots/*.png

Every image is a real render of the application at http://127.0.0.1:8501; nothing
is mocked. Uses the locally installed Chrome (channel="chrome") when available.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "screenshots"


def wait_ready(page: Page, text: str, timeout: float = 60) -> None:
    page.wait_for_selector(f"text={text}", timeout=timeout * 1000)
    # Streamlit streams elements; wait until the run indicator disappears and charts are drawn.
    end = time.time() + timeout
    while time.time() < end:
        running = page.locator('[data-testid="stStatusWidget"]').count()
        if not running:
            break
        time.sleep(0.5)
    time.sleep(2.5)


def shot(page: Page, name: str, height: int | None = None) -> None:
    if height:
        page.set_viewport_size({"width": 1600, "height": height})
        time.sleep(1.5)
    path = OUT / name
    page.screenshot(path=str(path), full_page=False)
    print(f"saved {path.relative_to(ROOT)}")


def click_tab(page: Page, label: str) -> None:
    page.get_by_role("tab", name=label).click()
    time.sleep(2.5)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8501")
    p.add_argument("--investigate", default="127.0.0.1", help="attacker IP for the investigation view")
    args = p.parse_args()
    OUT.mkdir(exist_ok=True)

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(channel="chrome", headless=True)
        except Exception:  # noqa: BLE001 - fall back to Playwright's bundled Chromium
            browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=2,
                                color_scheme="dark")

        def visit(path: str, ready: str, name: str, height: int) -> None:
            page.set_viewport_size({"width": 1600, "height": height})
            page.goto(args.url + path, wait_until="networkidle")
            wait_ready(page, ready)
            shot(page, name)

        visit("/", "Highest-risk attackers", "01-dashboard-overview.png", 1180)
        visit("/attack-intelligence", "Most common commands", "02-attack-analytics.png", 1500)
        visit(f"/investigation?ip={args.investigate}", "Activity timeline", "03-attacker-investigation.png", 1250)
        visit("/mitre", "Technique evidence", "04-mitre-mapping.png", 1620)
        visit("/detections", "Alert queue", "05-alert-center.png", 1500)

        page.set_viewport_size({"width": 1600, "height": 1250})
        page.goto(args.url + "/evidence", wait_until="networkidle")
        wait_ready(page, "Event record")
        page.get_by_placeholder("wget, authorized_keys, root …").fill("wget")
        page.keyboard.press("Enter")
        time.sleep(3)
        page.locator('[data-testid="stDataFrame"]').first.click(position={"x": 18, "y": 52})
        time.sleep(3)
        shot(page, "06-evidence-explorer.png")

        visit("/platform", "AWS architecture", "07-aws-architecture.png", 1080)
        page.set_viewport_size({"width": 1600, "height": 1350})
        click_tab(page, "Terraform & IaC security")
        shot(page, "08-terraform-validation.png")
        page.set_viewport_size({"width": 1600, "height": 1050})
        click_tab(page, "Automated tests")
        shot(page, "09-automated-tests.png")
        page.set_viewport_size({"width": 1600, "height": 760})
        click_tab(page, "Attack simulations")
        shot(page, "10-attack-simulations.png")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
