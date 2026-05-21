import os

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("ATDR_RUN_PLAYWRIGHT") != "1",
    reason="Set ATDR_RUN_PLAYWRIGHT=1 with API and Streamlit running to execute browser smoke tests.",
)


def test_streamlit_login_page_smoke():
    sync_api = pytest.importorskip("playwright.sync_api")
    dashboard_url = os.getenv("ATDR_DASHBOARD_URL", "http://127.0.0.1:8501")
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(dashboard_url, wait_until="networkidle", timeout=15000)
        body = page.locator("body").inner_text(timeout=10000)
        assert "ModuleNotFoundError" not in body
        assert "API is unavailable" not in body
        assert "<div" not in body
        browser.close()
