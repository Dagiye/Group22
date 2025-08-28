# backend/drivers/browser/playwright_driver.py

from playwright.sync_api import sync_playwright, Page, Browser
from typing import Optional, Dict, Any
import time

class BrowserDriver:
    """
    Browser automation driver using Playwright.
    Supports headless scanning, DOM snapshots, and JS interception.
    """

    def __init__(self, headless: bool = True, viewport: Optional[Dict[str, int]] = None):
        self.headless = headless
        self.viewport = viewport or {"width": 1280, "height": 720}
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None

    def start(self):
        """
        Launch the browser.
        """
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        self.page = self.browser.new_page(viewport=self.viewport)

    def navigate(self, url: str, timeout: int = 10000):
        """
        Navigate to a URL.
        """
        if not self.page:
            raise RuntimeError("Browser not started. Call start() first.")
        self.page.goto(url, timeout=timeout)

    def get_dom_snapshot(self) -> str:
        """
        Return the full page HTML.
        """
        if not self.page:
            raise RuntimeError("Browser not started. Call start() first.")
        return self.page.content()

    def inject_script(self, script_path: str):
        """
        Inject a JavaScript script into the page.
        """
        if not self.page:
            raise RuntimeError("Browser not started. Call start() first.")
        with open(script_path, "r", encoding="utf-8") as f:
            script = f.read()
        self.page.add_init_script(script)

    def capture_network_requests(self) -> list:
        """
        Capture XHR/Fetch network requests.
        Returns a list of request details.
        """
        requests = []

        def log_request(route):
            req = route.request
            requests.append({
                "url": req.url,
                "method": req.method,
                "headers": dict(req.headers),
                "post_data": req.post_data,
            })
            route.continue_()

        self.page.route("**/*", log_request)
        return requests

    def screenshot(self, path: str):
        """
        Take a screenshot of the page.
        """
        if not self.page:
            raise RuntimeError("Browser not started. Call start() first.")
        self.page.screenshot(path=path, full_page=True)

    def close(self):
        """
        Close browser and stop Playwright.
        """
        if self.page:
            self.page.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
