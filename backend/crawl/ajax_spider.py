"""
ajax_spider.py
---------------
Crawls JavaScript-heavy web apps using Playwright.
Discovers dynamic links, forms, and parameters that normal HTTP requests can't detect.
"""

import asyncio
from typing import Set
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright


class AjaxSpider:
    def __init__(self, base_url: str, max_depth: int = 2, delay: float = 0.5):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.delay = delay
        self.visited: Set[str] = set()
        self.to_visit: Set[str] = set([self.base_url])
        self.params: Set[str] = set()

    async def fetch_page(self, page, url: str) -> Set[str]:
        """Visit a page with Playwright, extract links and form parameters."""
        links: Set[str] = set()
        try:
            await page.goto(url, timeout=15000)
            await asyncio.sleep(self.delay)  # Let JS render

            # Extract links
            anchors = await page.query_selector_all("a[href]")
            for a in anchors:
                href = await a.get_attribute("href")
                if href and not href.startswith("#"):
                    full_url = urlparse(url)._replace(path=href).geturl()
                    if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                        links.add(full_url.split("#")[0])

            # Extract form input names as potential parameters
            forms = await page.query_selector_all("form")
            for form in forms:
                inputs = await form.query_selector_all("input[name]")
                for inp in inputs:
                    name = await inp.get_attribute("name")
                    if name:
                        self.params.add(name)

        except Exception:
            pass
        return links

    async def crawl(self):
        """Main async crawl loop."""
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()

            depth = 0
            current_level = self.to_visit.copy()
            while depth < self.max_depth and current_level:
                next_level = set()
                for url in current_level:
                    if url in self.visited:
                        continue
                    links = await self.fetch_page(page, url)
                    next_level.update(links - self.visited)
                    self.visited.add(url)
                current_level = next_level
                depth += 1

            await browser.close()

    def run(self):
        """Run the spider."""
        asyncio.run(self.crawl())
        return self.visited, self.params


if __name__ == "__main__":
    target = "https://example.com"
    spider = AjaxSpider(target)
    urls, params = spider.run()
    print(f"Discovered {len(urls)} pages (AJAX):")
    for u in urls:
        print(u)
    print(f"Discovered dynamic parameters: {params}")
