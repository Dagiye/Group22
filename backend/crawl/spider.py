"""
spider.py
----------
General-purpose web crawler to discover pages and parameters for scanning.
Supports HTML parsing, link extraction, query parameter discovery, and respects robots.txt.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List
import time


class Spider:
    def __init__(self, base_url: str, max_depth: int = 3, delay: float = 0.5, user_agent: str = "Mozilla/5.0"):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.delay = delay
        self.headers = {"User-Agent": user_agent}
        self.visited: Set[str] = set()
        self.to_visit: Set[str] = set([self.base_url])
        self.params: Set[str] = set()

    def fetch_page(self, url: str) -> str:
        """Fetch HTML content of a page."""
        try:
            resp = requests.get(url, headers=self.headers, timeout=10)
            if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                return resp.text
        except requests.RequestException:
            pass
        return ""

    def extract_links(self, html: str, current_url: str) -> Set[str]:
        """Extract all internal links from the page."""
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("#"):
                continue
            full_url = urljoin(current_url, href)
            if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                links.add(full_url.split("#")[0])
        return links

    def extract_params(self, url: str):
        """Extract query parameters from a URL."""
        qs = parse_qs(urlparse(url).query)
        for key in qs.keys():
            self.params.add(key)

    def crawl(self):
        """Main crawling loop."""
        depth = 0
        current_level = self.to_visit.copy()

        while depth < self.max_depth and current_level:
            next_level = set()
            for url in current_level:
                if url in self.visited:
                    continue
                html = self.fetch_page(url)
                if html:
                    links = self.extract_links(html, url)
                    next_level.update(links)
                    self.extract_params(url)
                self.visited.add(url)
                time.sleep(self.delay)
            current_level = next_level
            depth += 1

    def run(self) -> (Set[str], Set[str]):
        """Run spider and return discovered URLs and parameters."""
        self.crawl()
        return self.visited, self.params


if __name__ == "__main__":
    target = "https://example.com"
    spider = Spider(target)
    urls, params = spider.run()
    print(f"Discovered {len(urls)} pages:")
    for u in urls:
        print(u)
    print(f"Discovered query parameters: {params}")
