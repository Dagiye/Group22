"""
api_discovery.py
----------------
Discovers API endpoints and query parameters from a target website.
Supports both static URL enumeration and simple endpoint probing.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict
import re


class APIDiscovery:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.endpoints: List[Dict] = []

    def fetch_page(self, url: str) -> str:
        """Fetch page content with requests."""
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return ""

    def extract_links(self, html: str) -> List[str]:
        """Extract all links from page content."""
        urls = re.findall(r'href=[\'"]?([^\'" >]+)', html)
        full_urls = [urljoin(self.base_url, u) for u in urls if u.startswith("/")]
        return full_urls

    def discover_api_from_urls(self, urls: List[str]):
        """Identify endpoints that look like API URLs."""
        for url in urls:
            html = self.fetch_page(url)
            if html:
                links = self.extract_links(html)
                for link in links:
                    if re.search(r"/api/|/graphql|/v\d+/", link):
                        parsed = urlparse(link)
                        params = parse_qs(parsed.query)
                        endpoint_info = {
                            "url": link,
                            "path": parsed.path,
                            "params": params,
                        }
                        if endpoint_info not in self.endpoints:
                            self.endpoints.append(endpoint_info)

    def run(self, urls: List[str]):
        """Entry point for API discovery."""
        self.discover_api_from_urls(urls)
        return self.endpoints


if __name__ == "__main__":
    target_urls = ["https://example.com"]
    api_discover = APIDiscovery(target_urls[0])
    endpoints = api_discover.run(target_urls)
    print(f"Discovered {len(endpoints)} API endpoints:")
    for e in endpoints:
        print(e)
