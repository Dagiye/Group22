"""
sitemap.py
-----------
Module to fetch and parse sitemaps from a target web application.
Supports standard XML sitemaps, sitemap indexes, and automatic discovery of sitemap URLs.
"""

import requests
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from typing import List, Set


class SitemapParser:
    def __init__(self, base_url: str, user_agent: str = "Mozilla/5.0"):
        self.base_url = base_url.rstrip("/")
        self.headers = {"User-Agent": user_agent}
        self.sitemaps: Set[str] = set()
        self.urls: Set[str] = set()

    def discover_sitemaps(self) -> List[str]:
        """
        Discover sitemap URLs based on robots.txt or default locations.
        """
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = requests.get(robots_url, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        self.sitemaps.add(sitemap_url)
        except requests.RequestException:
            pass

        # Add common default sitemaps
        default_sitemaps = [
            urljoin(self.base_url, "/sitemap.xml"),
            urljoin(self.base_url, "/sitemap_index.xml")
        ]
        self.sitemaps.update(default_sitemaps)
        return list(self.sitemaps)

    def fetch_sitemap(self, sitemap_url: str) -> Set[str]:
        """
        Fetch a sitemap XML and extract all URLs.
        """
        try:
            resp = requests.get(sitemap_url, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                tree = ET.fromstring(resp.content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                # Handle sitemap index
                if tree.tag.endswith("sitemapindex"):
                    for sitemap in tree.findall("sm:sitemap", ns):
                        loc = sitemap.find("sm:loc", ns)
                        if loc is not None:
                            self.fetch_sitemap(loc.text)
                # Handle URL entries
                elif tree.tag.endswith("urlset"):
                    for url_elem in tree.findall("sm:url", ns):
                        loc = url_elem.find("sm:loc", ns)
                        if loc is not None:
                            self.urls.add(loc.text)
        except Exception as e:
            # For real scanner, consider logging errors
            pass
        return self.urls

    def run(self) -> Set[str]:
        """
        Run the full sitemap discovery and parsing process.
        """
        self.discover_sitemaps()
        for sitemap in self.sitemaps:
            self.fetch_sitemap(sitemap)
        return self.urls


if __name__ == "__main__":
    # Quick test
    target = "https://example.com"
    parser = SitemapParser(target)
    urls = parser.run()
    print(f"Discovered {len(urls)} URLs:")
    for u in urls:
        print(u)
