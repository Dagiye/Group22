"""
param_miner.py
--------------
Discovers parameters from HTML forms, URLs, and API endpoints.
This is used to find input points for further scanning (XSS, SQLi, etc.).
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from typing import List, Dict


class ParamMiner:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.params: List[Dict] = []

    def fetch_page(self, url: str) -> str:
        """Fetch page content with a GET request."""
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return ""

    def extract_url_params(self, url: str):
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for param, value in query_params.items():
            self.params.append({
                "url": url,
                "param": param,
                "value": value
            })

    def extract_form_params(self, html: str, url: str):
        """Extract parameters from HTML forms."""
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            form_action = form.get("action")
            form_url = urljoin(url, form_action) if form_action else url
            inputs = form.find_all("input")
            for input_tag in inputs:
                name = input_tag.get("name")
                value = input_tag.get("value", "")
                if name:
                    self.params.append({
                        "url": form_url,
                        "param": name,
                        "value": value
                    })

    def run(self, urls: List[str]):
        """Run parameter mining on a list of URLs."""
        for url in urls:
            html = self.fetch_page(url)
            if html:
                self.extract_form_params(html, url)
            self.extract_url_params(url)
        return self.params


if __name__ == "__main__":
    target_urls = ["https://example.com"]
    miner = ParamMiner(target_urls[0])
    results = miner.run(target_urls)
    print(f"Discovered {len(results)} parameters:")
    for p in results:
        print(p)
