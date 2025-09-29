"""
form_discovery.py
-----------------
Crawls a website to discover HTML forms and their input fields.
Collects hidden fields, text fields, selects, and checkboxes for scanning purposes.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict


class FormDiscovery:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.forms: List[Dict] = []

    def fetch_page(self, url: str) -> str:
        """Fetch page content with requests."""
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return ""

    def extract_forms(self, html: str, url: str):
        """Extract all forms and their input fields from a page."""
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            form_details = {
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "get").lower(),
                "inputs": [],
            }

            # Extract input fields
            for input_tag in form.find_all("input"):
                input_info = {
                    "name": input_tag.get("name"),
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value", ""),
                }
                form_details["inputs"].append(input_info)

            # Extract select fields
            for select_tag in form.find_all("select"):
                options = [opt.get("value") for opt in select_tag.find_all("option")]
                form_details["inputs"].append(
                    {"name": select_tag.get("name"), "type": "select", "options": options}
                )

            # Extract textarea fields
            for textarea in form.find_all("textarea"):
                form_details["inputs"].append(
                    {"name": textarea.get("name"), "type": "textarea", "value": textarea.text}
                )

            self.forms.append(form_details)

    def discover(self, urls: List[str]):
        """Discover forms from a list of URLs."""
        for url in urls:
            html = self.fetch_page(url)
            if html:
                self.extract_forms(html, url)

    def run(self, urls: List[str]):
        """Entry point for form discovery."""
        self.discover(urls)
        return self.forms


if __name__ == "__main__":
    target_urls = ["https://example.com"]
    fd = FormDiscovery(target_urls[0])
    forms = fd.run(target_urls)
    print(f"Discovered {len(forms)} forms:")
    for f in forms:
        print(f)
