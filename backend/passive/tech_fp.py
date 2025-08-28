"""
tech_fp.py
----------
Passive scanning module for technology fingerprinting.
Detects web server, framework, CMS, programming language, and common libraries.
"""

import requests
from typing import Dict, List
import re


class TechnologyFingerprint:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.headers: Dict[str, str] = {}
        self.body: str = ""
        self.technologies: List[Dict[str, str]] = []

        # Predefined patterns for technology detection
        self.header_patterns = {
            "Server": re.compile(r".*"),
            "X-Powered-By": re.compile(r".*")
        }

        self.body_patterns = {
            "WordPress": re.compile(r"wp-content"),
            "Joomla": re.compile(r"/templates/"),
            "Drupal": re.compile(r"/sites/"),
            "React": re.compile(r"__REACT_DEVTOOLS_GLOBAL_HOOK__"),
            "Angular": re.compile(r"ng-version"),
            "Vue.js": re.compile(r"__VUE_DEVTOOLS_GLOBAL_HOOK__"),
            "Express.js": re.compile(r"express"),
            "Django": re.compile(r"csrftoken"),
            "Flask": re.compile(r"flask"),
        }

    def fetch_response(self):
        """Fetch headers and body for fingerprinting."""
        try:
            resp = requests.get(self.url, timeout=10, allow_redirects=True)
            self.headers = resp.headers
            self.body = resp.text
        except Exception as e:
            self.technologies.append({
                "type": "Fetch Error",
                "pattern": None,
                "value": str(e),
                "description": "Failed to fetch URL for fingerprinting"
            })

    def analyze_headers(self):
        """Analyze response headers for technology indicators."""
        for header, pattern in self.header_patterns.items():
            value = self.headers.get(header)
            if value:
                self.technologies.append({
                    "type": f"Header: {header}",
                    "pattern": pattern.pattern,
                    "value": value,
                    "description": f"Technology info from {header} header"
                })

    def analyze_body(self):
        """Analyze response body for technology indicators."""
        for tech, pattern in self.body_patterns.items():
            if pattern.search(self.body):
                self.technologies.append({
                    "type": "Body Fingerprint",
                    "pattern": pattern.pattern,
                    "value": tech,
                    "description": f"{tech} detected in page source"
                })

    def fingerprint(self):
        """Main method to perform fingerprinting."""
        self.fetch_response()
        if self.headers:
            self.analyze_headers()
        if self.body:
            self.analyze_body()
        return self.technologies


if __name__ == "__main__":
    url = "https://example.com"
    fp = TechnologyFingerprint(url)
    results = fp.fingerprint()

    print(f"Technology fingerprinting results for {url}:")
    for tech in results:
        print(tech)
