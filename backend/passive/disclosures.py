"""
disclosures.py
---------------
Passive scanning module to detect sensitive information leaks in HTTP responses.
"""

import re
import requests
from typing import List, Dict


class DisclosureScanner:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.response_text: str = ""
        self.findings: List[Dict[str, str]] = []

        # Precompiled regex patterns for common secrets
        self.patterns = {
            "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "AWS Secret Key": re.compile(r"(?i)aws_secret_access_key[^=]*=[ ']*([A-Za-z0-9/+=]{40})"),
            "Email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
            "Private Key": re.compile(r"-----BEGIN PRIVATE KEY-----"),
            "JWT Token": re.compile(r"eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+")
        }

    def fetch_response(self):
        """Fetch the page content for analysis."""
        try:
            resp = requests.get(self.url, timeout=10, allow_redirects=True)
            self.response_text = resp.text
        except Exception as e:
            self.findings.append({
                "type": "Fetch Error",
                "pattern": None,
                "value": str(e),
                "description": "Failed to fetch the URL for analysis"
            })

    def analyze(self):
        """Scan response text for sensitive disclosures."""
        if not self.response_text:
            return self.findings

        for name, pattern in self.patterns.items():
            matches = pattern.findall(self.response_text)
            for match in matches:
                self.findings.append({
                    "type": name,
                    "pattern": pattern.pattern,
                    "value": match,
                    "description": f"Potential sensitive information of type '{name}' found in response"
                })

        return self.findings


if __name__ == "__main__":
    url = "https://example.com"
    scanner = DisclosureScanner(url)
    scanner.fetch_response()
    results = scanner.analyze()

    print(f"Sensitive information findings for {url}:")
    for r in results:
        print(r)
