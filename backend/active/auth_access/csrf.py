from typing import Dict, List
import requests
from bs4 import BeautifulSoup

class CSRFAttackTester:
    """
    Detect CSRF vulnerabilities by checking for missing or static anti-CSRF tokens.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.findings: List[Dict] = []

    def check_form(self, endpoint: str):
        resp = requests.get(f"{self.base_url}{endpoint}")
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        for form in forms:
            tokens = [inp for inp in form.find_all("input") if "csrf" in inp.get("name", "").lower()]

            if not tokens:
                self.findings.append({
                    "type": "CSRF",
                    "endpoint": endpoint,
                    "details": "Form is missing CSRF token"
                })
            elif all(inp.get("value") in (None, "", "1234") for inp in tokens):
                self.findings.append({
                    "type": "CSRF",
                    "endpoint": endpoint,
                    "details": "Static or predictable CSRF token"
                })

    def run(self, endpoints: List[str]) -> List[Dict]:
        for ep in endpoints:
            self.check_form(ep)
        return self.findings
