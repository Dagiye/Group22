"""
cookies.py
----------
Performs passive analysis of HTTP cookies for security issues.
"""

import requests
from http.cookies import SimpleCookie
from typing import Dict, List


class CookieScanner:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.cookies_raw: str = ""
        self.cookies: Dict[str, Dict[str, str]] = {}
        self.issues: List[Dict[str, str]] = []

    def fetch_cookies(self):
        """Fetch cookies from a GET request."""
        try:
            resp = requests.get(self.url, timeout=10, allow_redirects=True)
            self.cookies_raw = resp.headers.get("Set-Cookie", "")
            self._parse_cookies(resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else [self.cookies_raw])
        except Exception as e:
            self.cookies_raw = ""
            self.cookies = {}
            self.issues.append({"cookie": None, "issue": f"Failed to fetch cookies: {str(e)}", "description": ""})

    def _parse_cookies(self, cookies_list: list):
        """Parse cookies from the Set-Cookie headers."""
        for cookie_header in cookies_list:
            if not cookie_header:
                continue
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            for key, morsel in cookie.items():
                self.cookies[key] = {
                    "value": morsel.value,
                    "secure": morsel["secure"],
                    "httponly": morsel["httponly"],
                    "samesite": morsel["samesite"]
                }

    def analyze(self):
        """Check for insecure cookie attributes."""
        if not self.cookies:
            return []

        for name, attr in self.cookies.items():
            if attr["secure"].lower() != "true":
                self.issues.append({
                    "cookie": name,
                    "issue": "Cookie missing Secure flag",
                    "description": "Should be sent over HTTPS only"
                })
            if attr["httponly"].lower() != "true":
                self.issues.append({
                    "cookie": name,
                    "issue": "Cookie missing HttpOnly flag",
                    "description": "Should be inaccessible to JavaScript to prevent XSS theft"
                })
            if not attr["samesite"]:
                self.issues.append({
                    "cookie": name,
                    "issue": "Cookie missing SameSite attribute",
                    "description": "Should define SameSite to prevent CSRF"
                })

        return self.issues


if __name__ == "__main__":
    url = "https://example.com"
    scanner = CookieScanner(url)
    scanner.fetch_cookies()
    findings = scanner.analyze()

    print(f"Cookie security findings for {url}:")
    for f in findings:
        print(f)
