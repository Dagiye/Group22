"""
headers.py
----------
Performs passive analysis of HTTP response headers for security issues.
"""

import requests
from typing import Dict, List


class HeaderScanner:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.headers: Dict[str, str] = {}
        self.issues: List[Dict[str, str]] = []

    def fetch_headers(self):
        """Fetch headers using a HEAD request (fallback to GET)."""
        try:
            resp = requests.head(self.url, timeout=10, allow_redirects=True)
            self.headers = dict(resp.headers)
        except Exception:
            try:
                resp = requests.get(self.url, timeout=10, allow_redirects=True)
                self.headers = dict(resp.headers)
            except Exception:
                self.headers = {}

    def analyze(self):
        """Check for common header-based security issues."""
        if not self.headers:
            return []

        # Check security headers
        security_headers = {
            "Content-Security-Policy": "Mitigates XSS attacks",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "X-Frame-Options": "Prevents clickjacking",
            "Strict-Transport-Security": "Enforces HTTPS",
            "Referrer-Policy": "Controls referrer info sent",
            "Permissions-Policy": "Controls access to features like camera/microphone",
        }

        for header, desc in security_headers.items():
            if header not in self.headers:
                self.issues.append({
                    "header": header,
                    "issue": f"{header} is missing",
                    "description": desc
                })

        # Detect server info leakage
        server = self.headers.get("Server")
        if server:
            self.issues.append({
                "header": "Server",
                "issue": f"Server header reveals: {server}",
                "description": "Exposes server software and version information"
            })

        # Detect X-Powered-By leakage
        powered_by = self.headers.get("X-Powered-By")
        if powered_by:
            self.issues.append({
                "header": "X-Powered-By",
                "issue": f"X-Powered-By header reveals: {powered_by}",
                "description": "Exposes underlying technology"
            })

        return self.issues


if __name__ == "__main__":
    url = "https://example.com"
    scanner = HeaderScanner(url)
    scanner.fetch_headers()
    findings = scanner.analyze()

    print(f"Header security findings for {url}:")
    for f in findings:
        print(f)
