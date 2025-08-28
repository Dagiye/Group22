"""
rfi.py
------
Remote File Inclusion (RFI) detection helpers.

Features:
- Test endpoints by supplying remote URLs as inputs (http/https)
- Check for SSRF-like behavior or inclusion of remote content
- Safeguards: do NOT include attacker-controlled HTTP endpoints in payloads by default;
  this module returns findings and lets caller decide whether to attempt out-of-band detection.
- Structured findings for integration with evidence store
"""

import requests
from typing import List, Dict, Optional
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

COMMON_RFI_PAYLOADS = [
    "http://example.com/",          # non-malicious placeholder (caller should replace for OOB)
    "https://example.com/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/"  # cloud metadata probe (be careful)
]

class RFIScanner:
    def __init__(self, base_url: str, timeout: int = 8, user_agent: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent or "WebScanner-RFI/1.0"
        self.findings: List[Dict] = []

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self.user_agent)
        try:
            return requests.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            logger.debug("Request error for %s: %s", url, e)
            return None

    def test_param(self, endpoint: str, param: str, payloads: Optional[List[str]] = None):
        """
        Inject remote URLs into query parameter and check the response for signs
        that the remote content was included or fetched.
        """
        p_list = payloads or COMMON_RFI_PAYLOADS
        for p in p_list:
            url = f"{self.base_url}{endpoint}"
            params = {param: p}
            resp = self._request("GET", url, params=params)
            if not resp:
                continue
            body = resp.text or ""
            if self._rfi_fingerprint(body, p):
                self.findings.append({
                    "type": "RFI",
                    "endpoint": endpoint,
                    "injection": "query",
                    "param": param,
                    "payload": p,
                    "status_code": resp.status_code,
                    "evidence_snippet": body[:800]
                })

    def test_post(self, endpoint: str, field: str, payloads: Optional[List[str]] = None):
        p_list = payloads or COMMON_RFI_PAYLOADS
        for p in p_list:
            url = f"{self.base_url}{endpoint}"
            data = {field: p}
            resp = self._request("POST", url, data=data)
            if not resp:
                continue
            body = resp.text or ""
            if self._rfi_fingerprint(body, p):
                self.findings.append({
                    "type": "RFI",
                    "endpoint": endpoint,
                    "injection": "body",
                    "field": field,
                    "payload": p,
                    "status_code": resp.status_code,
                    "evidence_snippet": body[:800]
                })

    def _rfi_fingerprint(self, body: str, payload_url: str) -> bool:
        """
        Very conservative heuristics:
        - body contains the hostname or unique marker of the payload_url
        - body includes remote HTML content (e.g., '<html' combined with payload host)
        IMPORTANT: For real OOB verification, use a controlled callback domain
        (not provided here) and check server-side logs for inbound requests.
        """
        low = body.lower()
        if payload_url.lower().startswith("http://") or payload_url.lower().startswith("https://"):
            host = payload_url.split("//", 1)[1].split("/", 1)[0].lower()
            if host in low:
                return True
            # look for typical remote includes
            if "<html" in low or "<!doctype html" in low or "doctype html" in low:
                # remote content included
                return True
        # extra checks for cloud metadata indicators
        if "169.254.169.254" in payload_url and ("meta-data" in low or "iam" in low):
            return True
        return False

    def run(self) -> List[Dict]:
        return self.findings
