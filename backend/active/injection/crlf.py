"""
CRLF Injection scanner.
- Tests for HTTP response splitting, header injection, and cache poisoning vectors.
- Sends safe CRLF payloads and analyzes responses & headers for reflection or abnormal behavior.
"""

import asyncio
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import aiohttp

# Safe fallbacks if project utilities are not yet available.
try:
    from backend.core.evidence import EvidenceLogger
except Exception:
    class EvidenceLogger:
        async def log(self, *args, **kwargs): pass
        async def log_finding(self, *args, **kwargs): pass

try:
    from diffing.responses import ResponseDiffer
except Exception:
    class ResponseDiffer:
        def similarity(self, a: str, b: str) -> float:
            return 1.0 if a == b else 0.0


CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20CRLF=1",
    "%0d%0aContent-Length:%200",
    "%0d%0aX-Injected:1",
    "%0d%0aLocation:%20http://evil.com/",
    "%0aSet-Cookie:%20crlf=1",
]

TIMEOUT = 10


def _with_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


class CRLFScanner:
    def __init__(self, session: aiohttp.ClientSession, logger: EvidenceLogger, aggressive: bool = False, timeout: int = TIMEOUT):
        self.session = session
        self.logger = logger
        self.aggressive = aggressive
        self.timeout = timeout
        self.differ = ResponseDiffer()

    async def _get(self, url: str) -> Tuple[int, str, dict]:
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                text = await r.text(errors="ignore")
                return r.status, text, dict(r.headers)
        except Exception as e:
            await self.logger.log("crlf_error", {"url": url, "error": str(e)})
            return 0, "", {}

    async def scan_param(self, url: str, param: str) -> List[Dict]:
        findings: List[Dict] = []
        # baseline
        base_status, base_body, base_headers = await self._get(url)

        for payload in CRLF_PAYLOADS:
            test_url = _with_param(url, param, payload)
            status, body, headers = await self._get(test_url)
            if status == 0:
                continue

            # 1) Check headers for injected header names or values
            injected = {k: v for k, v in headers.items() if "injected" in k.lower() or "crlf" in k.lower() or "x-injected" in k.lower()}
            if injected:
                meta = {
                    "type": "crlf_header_injection",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "injected_headers": injected,
                    "status": status,
                }
                await self.logger.log_finding(category="CRLF", url=url, evidence="header_injection", severity="High", meta=meta)
                findings.append(meta)
                break

            # 2) Check for location redirect injection
            loc = headers.get("Location", "")
            if loc and ("evil.com" in loc or "http://" in loc and param in test_url):
                meta = {
                    "type": "crlf_location_injection",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "location": loc,
                    "status": status,
                }
                await self.logger.log_finding(category="CRLF", url=url, evidence="location_injection", severity="High", meta=meta)
                findings.append(meta)
                break

            # 3) Header reflection into body / content-length confusion
            if "Set-Cookie" in headers and "CRLF" in str(headers.get("Set-Cookie")):
                meta = {
                    "type": "crlf_setcookie_injection",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "set_cookie": headers.get("Set-Cookie"),
                    "status": status,
                }
                await self.logger.log_finding(category="CRLF", url=url, evidence="setcookie_injection", severity="High", meta=meta)
                findings.append(meta)
                break

            # 4) Heuristic: if body changed significantly (could indicate split)
            sim = self.differ.similarity(body, base_body[:4000])
            if sim < 0.6:
                meta = {
                    "type": "crlf_body_diff",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "similarity": sim,
                    "status": status,
                }
                await self.logger.log_finding(category="CRLF", url=url, evidence="body_diff", severity="Medium", meta=meta)
                findings.append(meta)
                # continue scanning other payloads unless aggressive is False
                if not self.aggressive:
                    break

        return findings
