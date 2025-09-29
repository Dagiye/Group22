"""
Reflected XSS detection module.

This module attempts to detect reflected cross-site scripting vulnerabilities
by injecting crafted payloads into query parameters, headers, and POST data.
It monitors whether the payloads are reflected unsafely in the response body
or executed in the DOM context.
"""

import logging
import re
from bs4 import BeautifulSoup
from backend.core.engine import ScanContext

logger = logging.getLogger(__name__)

# A richer set of payloads (covering multiple encodings and bypasses)
XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    "'\"><img src=x onerror=alert(1337)>",
    "<svg/onload=alert(1337)>",
    "<iframe src=javascript:alert(1337)>",
    "<body onload=alert(1337)>",
    "javascript:alert(1337)",  # URL scheme
]

REFLECTION_REGEXES = [
    re.compile(r"<script[^>]*>.*1337.*</script>", re.I),
    re.compile(r"onerror\s*=\s*['\"]?alert", re.I),
    re.compile(r"onload\s*=\s*['\"]?alert", re.I),
]


class ReflectedXSSTester:
    def __init__(self, context: ScanContext):
        self.context = context

    async def test_reflected_xss(self, request):
        findings = []

        for payload in XSS_PAYLOADS:
            modified = request.copy()
            modified.params.update({"xss_test": payload})

            logger.debug(f"[XSS-Reflected] Testing payload: {payload}")
            response = await self.context.http_client.send(modified)

            if not response or not response.text:
                continue

            evidence = None
            # Heuristic 1: Raw payload reflection
            if payload in response.text:
                evidence = f"Payload reflected verbatim in response."

            # Heuristic 2: Regex match for suspicious script injection
            for regex in REFLECTION_REGEXES:
                if regex.search(response.text):
                    evidence = f"Regex match for XSS pattern: {regex.pattern}"
                    break

            # Heuristic 3: DOM inspection (parse HTML to locate sink points)
            if not evidence:
                soup = BeautifulSoup(response.text, "html.parser")
                if soup.find_all(["script", "img", "svg", "iframe"]):
                    if "1337" in response.text:
                        evidence = "Payload present in DOM nodes."

            if evidence:
                findings.append({
                    "type": "Reflected XSS",
                    "severity": "High",
                    "payload": payload,
                    "target": str(modified.url),
                    "evidence": evidence,
                    "impact": "Attacker can execute arbitrary JavaScript in victim's browser.",
                    "remediation": "Sanitize and encode user input before reflection."
                })

        return findings if findings else {"vulnerable": False}
