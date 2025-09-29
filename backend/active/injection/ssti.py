"""
ssti.py
-------
Server-Side Template Injection (SSTI) scanner.

Capabilities:
- Test multiple template engines (Jinja2, Twig, Freemarker, Velocity, Razor, JSP)
- Detect SSTI by looking for template evaluation results (e.g., math eval, boolean eval)
- Support both reflected and timing-based (blind) techniques
- Log findings via EvidenceLogger and return structured results
"""

import json
import asyncio
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import aiohttp

from backend.core.evidence import EvidenceLogger
from diffing.responses import ResponseDiffer
from evasions.encode import url_safe

TIME_SAFETY_TIMEOUT = 12


def _with_param(url: str, key: str, value: str) -> str:
    """Helper to inject parameter into query string."""
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


class SSTIScanner:
    """
    Async SSTI scanner that tries safe probes against inputs.
    """

    # Template engine probes (payload, expected marker)
    REFLECTIVE_PROBES: List[Tuple[str, Optional[str]]] = [
        ("{{7*7}}", "49"),          # Jinja2, Django
        ("${7*7}", "49"),           # Freemarker
        ("<%= 7*7 %>", "49"),       # JSP / ERB
        ("${{7*7}}", "49"),         # Razor-style double
        ("$mathTool.multiply(7,7)", "49"),  # Velocity
    ]

    # Timing-based probes (for blind SSTI, only if aggressive is enabled)
    TIMING_PROBES: List[str] = [
        "{{%s}}" % ("''.join(['' for x in range(5000000)])"),  # Jinja loop delay
        "${{ ''.join(['' for x in range(5000000)]) }}",        # Twig / Jinja variant
    ]

    def __init__(self, session: aiohttp.ClientSession, logger: EvidenceLogger, aggressive: bool = False):
        self.session = session
        self.logger = logger
        self.aggressive = aggressive

    async def scan_param(self, url: str, param: str) -> List[Dict]:
        """
        Test a single parameter for SSTI.
        """
        findings = []
        differ = ResponseDiffer()

        for payload, marker in self.REFLECTIVE_PROBES:
            test_url = _with_param(url, param, url_safe(payload))
            try:
                async with self.session.get(test_url, timeout=TIME_SAFETY_TIMEOUT, ssl=False) as resp:
                    body = await resp.text()
                    if marker and marker in body:
                        evidence = {
                            "param": param,
                            "payload": payload,
                            "marker": marker,
                            "engine_hint": "Reflective eval"
                        }
                        await self.logger.log("ssti", url, evidence)
                        findings.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "type": "reflective",
                            "evidence": evidence,
                        })
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue

        if self.aggressive:
            for payload in self.TIMING_PROBES:
                test_url = _with_param(url, param, url_safe(payload))
                try:
                    start = time.time()
                    async with self.session.get(test_url, timeout=TIME_SAFETY_TIMEOUT, ssl=False) as resp:
                        await resp.text()
                    elapsed = time.time() - start
                    if elapsed > 5:  # heuristic threshold
                        evidence = {
                            "param": param,
                            "payload": payload,
                            "delay": elapsed,
                            "engine_hint": "Timing-based SSTI"
                        }
                        await self.logger.log("ssti", url, evidence)
                        findings.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "type": "timing",
                            "evidence": evidence,
                        })
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue

        return findings

    async def scan(self, url: str, params: List[str]) -> List[Dict]:
        """
        Scan all provided parameters on a URL.
        """
        all_findings: List[Dict] = []
        for param in params:
            res = await self.scan_param(url, param)
            all_findings.extend(res)
        return all_findings


# Example entry point for integration
async def run_ssti_scan(target_url: str, params: List[str], aggressive: bool = False) -> List[Dict]:
    async with aiohttp.ClientSession() as session:
        logger = EvidenceLogger()
        scanner = SSTIScanner(session, logger, aggressive)
        findings = await scanner.scan(target_url, params)
        return findings
