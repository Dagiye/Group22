"""
xpath.py
--------
Detects XPath / XML path injection issues. Useful for apps that accept XML or use XPath queries server-side.

Behavior:
- Sends special XPath payloads and checks for errors, differences, or disclosure
- Supports GET param injection and POST form / XML body injection
- Matches for common XPath error messages or big diffs in responses
"""

import re
import json
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import aiohttp

from backend.core.evidence import EvidenceLogger
from diffing.responses import ResponseDiffer

XPATH_ERRORS = [
    r"XPathException",
    r"org\.apache\.xpath",
    r"XPATH syntax error",
    r"invalid predicate",
    r"Unclosed token",
]
XPATH_ERR_RE = re.compile("|".join(XPATH_ERRORS), re.IGNORECASE)


def _with_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


class XPathScanner:
    def __init__(self, base_url: str, session: aiohttp.ClientSession, logger: EvidenceLogger, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger
        self.timeout = timeout
        self.differ = ResponseDiffer()
        self.findings: List[Dict] = []

        # payloads to provoke XPath engine behavior (non-destructive)
        self.payloads = [
            "' or '1'='1",
            " ' or 'a'='a",
            "' or count(/*)=1 or '",
            "' or boolean(/*)=true or '",
            "' or //user='admin' or '"
        ]

    async def _get(self, url: str) -> Tuple[int, str, Dict]:
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                return r.status, await r.text(errors="ignore"), dict(r.headers)
        except Exception as e:
            self.logger.log_error("XPathScanner._get", str(e))
            return 0, "", {}

    async def _post(self, url: str, data: Dict, json_body: Optional[dict] = None, headers: Optional[dict] = None) -> Tuple[int, str, Dict]:
        try:
            if json_body is not None:
                async with self.session.post(url, json=json_body, headers=headers or {}, timeout=self.timeout) as r:
                    return r.status, await r.text(errors="ignore"), dict(r.headers)
            else:
                async with self.session.post(url, data=data, headers=headers or {}, timeout=self.timeout) as r:
                    return r.status, await r.text(errors="ignore"), dict(r.headers)
        except Exception as e:
            self.logger.log_error("XPathScanner._post", str(e))
            return 0, "", {}

    def _looks_like_xpath_error(self, text: str) -> Optional[str]:
        m = XPATH_ERR_RE.search(text or "")
        return m.group(0) if m else None

    async def scan_get_params(self, url: str, params: List[str]) -> List[Dict]:
        base_status, base_body, _ = await self._get(url)

        for p in params:
            # error-based
            for payload in self.payloads:
                test_url = _with_param(url, p, payload)
                st, body, _ = await self._get(test_url)
                if st == 0:
                    continue
                err = self._looks_like_xpath_error(body)
                # diffing heuristic: large change between baseline and payload response may indicate injection
                sim = self.differ.similarity(body, base_body[:4000])
                if err or sim < 0.7:
                    finding = self._report(
                        kind="XPath Injection",
                        url=test_url,
                        param=p,
                        payload=payload,
                        evidence=err or f"similarity={sim:.2f}",
                        baseline_status=base_status,
                        status=st,
                        baseline_len=len(base_body),
                        observed_len=len(body),
                    )
                    self.findings.append(finding)
                    break
        return self.findings

    async def scan_post_xml(self, url: str, xml_field: str, xml_template: str, injection_points: List[str]) -> List[Dict]:
        """
        For endpoints that accept XML bodies: xml_template should be a string with placeholders
        e.g., '<request><user>{user}</user><pass>{pass}</pass></request>'
        injection_points are placeholder names to mutate.
        """
        base_status, base_body, _ = await self._post(url, {}, json_body=None, headers={"Content-Type": "application/xml"})
        for point in injection_points:
            for payload in self.payloads:
                xml_body = xml_template.replace("{" + point + "}", payload)
                st, body, _ = await self._post(url, {}, json_body=None, headers={"Content-Type": "application/xml"})
                if st == 0:
                    continue
                err = self._looks_like_xpath_error(body)
                sim = self.differ.similarity(body, base_body[:4000])
                if err or sim < 0.7:
                    finding = self._report(
                        kind="XPath Injection (XML)",
                        url=url,
                        param=point,
                        payload=payload,
                        evidence=err or f"similarity={sim:.2f}",
                        baseline_status=base_status,
                        status=st,
                        baseline_len=len(base_body),
                        observed_len=len(body),
                    )
                    self.findings.append(finding)
                    break
        return self.findings

    def _report(self, kind: str, url: str, param: str, payload: str, evidence: str,
                baseline_status=None, status=None, baseline_len=None, observed_len=None, severity="Medium") -> Dict:
        meta = {
            "kind": kind,
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "baseline_status": baseline_status,
            "status": status,
            "baseline_len": baseline_len,
            "observed_len": observed_len,
            "severity": severity,
        }
        try:
            self.logger.log_finding(category="XPath Injection", url=url, evidence=evidence, severity=severity, meta=meta)
        except Exception:
            pass
        return meta
