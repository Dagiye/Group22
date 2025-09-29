"""
svg_polyglot.py
---------------
SVG / polyglot XSS detection.

What it does:
- Crafts safe, unique SVG/polyglot payloads containing a non-executing but identifiable marker.
- Injects them into form fields, upload endpoints, or query params (caller supplies where to test).
- Re-visits target display pages or resource endpoints to detect:
    - direct reflection of the SVG payload text,
    - SVG served back with dangerous content-types (e.g., text/html) or inline <script> presence,
    - inline attributes like onload/onerror or embedded script tags inside <svg>.
- Returns structured findings, logs evidence via EvidenceLogger, and is careful not to execute JS itself.

Integration points:
- `session` : aiohttp.ClientSession (async)
- `logger` : EvidenceLogger-like interface with async methods `.log()` and `.log_finding(...)`
- `differ` : ResponseDiffer with `.similarity(a,b)` returning float in 0..1
"""

import asyncio
import uuid
import logging
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
TIMEOUT = 12


# fallback minimal adapters if project not wired yet
try:
    from backend.core.evidence import EvidenceLogger
except Exception:
    class EvidenceLogger:
        async def log(self, *a, **k): pass
        async def log_finding(self, *a, **k): pass

try:
    from diffing.responses import ResponseDiffer
except Exception:
    class ResponseDiffer:
        def similarity(self, a, b): return 1.0 if a == b else 0.0


def _unique_marker() -> str:
    return "SVG_POLY_" + uuid.uuid4().hex[:10]


def make_svg_payload(marker: str) -> str:
    """
    Build a conservative SVG payload containing a unique marker.
    The payload avoids active execution (no inline alert calls), but contains markers and suspicious constructs
    that, if reflected or served incorrectly, likely indicate risk.
    """
    # This SVG contains:
    # - a comment with the marker
    # - an <image> tag with xlink:href (possible vector if not sanitized)
    # - an inline <script> commented out to avoid execution in scanner (server-side detection only)
    # - an <svg> onload attribute value placed as text so we detect attributes (not executed here)
    payload = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!-- {marker} -->\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        f'<title>{marker}</title>'
        # include an attribute-looking string (not executed)
        f'<rect width="100" height="100" style="fill: #eee;" data-marker="{marker}"></rect>'
        # include a script element but keep inside CDATA to avoid accidental eval in scanners
        f'<!-- safe-script-start --><script type="application/ecmascript"><![CDATA[/*{marker}*/]]></script><!-- safe-script-end -->'
        f'</svg>'
    )
    return payload


class SVGPolyglotScanner:
    def __init__(self, session: aiohttp.ClientSession, logger: EvidenceLogger, differ: Optional[ResponseDiffer] = None, timeout: int = TIMEOUT):
        self.session = session
        self.logger = logger
        self.differ = differ or ResponseDiffer()
        self.timeout = timeout

    async def _get(self, url: str) -> Tuple[int, str, dict]:
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.get(url, timeout=timeout) as r:
                txt = await r.text(errors="ignore")
                return r.status, txt, dict(r.headers)
        except Exception as e:
            await self.logger.log("svg_get_error", {"url": url, "error": str(e)})
            return 0, "", {}

    async def _post(self, url: str, data=None, files: Optional[dict] = None, headers: Optional[dict] = None) -> Tuple[int, str, dict]:
        """
        Generic POST helper. If files provided, use multipart/form-data.
        files: {"fieldname": ("filename.svg", svg_bytes, "image/svg+xml")}
        """
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            if files:
                # aiohttp expects multipart writer or pass files in data with open file-like objects.
                # We'll use multipart via aiohttp.FormData for compatibility.
                from aiohttp import FormData
                fd = FormData()
                for k, v in (data or {}).items():
                    fd.add_field(k, str(v))
                for field, (fname, content, ctype) in files.items():
                    fd.add_field(field, content, filename=fname, content_type=ctype)
                async with self.session.post(url, data=fd, timeout=timeout, headers=headers or {}) as r:
                    txt = await r.text(errors="ignore")
                    return r.status, txt, dict(r.headers)
            else:
                async with self.session.post(url, data=data or {}, timeout=timeout, headers=headers or {}) as r:
                    txt = await r.text(errors="ignore")
                    return r.status, txt, dict(r.headers)
        except Exception as e:
            await self.logger.log("svg_post_error", {"url": url, "error": str(e)})
            return 0, "", {}

    # Heuristics to evaluate a returned document for suspicious SVG handling
    def _analyze_response_for_svg(self, url: str, body: str, headers: dict, marker: str) -> List[Dict]:
        findings: List[Dict] = []
        if not body:
            return findings

        ct = headers.get("content-type", "").lower()
        # 1) Check if the marker appears verbatim
        if marker.lower() in body.lower():
            # parse DOM to determine context
            try:
                soup = BeautifulSoup(body, "html.parser")
            except Exception:
                soup = None

            # If content-type indicates image/svg+xml or text/xml, server might be returning raw SVG resource
            if "image/svg+xml" in ct or "xml" in ct:
                # If served as SVG but contains <script> tags or on* attributes inside svg -> high risk
                script_tags = []
                if soup:
                    # find svg elements
                    for svg in soup.find_all("svg"):
                        # look for script tags inside svg
                        for sc in svg.find_all("script"):
                            script_tags.append(str(sc)[:500])
                        # attributes like onload/onerror
                        attr_sinks = []
                        for tag in svg.find_all(True):
                            for a in tag.attrs:
                                if a.lower().startswith("on"):
                                    attr_sinks.append({ "tag": tag.name, "attribute": a, "value": str(tag.attrs.get(a))[:200]})
                    if script_tags or attr_sinks:
                        findings.append({
                            "type": "svg_inline_script_or_attribute",
                            "severity": "High",
                            "evidence": {
                                "marker_found": marker,
                                "script_samples": script_tags,
                                "attribute_sinks": attr_sinks
                            },
                            "url": url,
                            "content_type": ct
                        })
                    else:
                        # marker present in SVG but no script/attributes detected — still suspicious (medium)
                        findings.append({
                            "type": "svg_marker_reflected",
                            "severity": "Medium",
                            "evidence": {"marker_found": marker},
                            "url": url,
                            "content_type": ct
                        })
                else:
                    findings.append({
                        "type": "svg_marker_reflected_unparsed",
                        "severity": "Medium",
                        "evidence": {"marker_found": marker},
                        "url": url,
                        "content_type": ct
                    })

            else:
                # Served as HTML or other content type — if SVG content appears inside HTML without proper encoding,
                # this could lead to execution (e.g., inline SVG in HTML document).
                # Check if <svg> tags exist in HTML
                try:
                    soup = BeautifulSoup(body, "html.parser")
                    svgs = soup.find_all("svg")
                    if svgs:
                        # check for scripts/attributes inside inline SVGs
                        script_samples = []
                        attr_sinks = []
                        for svg in svgs:
                            for sc in svg.find_all("script"):
                                script_samples.append(str(sc)[:500])
                            for tag in svg.find_all(True):
                                for a in tag.attrs:
                                    if a.lower().startswith("on"):
                                        attr_sinks.append({ "tag": tag.name, "attribute": a })
                        severity = "High" if script_samples or attr_sinks else "Medium"
                        findings.append({
                            "type": "svg_embedded_in_html",
                            "severity": severity,
                            "evidence": {
                                "marker_found": marker,
                                "script_samples": script_samples,
                                "attribute_sinks": attr_sinks
                            },
                            "url": url,
                            "content_type": ct
                        })
                    else:
                        # marker present somewhere else in HTML — still suspicious but lower severity
                        findings.append({
                            "type": "svg_marker_in_html",
                            "severity": "Low",
                            "evidence": {"marker_found": marker},
                            "url": url,
                            "content_type": ct
                        })
                except Exception:
                    findings.append({
                        "type": "svg_marker_unparsed_html",
                        "severity": "Low",
                        "evidence": {"marker_found": marker},
                        "url": url,
                        "content_type": ct
                    })
        else:
            # marker not found; check for returned SVG resources with suspicious artifacts (e.g., script tags)
            if "image/svg+xml" in ct or "xml" in ct:
                try:
                    soup = BeautifulSoup(body, "xml")
                    scripts = soup.find_all("script")
                    if scripts:
                        findings.append({
                            "type": "svg_resource_with_scripts",
                            "severity": "High",
                            "evidence": {"script_samples": [str(s)[:500] for s in scripts]},
                            "url": url,
                            "content_type": ct
                        })
                except Exception:
                    pass

        return findings

    async def test_injection_point(self, injection_url: str, param_name: Optional[str] = None, method: str = "POST", upload_field: Optional[str] = None) -> List[Dict]:
        """
        injection_url : endpoint to submit SVG (form action, upload endpoint, query target)
        param_name : if provided, place SVG into this param or form field
        method : "GET" or "POST"
        upload_field : if provided, use multipart upload under this field name with filename.svg and content-type image/svg+xml

        Returns list of findings (may be empty).
        """
        findings: List[Dict] = []
        marker = _unique_marker()
        svg_payload = make_svg_payload(marker)

        # baseline get/post to compare if needed
        # perform the submission/injection
        if upload_field:
            # upload as multipart file
            files = {upload_field: (f"{marker}.svg", svg_payload.encode("utf-8"), "image/svg+xml")}
            status, body, headers = await self._post(injection_url, data={}, files=files)
        else:
            if method.upper() == "GET":
                # place payload into query param
                parsed = urlparse(injection_url)
                q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                q[param_name or "svg"] = svg_payload
                new_q = urlencode(q, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_q))
                status, body, headers = await self._get(test_url)
            else:
                # POST form-encoded
                data = { (param_name or "svg"): svg_payload }
                status, body, headers = await self._post(injection_url, data=data)

        # log submission
        await self.logger.log("svg_injection_submitted", {"url": injection_url, "marker": marker, "status": status})

        # After submission, caller should normally provide the page(s) where stored content may be displayed.
        # For convenience, try these heuristics:
        candidates = [injection_url]
        # If injection endpoint returns a Location header, follow it
        loc = headers.get("Location")
        if loc:
            candidates.insert(0, urljoin(injection_url, loc))

        # Check candidate pages/resources for reflection or suspicious svg handling
        all_findings: List[Dict] = []
        for candidate in candidates:
            st2, body2, headers2 = await self._get(candidate)
            if st2 == 0:
                continue
            fs = self._analyze_response_for_svg(candidate, body2, headers2, marker)
            if fs:
                for f in fs:
                    # enrich and persist finding
                    f_meta = {
                        "injection_point": injection_url,
                        "marker": marker,
                        "original_status": status,
                        "response_status": st2,
                        "content_type": headers2.get("content-type"),
                        "url": candidate,
                    }
                    try:
                        await self.logger.log_finding(category="SVG Polyglot", url=candidate, evidence=f.get("evidence") or marker, severity=f.get("severity", "Medium"), meta={**f_meta, **f})
                    except Exception:
                        pass
                    all_findings.append({**f_meta, **f})

        return all_findings

    async def scan_candidates(self, injection_points: List[Dict]) -> List[Dict]:
        """
        Helper to scan multiple injection candidate definitions.

        injection_points: list of dicts:
          {
            "url": str,
            "param": Optional[str],
            "method": "GET"|"POST",
            "upload_field": Optional[str]
          }

        Returns aggregated findings.
        """
        results = []
        for ip in injection_points:
            try:
                res = await self.test_injection_point(ip["url"], param_name=ip.get("param"), method=ip.get("method","POST"), upload_field=ip.get("upload_field"))
                results.extend(res)
            except Exception as e:
                await self.logger.log("svg_scan_error", {"point": ip, "error": str(e)})
        return results
