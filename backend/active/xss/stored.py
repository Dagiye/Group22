"""
stored.py
---------
Stored (persistent) XSS scanner.

Workflow:
1. Discover forms / postable endpoints on an entry page (caller may supply or scan).
2. For each form, inject unique, low-impact payloads per field and submit.
3. Optionally follow links / refresh pages where the submitted content may be rendered.
4. Detect stored reflections with:
   - direct string match of unique marker,
   - DOM node context (script, attribute, JS sink),
   - diffing vs baseline to find inserted content.
5. Log findings via EvidenceLogger.

Notes:
- This module intentionally avoids payloads that execute alerts in automated environments;
  instead, it uses unique markers (e.g., XSS_STORED_<uuid>) to detect persistence.
- For real exploitation proof, the orchestration should optionally enable reflective/execution checks in a browser (Playwright)
  to see if the stored payload executes. This module focuses on detection of storage & unsafe insertion.
"""

import asyncio
import logging
import json
import uuid
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

# Project adapters (replace with your actual implementations)
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

logger = logging.getLogger(__name__)
TIMEOUT = 12


# Conservative stored XSS marker template — unique per submission
def make_marker() -> str:
    return f"XSS_STORED_{uuid.uuid4().hex[:10]}"


# Field injection strategies: how to place the marker into different input types
def craft_payload_for_field(field_type: str, marker: str) -> str:
    # Keep payload small and unambiguous; avoid newline/control characters
    if field_type in ("text", "search", "email", "textarea"):
        return f"{marker}"
    if field_type in ("url",):
        # embed marker in URL-safe form
        return f"http://example.com/{marker}"
    # fallback
    return marker


class StoredXSSTester:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        logger: EvidenceLogger,
        differ: Optional[ResponseDiffer] = None,
        max_follow: int = 10,
        timeout: int = TIMEOUT,
    ):
        self.session = session
        self.logger = logger
        self.differ = differ or ResponseDiffer()
        self.max_follow = max_follow
        self.timeout = timeout

    async def _get(self, url: str) -> Tuple[int, str, dict]:
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                text = await r.text(errors="ignore")
                return r.status, text, dict(r.headers)
        except Exception as e:
            await self.logger.log("stored_xss_error", {"stage": "_get", "url": url, "error": str(e)})
            return 0, "", {}

    async def _post(self, url: str, data: dict, headers: Optional[dict] = None) -> Tuple[int, str, dict]:
        try:
            async with self.session.post(url, data=data, headers=headers or {}, timeout=self.timeout) as r:
                text = await r.text(errors="ignore")
                return r.status, text, dict(r.headers)
        except Exception as e:
            await self.logger.log("stored_xss_error", {"stage": "_post", "url": url, "error": str(e)})
            return 0, "", {}

    def _extract_forms(self, base_url: str, html: str) -> List[Dict]:
        """
        Parse HTML and return a list of form descriptors:
        {action, method, fields: [{name, type, value}]}
        """
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            action = urljoin(base_url, action)
            method = (f.get("method") or "get").lower()
            fields = []
            # inputs
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                ftype = inp.get("type") or ("textarea" if inp.name == "textarea" else "text")
                value = inp.get("value") or ""
                fields.append({"name": name, "type": ftype, "value": value})
            forms.append({"action": action, "method": method, "fields": fields})
        return forms

    async def discover_display_locations(self, entry_url: str) -> List[str]:
        """
        Heuristic: follow some links from the entry page to find candidate pages where stored content may appear.
        This is a conservative, configurable crawl that returns a list of URLs to re-check after posting.
        The caller may replace/override this function to use an app-specific flow (e.g., comment page → article page).
        """
        status, html, _ = await self._get(entry_url)
        if status == 0 or not html:
            return []
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True)[: self.max_follow]:
            href = a["href"]
            full = urljoin(entry_url, href)
            # skip mailto, javascript, fragments
            if full.startswith("javascript:") or full.startswith("mailto:") or "#" in full:
                continue
            parsed = urlparse(full)
            if not parsed.scheme.startswith("http"):
                continue
            links.append(full)
        # dedupe while preserving order
        seen = set()
        result = []
        for u in links:
            if u not in seen:
                seen.add(u)
                result.append(u)
        return result

    async def submit_form_with_marker(self, form: Dict, marker_map: Dict[str, str]) -> Tuple[int, str]:
        """
        Submit a form with markers injected into fields using POST or GET.
        marker_map is {field_name: marker_payload}
        """
        action = form["action"]
        method = form["method"].lower()
        data = {}
        for f in form["fields"]:
            name = f["name"]
            if name in marker_map:
                data[name] = marker_map[name]
            else:
                data[name] = f.get("value") or ""
        if method == "get":
            # append as query
            # build query string
            q = "&".join([f"{k}={aiohttp.helpers.quote(v, safe='')}" for k, v in data.items()])
            url = f"{action}?{q}" if "?" not in action else f"{action}&{q}"
            st, txt, _ = await self._get(url)
            return st, txt
        else:
            st, txt, _ = await self._post(action, data)
            return st, txt

    async def analyze_for_marker(self, url: str, html: str, markers: List[str]) -> List[Dict]:
        """
        Look for each marker in HTML by:
         - direct substring search
         - DOM node classification (script, attribute, text node)
         - diffing compared to baseline (if baseline provided by caller)
        Returns findings list of dicts.
        """
        findings = []
        if not html:
            return findings
        low = html.lower()
        for m in markers:
            if m.lower() in low:
                # Determine context using BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
                # find elements that contain the marker
                elems = soup.find_all(string=lambda s: s and m in s)
                for e in elems:
                    parent = e.parent
                    tag = parent.name if parent else "text"
                    attr_context = None
                    # if marker appears inside an attribute (e.g., <img alt="marker">)
                    for attr_name, attr_val in parent.attrs.items() if parent and isinstance(parent.attrs, dict) else []:
                        try:
                            if isinstance(attr_val, str) and m in attr_val:
                                attr_context = attr_name
                                break
                            if isinstance(attr_val, list) and any(m in x for x in attr_val):
                                attr_context = attr_name
                                break
                        except Exception:
                            continue
                    context = {
                        "tag": tag,
                        "attribute": attr_context,
                        "snippet": str(parent)[:800],
                    }
                    severity = "High" if tag in ("script", "iframe", "svg", "object") or attr_context in ("onerror", "onload", "onclick") else "Medium"
                    findings.append({
                        "type": "Stored XSS",
                        "marker": m,
                        "url": url,
                        "context": context,
                        "severity": severity,
                        "remediation": "Encode output contextually and sanitize stored content.",
                    })
        return findings

    async def scan_page_for_stored(self, entry_url: str) -> List[Dict]:
        """
        Full page-level stored XSS scanner:
        - Get entry page
        - Extract forms
        - For each form, craft unique marker per field and submit
        - Discover follow-up pages (display locations) and re-check for markers
        """
        all_findings = []
        st, html, _ = await self._get(entry_url)
        if st == 0 or not html:
            return all_findings

        forms = self._extract_forms(entry_url, html)
        if not forms:
            # no forms; nothing to submit => nothing to test
            return all_findings

        # For each form, prepare marker map and submit
        for form in forms:
            marker_map = {}
            markers_list = []
            for field in form["fields"]:
                marker = make_marker()
                payload = craft_payload_for_field(field.get("type", "text"), marker)
                marker_map[field["name"]] = payload
                markers_list.append(marker)

            # Submit form
            submit_status, submit_body = await self.submit_form_with_marker(form, marker_map)
            await self.logger.log("stored_submission", {"form_action": form["action"], "status": submit_status})

            # After submit, discover pages where the content may be rendered
            display_urls = await self.discover_display_locations(entry_url)
            # include entry_url itself and form.action page
            candidates = [entry_url, form["action"]] + display_urls
            checked = set()
            for u in candidates:
                if not u or u in checked:
                    continue
                checked.add(u)
                st2, page_html, _ = await self._get(u)
                if st2 == 0 or not page_html:
                    continue
                findings = await self.analyze_for_marker(u, page_html, markers_list)
                if findings:
                    # augment and persist findings
                    for f in findings:
                        f["origin_form"] = form["action"]
                        f["submitted_markers"] = markers_list
                        await self.logger.log_finding(category="Stored XSS", url=u, evidence=f["marker"], severity=f["severity"], meta=f)
                    all_findings.extend(findings)

        return all_findings
