"""
dom.py
------
DOM-based XSS detection module.

Approach:
- Static heuristics: parse HTML, collect inline scripts and attributes; look for direct references
  to location/hash/document.* usage and common sinks (innerHTML, document.write, eval, setTimeout with string, insertAdjacentHTML).
- Dynamic confirmation (optional): if Playwright driver is available in your drivers/browser,
  load the page, instrument window functions, and inject a safe, unique marker to see if it reaches sinks.
- Returns structured findings and logs via EvidenceLogger.

Notes:
- Dynamic instrumentation requires a Playwright-capable environment and the `playwright_driver` in drivers.
- This module is conservative by default and avoids destructive actions.
"""

import re
import asyncio
import logging
import uuid
from typing import List, Dict, Optional

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Heuristics regex
SINK_REGEXES = [
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"document\.writeln\s*\(", re.I),
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"setTimeout\s*\(\s*['\"]", re.I),
    re.compile(r"setInterval\s*\(\s*['\"]", re.I),
    re.compile(r"insertAdjacentHTML\s*\(", re.I),
    re.compile(r"outerHTML\s*=", re.I),
    re.compile(r"location\.hash", re.I),
    re.compile(r"location\.search", re.I),
    re.compile(r"document\.location", re.I),
]

ATTR_SINKS = [
    # attributes where unescaped user input can execute JS
    "onerror", "onload", "onclick", "onmouseover", "onfocus", "onmouseenter"
]

# fallback stubs if project modules aren't present
try:
    from backend.core.evidence import EvidenceLogger
except Exception:  # pragma: no cover
    class EvidenceLogger:
        async def log(self, *args, **kwargs):
            pass
        async def log_finding(self, *args, **kwargs):
            pass

try:
    from diffing.responses import ResponseDiffer
except Exception:  # pragma: no cover
    class ResponseDiffer:
        def similarity(self, a: str, b: str) -> float:
            return 1.0 if a == b else 0.0

# Try to import your project's playwright driver if available
_playwright_available = False
_playwright_driver = None
try:
    from drivers.browser.playwright_driver import PlaywrightDriver  # type: ignore
    _playwright_available = True
    _playwright_driver = PlaywrightDriver
except Exception:
    _playwright_available = False
    _playwright_driver = None


def _unique_marker() -> str:
    return f"DOM_XSS_{uuid.uuid4().hex[:10]}"


class DOMXSSTester:
    def __init__(self, session: aiohttp.ClientSession, logger: EvidenceLogger, differ: Optional[ResponseDiffer] = None, browser_timeout: int = 12):
        self.session = session
        self.logger = logger
        self.differ = differ or ResponseDiffer()
        self.browser_timeout = browser_timeout

    async def _get(self, url: str) -> (int, str, dict):
        try:
            async with self.session.get(url, timeout=self.browser_timeout) as r:
                text = await r.text(errors="ignore")
                return r.status, text, dict(r.headers)
        except Exception as e:
            await self.logger.log("dom_xss_error", {"stage": "_get", "url": url, "error": str(e)})
            return 0, "", {}

    def _static_script_analysis(self, html: str) -> List[Dict]:
        """
        Parse inline scripts and find suspicious sinks and sources.
        Returns list of potential issues with snippet and reason.
        """
        findings = []
        if not html:
            return findings

        soup = BeautifulSoup(html, "html.parser")

        # 1) attributes with event handlers (possible sink if user input reflected into them)
        for tag in soup.find_all(True):
            for attr in ATTR_SINKS:
                if tag.has_attr(attr):
                    val = tag.get(attr, "")
                    if val and len(val) > 0:
                        findings.append({
                            "type": "dom_attr_sink",
                            "tag": tag.name,
                            "attribute": attr,
                            "snippet": str(tag)[:800],
                            "reason": f"Element has {attr} attribute",
                            "severity": "Medium"
                        })

        # 2) inline script analysis
        for script in soup.find_all("script"):
            # ignore scripts with src (external), focus on inline
            if script.get("src"):
                continue
            script_text = script.string or ""
            if not script_text.strip():
                continue
            for regex in SINK_REGEXES:
                if regex.search(script_text):
                    findings.append({
                        "type": "dom_script_sink",
                        "snippet": script_text.strip()[:800],
                        "reason": f"Matched sink regex: {regex.pattern}",
                        "severity": "High" if "innerHTML" in regex.pattern or "document.write" in regex.pattern or "eval" in regex.pattern else "Medium"
                    })
                    # we continue scanning; multiple sinks possible
        return findings

    async def _dynamic_instrumentation(self, url: str, param_injections: Optional[List[Dict]] = None, timeout: Optional[int] = None) -> List[Dict]:
        """
        Optional dynamic confirmation using Playwright driver:
        - Launches a headless browser page
        - Installs JS hooks to record calls to sinks (overrides innerHTML, document.write, eval, setTimeout, etc.)
        - Navigates to page with injected markers (param_injections like [{"param":"q","value":"MARKER"}])
        - Returns findings where sink functions were invoked with markers.

        param_injections is optional. If not provided, we just open the page as-is and listen.
        """
        if not _playwright_available or _playwright_driver is None:
            return []

        findings = []
        marker = _unique_marker()

        # craft url with injections if provided
        injected_url = url
        if param_injections:
            from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            for inj in param_injections:
                q[inj.get("param")] = inj.get("value", marker)
            new_q = urlencode(q, doseq=True)
            injected_url = urlunparse(parsed._replace(query=new_q))

        # Use your project's PlaywrightDriver wrapper if exists
        try:
            # instantiate driver (assumes driver implements async context manager or similar interface)
            driver = _playwright_driver()
            await driver.start()  # start browser runtime
            page = await driver.new_page()
            # instrumentation script: override sinks and record calls to window.__xss_calls__
            sink_hook = """
                (function(){
                    if(window.__xss_hooks_installed) return;
                    window.__xss_hooks_installed = true;
                    window.__xss_calls = [];
                    const pushCall = (type, value) => window.__xss_calls.push({type, value: String(value).slice(0,800)});
                    const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                    if(origInnerHTML && origInnerHTML.set){
                      const origSet = origInnerHTML.set;
                      Object.defineProperty(Element.prototype, 'innerHTML', {
                        set: function(v){
                          try { pushCall('innerHTML', v); } catch(e){}
                          return origSet.call(this, v);
                        },
                        get: function(){ return origSet.call(this); }
                      });
                    }
                    const origWrite = document.write;
                    document.write = function(){ try{ pushCall('document.write', Array.from(arguments).join(' ')); }catch(e){}; return origWrite.apply(this, arguments); };
                    const origEval = window.eval;
                    window.eval = function(v){ try{ pushCall('eval', v); }catch(e){}; return origEval.apply(this, arguments); };
                    const origSetTimeout = window.setTimeout;
                    window.setTimeout = function(fn, t){ try{ pushCall('setTimeout', String(fn).slice(0,800)); }catch(e){}; return origSetTimeout.apply(this, arguments); };
                    const origInsert = Element.prototype.insertAdjacentHTML;
                    if(origInsert){
                       Element.prototype.insertAdjacentHTML = function(pos, html){
                          try{ pushCall('insertAdjacentHTML', html); }catch(e){}; return origInsert.call(this, pos, html);
                       };
                    }
                })();
            """
            await page.add_init_script(sink_hook)
            # navigate
            await page.goto(injected_url, timeout=(timeout or self.browser_timeout) * 1000)
            # wait briefly for async scripts
            await asyncio.sleep(1)
            # retrieve recorded calls
            calls = await page.evaluate("() => window.__xss_calls || []")
            if calls:
                for c in calls:
                    val = c.get("value", "")
                    # if marker present or just sink usage, record
                    findings.append({
                        "type": "dom_dynamic_sink",
                        "sink": c.get("type"),
                        "value_snippet": val[:800],
                        "url": injected_url,
                        "severity": "High" if marker in val else "Medium",
                        "evidence": val[:800]
                    })
            # cleanup
            await page.close()
            await driver.stop()
        except Exception as e:
            await self.logger.log("dom_dynamic_error", {"url": url, "error": str(e)})
            # best-effort: return whatever findings we had
        return findings

    async def scan(self, url: str, enable_dynamic: bool = False, injection_points: Optional[List[Dict]] = None) -> List[Dict]:
        """
        High-level entry:
        - fetch page
        - run static analysis for DOM sinks and attributes
        - if enable_dynamic and playwright available => run dynamic instrumentation
        """
        results = []
        status, html, headers = await self._get(url)
        if status == 0 or not html:
            return results

        # static analysis
        static_findings = self._static_script_analysis(html)
        for f in static_findings:
            # persist findings
            f_meta = {
                "type": f.get("type"),
                "reason": f.get("reason"),
                "snippet": f.get("snippet"),
                "severity": f.get("severity"),
                "url": url,
                "remediation": "Avoid writing untrusted data into DOM APIs; properly sanitize/encode by context."
            }
            await self.logger.log_finding(category="DOM XSS (static)", url=url, evidence=f_meta["reason"], severity=f_meta["severity"], meta=f_meta)
            results.append(f_meta)

        # attribute sinks heuristics already included; we can also check for reflected user input markers
        # (if your pipeline supplies markers, you can check for them here; omitted for general scanner)

        # optional dynamic confirmation
        if enable_dynamic:
            dyn = await self._dynamic_instrumentation(url, param_injections=injection_points)
            for d in dyn:
                d_meta = {
                    "type": d.get("type"),
                    "sink": d.get("sink"),
                    "evidence": d.get("evidence"),
                    "value_snippet": d.get("value_snippet"),
                    "severity": d.get("severity"),
                    "url": url,
                    "remediation": "Use safe DOM APIs (textContent, setAttribute with proper escaping) and CSP."
                }
                await self.logger.log_finding(category="DOM XSS (dynamic)", url=url, evidence=d_meta["evidence"], severity=d_meta["severity"], meta=d_meta)
                results.append(d_meta)

        return results
