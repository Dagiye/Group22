"""
mutation.py
-----------
Mutation-based XSS detection module.

Rationale:
- Some XSS only appears after JS mutates the DOM (e.g., reading location.hash and then calling .innerHTML,
  or building nodes from untrusted HTML). Static detection may raise many false positives; dynamic
  instrumentation (MutationObserver + API wrappers) provides stronger evidence.

Capabilities:
- Static script scanning for mutation API usage.
- Dynamic instrumentation (Playwright) that:
  * overrides Element.prototype.appendChild, replaceChild, insertAdjacentHTML, innerHTML setter, etc.
  * installs a MutationObserver to capture inserted HTML/text
  * records invocations and payloads into window.__mutation_calls
- Injects a unique marker into a parameter and loads the page; if marker appears in recorded mutation calls,
  it reports a high-confidence finding.
- Conservative by default (no destructive actions). Dynamic tests run only if enabled and driver available.

Integration:
- Requires `drivers.browser.playwright_driver.PlaywrightDriver` wrapper (optional).
- Requires `core.evidence.EvidenceLogger` and `diffing.responses.ResponseDiffer` (optional fallbacks provided).
"""

import re
import uuid
import asyncio
import logging
from typing import List, Dict, Optional

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Heuristics: regexes to detect common mutation APIs in scripts
MUTATION_API_REGEXES = [
    re.compile(r"\.appendChild\s*\(", re.I),
    re.compile(r"\.replaceChild\s*\(", re.I),
    re.compile(r"\.insertAdjacentHTML\s*\(", re.I),
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"\.outerHTML\s*=", re.I),
    re.compile(r"\.cloneNode\s*\(", re.I),
    re.compile(r"createElement\s*\(", re.I),
]

# Playwright driver availability attempt
_playwright_available = False
_playwright_driver = None
try:
    from drivers.browser.playwright_driver import PlaywrightDriver  # type: ignore
    _playwright_available = True
    _playwright_driver = PlaywrightDriver
except Exception:
    _playwright_available = False
    _playwright_driver = None

# Project adapters with safe fallbacks
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
    return "MUT_XSS_" + uuid.uuid4().hex[:10]


class MutationXSSTester:
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
            await self.logger.log("mutation_error", {"stage": "_get", "url": url, "error": str(e)})
            return 0, "", {}

    def _static_script_scan(self, html: str) -> List[Dict]:
        """
        Parse inline scripts and return potential mutation API hits (heuristic).
        """
        findings = []
        if not html:
            return findings
        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script"):
            if script.get("src"):
                # skip external scripts for static analysis (could fetch them later if needed)
                continue
            text = script.string or ""
            if not text.strip():
                continue
            for rx in MUTATION_API_REGEXES:
                if rx.search(text):
                    findings.append({
                        "type": "mutation_api_detected",
                        "snippet": (text.strip()[:800]),
                        "pattern": rx.pattern,
                        "severity": "Medium",
                        "reason": f"Found potential DOM mutation API: {rx.pattern}"
                    })
        # attribute-based heuristics: event handlers that may source user input
        for tag in soup.find_all(True):
            for attr in ("onload", "onerror", "onclick", "onchange"):
                if tag.has_attr(attr):
                    findings.append({
                        "type": "attr_event_handler",
                        "tag": tag.name,
                        "attribute": attr,
                        "snippet": str(tag)[:500],
                        "severity": "Low",
                        "reason": f"Element has event handler {attr}"
                    })
        return findings

    async def _dynamic_instrument(self, url_with_marker: str, timeout: Optional[int] = None) -> List[Dict]:
        """
        Use a Playwright-like driver to:
         - add an init script that wraps DOM mutation APIs and records inserted content
         - navigate to url_with_marker
         - collect window.__mutation_calls (array of {api, content, node, context})
        Returns list of findings (high-confidence if marker seen).
        """
        if not _playwright_available or _playwright_driver is None:
            return []

        injection_script = r"""
(function(){
  if (window.__mutation_instrumented) return;
  window.__mutation_instrumented = true;
  window.__mutation_calls = [];
  function pushCall(api, content, nodeDesc){
    try{ window.__mutation_calls.push({api:api, content:String(content).slice(0,2000), node: nodeDesc}); }catch(e){}
  }

  // override innerHTML setter
  const innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if(innerDesc && innerDesc.set){
    const origSet = innerDesc.set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(v){
        try{ pushCall('innerHTML', v, this.tagName); }catch(e){}
        return origSet.call(this, v);
      },
      get: function(){ return innerDesc.get.call(this); }
    });
  }

  // wrap insertAdjacentHTML
  const origInsert = Element.prototype.insertAdjacentHTML;
  if(origInsert){
    Element.prototype.insertAdjacentHTML = function(position, html){
      try{ pushCall('insertAdjacentHTML', html, this.tagName + '#' + (this.id||'')); }catch(e){}
      return origInsert.call(this, position, html);
    };
  }

  // wrap appendChild / replaceChild / insertBefore
  const origAppend = Element.prototype.appendChild;
  if(origAppend){
    Element.prototype.appendChild = function(node){
      try{ pushCall('appendChild', node && (node.innerHTML || node.textContent || node.nodeValue || node.outerHTML), this.tagName); }catch(e){}
      return origAppend.call(this, node);
    };
  }
  const origReplace = Element.prototype.replaceChild;
  if(origReplace){
    Element.prototype.replaceChild = function(newNode, oldNode){
      try{ pushCall('replaceChild', newNode && (newNode.innerHTML || newNode.textContent || newNode.outerHTML), this.tagName); }catch(e){}
      return origReplace.call(this, newNode, oldNode);
    };
  }
  const origInsertBefore = Element.prototype.insertBefore;
  if(origInsertBefore){
    Element.prototype.insertBefore = function(newNode, refNode){
      try{ pushCall('insertBefore', newNode && (newNode.innerHTML || newNode.textContent || newNode.outerHTML), this.tagName); }catch(e){}
      return origInsertBefore.call(this, newNode, refNode);
    };
  }

  // MutationObserver to catch textContent changes and subtree insertions
  try{
    const mo = new MutationObserver(function(mutations){
      for(const m of mutations){
        try{
          if(m.addedNodes && m.addedNodes.length){
            m.addedNodes.forEach(function(n){
              try{ pushCall('mutation_added', n && (n.innerHTML || n.textContent || n.nodeValue), n && (n.tagName || '#text')); }catch(e){}
            });
          }
          if(m.type === 'characterData'){
            try{ pushCall('mutation_char', m.target && m.target.data, m.target && (m.target.parentNode && m.target.parentNode.tagName)); }catch(e){}
          }
        }catch(e){}
      }
    });
    mo.observe(document, { childList: true, subtree: true, characterData: true });
  }catch(e){}
})();
        """

        findings = []
        try:
            driver = _playwright_driver()
            await driver.start()
            page = await driver.new_page()
            # add init script BEFORE any scripts run
            await page.add_init_script(injection_script)
            await page.goto(url_with_marker, timeout=(timeout or self.browser_timeout) * 1000)
            # wait small time to allow SPA scripts to run
            await asyncio.sleep(1.0)
            calls = await page.evaluate("() => window.__mutation_calls || []")
            # Stop page & driver
            await page.close()
            await driver.stop()
            # analyze calls
            for c in calls:
                api = c.get("api")
                content = c.get("content") or ""
                node = c.get("node") or ""
                findings.append({
                    "api": api,
                    "content_snippet": content[:1000],
                    "node": node,
                    "evidence": content[:1000],
                    "severity": "High" if 'MUT_XSS_' in content else "Medium"
                })
        except Exception as e:
            await self.logger.log("mutation_dynamic_error", {"url": url_with_marker, "error": str(e)})
            # return what we have (or empty)
        return findings

    async def scan(self, url: str, param_to_inject: Optional[str] = None, enable_dynamic: bool = True) -> List[Dict]:
        """
        High-level scan:
        - fetch page
        - static scan (script inspection)
        - if param_to_inject supplied and dynamic enabled: inject unique marker into param and run instrumentation
        - return aggregated findings
        """
        results = []
        status, html, headers = await self._get(url)
        if status == 0 or not html:
            return results

        # static check
        static_findings = self._static_script_scan(html)
        for sf in static_findings:
            meta = {
                "type": sf.get("type"),
                "reason": sf.get("reason"),
                "pattern": sf.get("pattern", None),
                "snippet": sf.get("snippet", "")[:800],
                "severity": sf.get("severity", "Low"),
                "url": url,
                "remediation": "Avoid constructing DOM from untrusted input; use textContent, sanitize libraries, and CSP."
            }
            await self.logger.log_finding(category="Mutation XSS (static)", url=url, evidence=meta["reason"], severity=meta["severity"], meta=meta)
            results.append(meta)

        # dynamic confirmation if requested
        if enable_dynamic and param_to_inject and _playwright_available:
            marker = _unique_marker()
            # craft URL with marker in param (preserve existing query)
            from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            q[param_to_inject] = marker
            new_query = urlencode(q, doseq=True)
            url_with_marker = urlunparse(parsed._replace(query=new_query))

            dyn_findings = await self._dynamic_instrument(url_with_marker)
            for d in dyn_findings:
                severity = d.get("severity", "Medium")
                evidence = d.get("content_snippet", "")[:1000]
                meta = {
                    "type": "Mutation XSS (dynamic)",
                    "api": d.get("api"),
                    "node": d.get("node"),
                    "evidence": evidence,
                    "url": url_with_marker,
                    "severity": severity,
                    "remediation": "Sanitize before inserting into DOM APIs; use safe DOM methods and CSP."
                }
                await self.logger.log_finding(category="Mutation XSS (dynamic)", url=url_with_marker, evidence=evidence, severity=severity, meta=meta)
                results.append(meta)

        return results
