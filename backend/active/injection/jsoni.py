"""
JSON Injection scanner (JSONi).
- Tests injection into JSON fields (e.g., when backend deserializes JSON into queries or objects).
- Looks for echoed operator strings, schema changes, or diffs.
- Supports JSON body POST testing and attempts common payloads for prototype/field poisoning.
"""

import json
import asyncio
from typing import List, Dict, Optional
import aiohttp

try:
    from backend.core.evidence import EvidenceLogger
except Exception:
    class EvidenceLogger:
        async def log(self,*args,**kwargs): pass
        async def log_finding(self,*args,**kwargs): pass

try:
    from diffing.responses import ResponseDiffer
except Exception:
    class ResponseDiffer:
        def similarity(self,a,b): return 1.0 if a==b else 0.0

TIMEOUT = 12

# JSON-specific payloads for injection / prototype pollution / operator leakage
JSON_PAYLOADS = [
    # Prototype pollution style objects
    {"__proto__": {"polluted": "1"}},
    {"constructor": {"prototype": {"polluted": "1"}}},
    # Mongo operator injection (if server uses JSON to build Mongo queries)
    {"username": {"$ne": None}},
    {"age": {"$gt": ""}},
    # regular injection: reflect raw JSON special tokens
    {"search": "' OR '1'='1"},
    {"filter": {"$where": "this.value != null"}},
]


class JSONInjectionScanner:
    def __init__(self, session: aiohttp.ClientSession, logger: EvidenceLogger, aggressive: bool = False, timeout: int = TIMEOUT):
        self.session = session
        self.logger = logger
        self.aggressive = aggressive
        self.timeout = timeout
        self.differ = ResponseDiffer()

    async def _post_json(self, url: str, payload: Dict) -> (int, str, dict):
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.post(url, json=payload, timeout=timeout) as r:
                text = await r.text(errors="ignore")
                return r.status, text, dict(r.headers)
        except Exception as e:
            await self.logger.log("jsoni_error", {"url": url, "error": str(e)})
            return 0, "", {}

    async def scan_json_field(self, url: str, base_json: Dict, target_fields: Optional[List[str]] = None) -> List[Dict]:
        """
        Iterate JSON payload variants and insert injection payloads into target fields (or all) and post.
        """
        findings: List[Dict] = []
        target_fields = target_fields or list(base_json.keys())

        # baseline
        st_b, body_b, _ = await self._post_json(url, base_json)

        for field in target_fields:
            for p in JSON_PAYLOADS:
                # create variant copy and set the field to the payload
                payload_variant = json.loads(json.dumps(base_json))  # deep copy
                payload_variant[field] = p

                st, body, headers = await self._post_json(url, payload_variant)
                if st == 0:
                    continue

                # 1) check for echoed operator or key strings
                text_lower = (body or "").lower()
                marker_candidates = []
                # Check for prototype pollution reflection
                if '"polluted"' in text_lower or "polluted" in text_lower:
                    marker_candidates.append("prototype_polluted_reflection")

                # Check for mongo operator leakage
                if "$ne" in text_lower or "$where" in text_lower or "$gt" in text_lower:
                    marker_candidates.append("nosql_operator_leak")

                # 2) diffing heuristic
                sim = self.differ.similarity(body, body_b[:4000] if body_b else "")
                if marker_candidates or sim < 0.75:
                    meta = {
                        "type": "json_injection",
                        "url": url,
                        "field": field,
                        "payload": p,
                        "markers": marker_candidates,
                        "similarity": sim,
                        "status": st,
                        "response_snippet": body[:800],
                    }
                    severity = "High" if marker_candidates else "Medium"
                    await self.logger.log_finding(category="JSONi", url=url, evidence="json_injection_evidence", severity=severity, meta=meta)
                    findings.append(meta)
                    # conservative: stop on first finding for this field
                    break

        return findings
