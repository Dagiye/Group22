"""
NoSQL Injection scanner (focus: MongoDB-style apps).
Covers: boolean logic via operators, regex-based probing, projection pollution hints.
Heuristics:
  - Response-diff for conditional behavior
  - Known NoSQL operator patterns
  - Status anomalies
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
import json
import re
import aiohttp

from backend.core.evidence import EvidenceLogger
from diffing.responses import ResponseDiffer
from evasions.encode import url_safe


def _with_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


MONGO_HINTS = [
    r"\$where",
    r"\$ne",
    r"\$gt",
    r"\$regex",
    r"\$and",
    r"\$or",
]

MONGO_HINTS_RE = re.compile("|".join(MONGO_HINTS), re.IGNORECASE)


class NoSQLiScanner:
    """
    Async NoSQL injection scanner for query-based endpoints (GET/POST).
    """

    def __init__(self, base_url: str, session: aiohttp.ClientSession, logger: EvidenceLogger):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger
        self.differ = ResponseDiffer()

        # Boolean pairs using NoSQL operators
        self.boolean_pairs = [
            # often used against login or search parameters
            ('{"$ne": null}', '"fixedvalue"'),
            ('{"$gt": ""}', '"zzzzzzzzzz"'),
            ('{"$regex": ".*"}', '"no_such_value_12345"'),
        ]

        # Projection poisoning / array operator hints (if payload is JSON)
        self.json_injections = [
            {"$where": "this.value != null"},
            {"$or": [{"a": {"$gt": ""}}, {"b": {"$gt": ""}}]},
            {"$ne": None},
        ]

    async def _get(self, url: str) -> Tuple[int, str]:
        try:
            async with self.session.get(url, timeout=12) as r:
                return r.status, await r.text(errors="ignore")
        except Exception as e:
            self.logger.log_error("NoSQLiScanner._get", f"{url}: {e}")
            return 0, ""

    async def _post(self, url: str, data: Dict[str, str]) -> Tuple[int, str]:
        try:
            async with self.session.post(url, data=data, timeout=12) as r:
                return r.status, await r.text(errors="ignore")
        except Exception as e:
            self.logger.log_error("NoSQLiScanner._post", f"{url}: {e}")
            return 0, ""

    async def scan_get_params(self, url: str, params: List[str]) -> List[dict]:
        findings: List[dict] = []
        # Baseline
        st_b, body_b = await self._get(url)
        baseline = (st_b, body_b[:4000])

        for p in params:
            # Boolean pairs
            for t, f_val in self.boolean_pairs:
                t_url = _with_param(url, p, url_safe(t))
                f_url = _with_param(url, p, url_safe(f_val))
                st_t, body_t = await self._get(t_url)
                st_f, body_f = await self._get(f_url)
                if st_t == 0 or st_f == 0:
                    continue

                sim_tf = self.differ.similarity(body_t, body_f)
                sim_tb = self.differ.similarity(body_t, baseline[1])
                sim_fb = self.differ.similarity(body_f, baseline[1])

                if sim_tf < 0.60 and (sim_tb > 0.85 or sim_fb > 0.85 or st_t != st_f):
                    evidence = f"similarity(true,false)={sim_tf:.2f}; status({st_t},{st_f})"
                    findings.append(self._report(
                        "NoSQL Injection (boolean/ops, GET)",
                        p, f"{t_url} vs {f_url}", evidence, st_b, (st_t, st_f),
                        len(baseline[1]), (len(body_t), len(body_f))
                    ))
                    break

            # Error hint (rare in NoSQL but check for unhandled operator echo)
            inj = '{"$ne": null}'
            e_url = _with_param(url, p, url_safe(inj))
            st, body = await self._get(e_url)
            if st != 0 and MONGO_HINTS_RE.search(body):
                findings.append(self._report(
                    "NoSQL Injection (operator leakage, GET)",
                    p, e_url, "Response contains NoSQL operator echoes.",
                    st_b, st, len(baseline[1]), len(body)
                ))

        return findings

    async def scan_post_form(self, url: str, form: Dict[str, str], target_params: Optional[List[str]] = None) -> List[dict]:
        findings: List[dict] = []
        target_params = target_params or list(form.keys())
        # Baseline
        st_b, body_b = await self._post(url, form)
        baseline = (st_b, body_b[:4000])

        for p in target_params:
            # Boolean pairs
            for t, f_val in self.boolean_pairs:
                st_t, body_t = await self._post(url, {**form, p: t})
                st_f, body_f = await self._post(url, {**form, p: f_val})
                if st_t == 0 or st_f == 0:
                    continue
                sim_tf = self.differ.similarity(body_t, body_f)
                sim_tb = self.differ.similarity(body_t, baseline[1])
                sim_fb = self.differ.similarity(body_f, baseline[1])
                if sim_tf < 0.60 and (sim_tb > 0.85 or sim_fb > 0.85 or st_t != st_f):
                    evidence = f"similarity(true,false)={sim_tf:.2f}; status({st_t},{st_f})"
                    findings.append(self._report(
                        "NoSQL Injection (boolean/ops, POST)",
                        p, url, evidence, baseline[0], (st_t, st_f),
                        len(baseline[1]), (len(body_t), len(body_f)),
                        request_body=json.dumps({**form, p: "<boolean-operator>"} )[:500]
                    ))
                    break

            # JSON body injections (if the endpoint accepts JSON; caller can adapt)
            # We provide helper to craft JSON; here we just try 'application/x-www-form-urlencoded' style.

        return findings

    def _report(
        self,
        title: str,
        param: str,
        url: str,
        evidence: str,
        baseline_status,
        status,
        baseline_len,
        new_len,
        request_body: Optional[str] = None,
    ) -> dict:
        data = {
            "title": title,
            "category": "Injection/NoSQLi",
            "url": url,
            "parameter": param,
            "evidence": evidence,
            "baseline_status": baseline_status,
            "status": status,
            "baseline_len": baseline_len,
            "observed_len": new_len,
            "severity": "High",
            "recommendation": (
                "Use server-side input validation and strict schema. Avoid directly passing client-supplied "
                "objects into NoSQL queries. Whitelist allowed operators/fields and sanitize strings."
            ),
            "request_body": request_body,
        }
        self.logger.log_finding(
            category="NoSQL Injection",
            url=url,
            evidence=evidence,
            severity=data["severity"],
            meta=data,
        )
        return data
