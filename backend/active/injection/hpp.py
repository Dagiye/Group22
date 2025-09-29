"""
HPP (HTTP Parameter Pollution) scanner.
- Tests duplicate params, repeated params order, and mixed GET/POST situations.
- Looks for parameter parsing inconsistencies or unexpected behavior.
"""

import asyncio
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

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

TIMEOUT = 10


def _with_multi_params(url: str, key: str, values: List[str]) -> str:
    parsed = urlparse(url)
    q = parse_qsl(parsed.query, keep_blank_values=True)
    # remove existing keys with same name
    q = [kv for kv in q if kv[0] != key]
    q.extend([(key, v) for v in values])
    qs = urlencode(q, doseq=True)
    return urlunparse(parsed._replace(query=qs))


class HPPScanner:
    def __init__(self, session: aiohttp.ClientSession, logger: EvidenceLogger, timeout: int = TIMEOUT):
        self.session = session
        self.logger = logger
        self.timeout = timeout
        self.differ = ResponseDiffer()

    async def _get(self, url: str) -> Tuple[int, str, dict]:
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                txt = await r.text(errors="ignore")
                return r.status, txt, dict(r.headers)
        except Exception as e:
            await self.logger.log("hpp_error", {"url": url, "error": str(e)})
            return 0, "", {}

    async def scan_param(self, url: str, param: str, test_values: Optional[List[str]] = None) -> List[Dict]:
        """
        Create multiple permutations of the same parameter and observe differences:
        - duplicate param with different values
        - same param order reversed
        - mixing POST/GET: send same param in both places
        """
        findings: List[Dict] = []
        test_values = test_values or ["A", "B", "C"]

        # baseline
        base_status, base_body, _ = await self._get(url)

        # 1) duplicate params: ?p=A&p=B
        u_dup = _with_multi_params(url, param, [test_values[0], test_values[1]])
        st_dup, body_dup, _ = await self._get(u_dup)
        if st_dup != 0:
            sim = self.differ.similarity(body_dup, base_body[:4000])
            if sim < 0.8:
                meta = {
                    "type": "hpp_duplicate_params",
                    "url": url,
                    "param": param,
                    "permutation": [test_values[0], test_values[1]],
                    "similarity": sim,
                    "status": st_dup
                }
                await self.logger.log_finding(category="HPP", url=url, evidence="duplicate_param_diff", severity="Medium", meta=meta)
                findings.append(meta)

        # 2) reversed order: ?p=B&p=A
        u_rev = _with_multi_params(url, param, [test_values[1], test_values[0]])
        st_rev, body_rev, _ = await self._get(u_rev)
        if st_rev != 0:
            sim = self.differ.similarity(body_rev, body_dup)
            if sim < 0.8:
                meta = {
                    "type": "hpp_order_dependent",
                    "url": url,
                    "param": param,
                    "permutations": [[test_values[0], test_values[1]], [test_values[1], test_values[0]]],
                    "similarity": sim,
                    "status": st_rev
                }
                await self.logger.log_finding(category="HPP", url=url, evidence="order_dependent", severity="Medium", meta=meta)
                findings.append(meta)

        # 3) GET + POST mix: send param in GET and in POST body with different values
        # build POST data and GET query simultaneously
        parsed = urlparse(url)
        base_q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        get_url = _with_multi_params(url, param, [test_values[0]])
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.post(get_url, data={param: test_values[1]}, timeout=timeout) as r:
                txt = await r.text(errors="ignore")
                sim = self.differ.similarity(txt, base_body[:4000])
                if sim < 0.8:
                    meta = {
                        "type": "hpp_get_post_mismatch",
                        "url": url,
                        "param": param,
                        "get_value": test_values[0],
                        "post_value": test_values[1],
                        "similarity": sim,
                        "status": r.status
                    }
                    await self.logger.log_finding(category="HPP", url=url, evidence="get_post_mismatch", severity="Medium", meta=meta)
                    findings.append(meta)
        except Exception as e:
            await self.logger.log("hpp_post_error", {"url": url, "error": str(e)})

        return findings
