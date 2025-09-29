"""
Replay attack detection module.

This module attempts to detect whether an application is vulnerable
to replaying previously valid authenticated requests.
"""

import time
import logging
from backend.core.engine import ScanContext

logger = logging.getLogger(__name__)


class ReplayAttackTester:
    def __init__(self, context: ScanContext):
        self.context = context

    async def test_replay(self, request):
        """
        Try replaying the same authenticated request multiple times.
        Detect anomalies such as multiple identical transactions
        (e.g., double charges, duplicate transfers).
        """
        results = []

        for i in range(2):
            logger.info(f"[Replay] Sending attempt {i+1} for {request.url}")
            response = await self.context.http_client.send(request)
            results.append(response)

            time.sleep(1)  # small delay between replays

        # Heuristic: identical status & body → suspicious
        if len(set(r.status_code for r in results)) == 1 and \
           len(set(r.text for r in results)) == 1:
            return {
                "vulnerable": True,
                "issue": "Replay attack possible",
                "evidence": results[0].text[:200]
            }

        return {"vulnerable": False}
