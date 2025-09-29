"""
Race condition detection module.

Tests whether two or more concurrent requests lead to inconsistent
application state (TOCTOU issues, balance bypass, etc).
"""

import asyncio
import logging
from backend.core.engine import ScanContext

logger = logging.getLogger(__name__)


class RaceConditionTester:
    def __init__(self, context: ScanContext):
        self.context = context

    async def test_race_condition(self, request, parallel=5):
        """
        Sends multiple concurrent requests to the target and
        inspects responses for anomalies.
        """
        tasks = []
        for i in range(parallel):
            logger.info(f"[Race] Spawning request {i+1} → {request.url}")
            tasks.append(self.context.http_client.send(request))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        bodies = [r.text for r in responses if hasattr(r, "text")]
        if len(set(bodies)) > 1:
            return {
                "vulnerable": True,
                "issue": "Possible race condition",
                "sample_responses": [b[:200] for b in bodies]
            }

        return {"vulnerable": False}
