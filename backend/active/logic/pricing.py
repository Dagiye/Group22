"""
Pricing logic manipulation tester.

Detects vulnerabilities in price calculations (e.g., negative quantity,
manipulating client-side price parameters, bypassing coupon restrictions).
"""

import logging
from backend.core.engine import ScanContext

logger = logging.getLogger(__name__)


class PricingTester:
    def __init__(self, context: ScanContext):
        self.context = context

    async def test_price_tampering(self, request):
        """
        Try modifying product pricing fields (JSON, form params, query string).
        """
        tampered_variants = [
            {"quantity": "999999"},
            {"price": "0"},
            {"discount": "100"},
            {"coupon": "' OR 1=1 --"}
        ]

        findings = []

        for tamper in tampered_variants:
            logger.info(f"[Pricing] Testing tamper params {tamper}")
            modified = request.copy()
            modified.params.update(tamper)

            response = await self.context.http_client.send(modified)
            if "free" in response.text.lower() or "0.00" in response.text:
                findings.append({
                    "tamper": tamper,
                    "issue": "Price manipulation successful",
                    "evidence": response.text[:200]
                })

        return findings if findings else {"vulnerable": False}
