# backend/active/auth/csrf.py
from typing import Optional
from active.base import ActiveCheck
from backend.core.engine import HTTPRequest, HTTPResponse
from backend.core.evidence import Evidence


class CSRFCheck(ActiveCheck):
    name = "csrf-check"
    description = "Detects missing or ineffective CSRF protections in forms."
    severity = "high"
    categories = ["auth", "csrf"]

    async def run(self, request: HTTPRequest, response: HTTPResponse) -> None:
        """
        Look for HTML forms missing anti-CSRF tokens or replay the request
        without tokens to test if it's still accepted.
        """
        if "form" not in response.content.lower():
            return  # No forms → no CSRF test needed

        # Example heuristic: look for CSRF token fields
        if "csrf" not in response.content.lower():
            self.record_finding(
                title="Missing CSRF Token",
                description="Form detected without any anti-CSRF token.",
                severity=self.severity,
                request=request,
                response=response,
                evidence=Evidence(content=response.content, content_type="html"),
            )
            return

        # TODO: implement replay test (send modified request without token)
        # For now just placeholder logic:
        stripped_request = request.clone()
        stripped_request.remove_param("csrf_token")

        # simulate sending stripped request via context engine
        replay_response: Optional[HTTPResponse] = await self.context.engine.send(stripped_request)

        if replay_response and replay_response.status_code in (200, 302):
            self.record_finding(
                title="Bypassable CSRF Protection",
                description="CSRF token removed but request was still accepted.",
                severity="critical",
                request=stripped_request,
                response=replay_response,
            )
