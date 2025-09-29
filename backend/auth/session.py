# backend/active/auth/session.py
from active.base import ActiveCheck
from backend.core.engine import HTTPRequest, HTTPResponse
from backend.core.evidence import Evidence


class SessionCheck(ActiveCheck):
    name = "session-check"
    description = "Detects insecure session management practices."
    severity = "high"
    categories = ["auth", "session"]

    async def run(self, request: HTTPRequest, response: HTTPResponse) -> None:
        """
        Analyze session cookies and headers for security flags.
        """
        cookies = response.cookies
        if not cookies:
            return

        for name, cookie in cookies.items():
            issues = []
            if not cookie.get("secure"):
                issues.append("Missing Secure flag")
            if not cookie.get("httponly"):
                issues.append("Missing HttpOnly flag")
            if "samesite" not in cookie:
                issues.append("Missing SameSite flag")

            if issues:
                self.record_finding(
                    title=f"Insecure Session Cookie: {name}",
                    description="; ".join(issues),
                    severity=self.severity,
                    request=request,
                    response=response,
                    evidence=Evidence(content=str(cookie), content_type="json"),
                )
