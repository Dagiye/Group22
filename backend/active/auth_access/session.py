"""
session.py
----------
Session-related checks:
- session fixation
- session timeout & expiry checks
- session reuse detection
"""

import requests
import time
from typing import Dict, List, Optional

class SessionTester:
    def __init__(self, base_url: str, session_cookie_name: str = "sessionid", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.session_cookie_name = session_cookie_name
        self.timeout = timeout
        self.findings: List[Dict] = []

    def session_fixation(self, login_endpoint: str, username: str, password: str, attacker_set_value: str):
        """
        Attempt session fixation:
        1) Set cookie to attacker-controlled value
        2) Perform login
        3) Check if server accepts the same cookie after authentication
        """
        s = requests.Session()
        # domain for cookies might be required; using base host as domain is helpful
        host = self.base_url.split("://")[-1].split("/")[0]
        s.cookies.set(self.session_cookie_name, attacker_set_value, domain=host)
        try:
            resp = s.post(f"{self.base_url}{login_endpoint}", data={"username": username, "password": password}, timeout=self.timeout)
            # After login, check if cookie remains and equals attacker value
            current = s.cookies.get(self.session_cookie_name)
            if current == attacker_set_value:
                self.findings.append({
                    "type": "session_fixation",
                    "endpoint": login_endpoint,
                    "attacker_cookie": attacker_set_value,
                    "status_code": resp.status_code,
                    "evidence": f"Server kept attacker-controlled session id: {current}"
                })
        except requests.RequestException as e:
            self.findings.append({"error": str(e)})

    def session_timeout_check(self, protected_endpoint: str, login_flow_callable, wait_seconds: int = 3600):
        """
        Verify session expiry behavior:
        - login_flow_callable() should return a requests.Session() authenticated
        - access protected endpoint immediately -> should succeed
        - wait wait_seconds -> access again -> should be unauthorized or redirected to login
        """
        s = login_flow_callable()
        if not isinstance(s, requests.Session):
            raise ValueError("login_flow_callable must return a requests.Session()")

        try:
            initial = s.get(f"{self.base_url}{protected_endpoint}", timeout=self.timeout)
            time.sleep(0.1)  # small pause to avoid race in slow environments
            later = None
            # We don't actually wait long in automated tests; caller configures wait_seconds
            time.sleep(wait_seconds)
            later = s.get(f"{self.base_url}{protected_endpoint}", timeout=self.timeout)
            # If both initial and later are 200, session might not expire properly
            if isinstance(initial, requests.Response) and isinstance(later, requests.Response) and initial.status_code == 200 and later.status_code == 200:
                self.findings.append({
                    "type": "session_timeout_issue",
                    "endpoint": protected_endpoint,
                    "initial_status": initial.status_code,
                    "later_status": later.status_code,
                    "details": f"Session persisted beyond expected timeframe ({wait_seconds}s)"
                })
        except requests.RequestException as e:
            self.findings.append({"error": str(e)})

    def session_reuse_detection(self, login_flow_callable, reuse_session_callable):
        """
        Detects session token reuse vulnerability:
        - login_flow_callable() returns a Session (owner A)
        - reuse_session_callable(session_token) simulates reuse by attacker using the token
        If reuse_session_callable can access protected endpoints using session token, it's a finding.
        """
        s = login_flow_callable()
        if not isinstance(s, requests.Session):
            raise ValueError("login_flow_callable must return a requests.Session()")

        token = s.cookies.get(self.session_cookie_name)
        if not token:
            self.findings.append({"type": "no_session_token", "details": "No session cookie found after login"})
            return

        # reuse_session_callable should attempt to use the token (e.g., set cookie) and call a protected endpoint
        try:
            success = reuse_session_callable(token)
            if success:
                self.findings.append({
                    "type": "session_reuse",
                    "token_sample": token[:40] + "...",
                    "details": "Session token was reusable from a different client"
                })
        except Exception as e:
            self.findings.append({"error": str(e)})

    def run(self) -> List[Dict]:
        return self.findings
