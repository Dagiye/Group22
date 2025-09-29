"""
priv_esc.py
-----------
Privilege escalation checks:
- horizontal privilege escalation (accessing peers' data)
- vertical privilege escalation (accessing admin features)
- role tampering via cookies / tokens
"""

import requests
from typing import Dict, List, Optional


class PrivilegeEscalationTester:
    def __init__(self, base_url: str, session: Optional[requests.Session] = None, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings: List[Dict] = []

    def _get(self, path: str, cookies: Dict[str, str] = None, headers: Dict[str, str] = None):
        try:
            return self.session.get(
                f"{self.base_url}{path}",
                cookies=cookies,
                headers=headers,
                timeout=self.timeout
            )
        except requests.RequestException as e:
            return {"error": str(e)}

    def horizontal_escalation(self, target_path: str, low_priv_cookies: Dict[str, str], id_param: str, test_ids: List[str]):
        """
        With a low-privilege session (low_priv_cookies), try to access other users' resources by changing an ID param.
        """
        for tid in test_ids:
            params = {id_param: tid}
            try:
                resp = self.session.get(f"{self.base_url}{target_path}", params=params, cookies=low_priv_cookies, timeout=self.timeout)
                text = resp.text.lower() if isinstance(resp, requests.Response) else ""
                # Heuristic: successful access (200) and presence of identifiable user data not belonging to low-priv user
                if isinstance(resp, requests.Response) and resp.status_code == 200 and "forbidden" not in text and "unauthorized" not in text:
                    self.findings.append({
                        "type": "horizontal_privilege_escalation",
                        "endpoint": target_path,
                        "tested_id": tid,
                        "status_code": resp.status_code,
                        "evidence": resp.text[:600]
                    })
            except requests.RequestException:
                continue

    def vertical_escalation_via_role_tamper(self, target_path: str, cookie_name: str, low_role_cookies: Dict[str, str], tampered_values: List[str]):
        """
        Try tampering role-identifying cookie/token values to elevate privileges.
        E.g., change role=user -> role=admin or change a user_id to 1
        """
        for tv in tampered_values:
            cookies = low_role_cookies.copy()
            cookies[cookie_name] = tv
            try:
                resp = self.session.get(f"{self.base_url}{target_path}", cookies=cookies, timeout=self.timeout)
                text = resp.text.lower() if isinstance(resp, requests.Response) else ""
                if isinstance(resp, requests.Response) and resp.status_code == 200 and ("admin" in text or "manage" in text or "dashboard" in text):
                    self.findings.append({
                        "type": "vertical_privilege_escalation",
                        "endpoint": target_path,
                        "tampered_cookie": cookie_name,
                        "tampered_value": tv,
                        "status_code": resp.status_code,
                        "evidence": resp.text[:600]
                    })
            except requests.RequestException:
                continue

    def jwt_role_bypass(self, verify_endpoint: str, jwt_token: str, manipulated_tokens: List[str], header_name: str = "Authorization"):
        """
        Try sending manipulated JWTs (e.g., alg=none, header changes, payload changes) to a verification endpoint.
        manipulated_tokens are full token strings prepared by caller.
        """
        for token in manipulated_tokens:
            headers = {header_name: f"Bearer {token}"}
            try:
                resp = self.session.get(f"{self.base_url}{verify_endpoint}", headers=headers, timeout=self.timeout)
                if isinstance(resp, requests.Response) and resp.status_code == 200 and "admin" in resp.text.lower():
                    self.findings.append({
                        "type": "jwt_role_bypass",
                        "endpoint": verify_endpoint,
                        "token_sample": token[:80] + "..." if isinstance(token, str) else token,
                        "status_code": resp.status_code,
                        "evidence": resp.text[:600]
                    })
            except requests.RequestException:
                continue

    def run(self) -> List[Dict]:
        """
        Return collected findings. Methods are intentionally independent so scan controller calls the ones needed.
        """
        return self.findings
