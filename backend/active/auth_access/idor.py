from typing import Dict, List
import requests

class IDORTester:
    """
    Detect Insecure Direct Object References (IDOR).
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.findings: List[Dict] = []

    def test_idor(self, endpoint: str, param: str, values: List[str]):
        for v in values:
            url = f"{self.base_url}{endpoint}?{param}={v}"
            resp = requests.get(url)

            if resp.status_code == 200 and "error" not in resp.text.lower():
                self.findings.append({
                    "type": "IDOR",
                    "endpoint": endpoint,
                    "parameter": param,
                    "value": v,
                    "details": "Object accessed without proper authorization"
                })

    def run(self) -> List[Dict]:
        return self.findings
