import requests

class CORSTester:
    """
    Detects unsafe CORS configurations by sending requests with
    arbitrary Origin headers and checking server responses.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.payloads = [
            "http://evil.com",
            "http://attacker.local",
            "null",
        ]

    def test_payloads(self):
        results = []
        for origin in self.payloads:
            try:
                headers = {"Origin": origin}
                response = requests.get(self.target_url, headers=headers, timeout=self.timeout)
                cors_header = response.headers.get("Access-Control-Allow-Origin", "")
                results.append({
                    "origin": origin,
                    "status": response.status_code,
                    "allow_origin": cors_header,
                    "content_snippet": response.text[:200]
                })
            except requests.exceptions.RequestException as e:
                results.append({"origin": origin, "error": str(e)})
        return results

    def is_vulnerable(self, allow_origin_header: str) -> bool:
        # Vulnerable if server reflects arbitrary origins
        return allow_origin_header in self.payloads or allow_origin_header == "*"
