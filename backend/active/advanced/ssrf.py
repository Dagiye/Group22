import requests
from urllib.parse import urlparse

class SSRFScanner:
    """
    Detects SSRF vulnerabilities by sending crafted requests
    and analyzing responses for internal resource exposure.
    Works for any backend tech stack.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata
        ]

    def test_payload(self, endpoint: str):
        results = []
        for payload in self.payloads:
            try:
                full_url = f"{endpoint}?url={payload}"
                response = requests.get(full_url, timeout=self.timeout)
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "content_snippet": response.text[:200]
                })
            except requests.exceptions.RequestException as e:
                results.append({"payload": payload, "error": str(e)})
        return results

    def is_ssrf(self, response_snippet: str) -> bool:
        # Simple heuristic: internal addresses or metadata keywords
        internal_keywords = ["127.0.0.1", "169.254.169.254", "localhost", "metadata"]
        return any(k in response_snippet for k in internal_keywords)
