"""
responses.py
------------
Module for comparing HTTP responses to detect anomalies.
Used in active scanning for injection and fuzzing.
"""

from typing import Dict, List
import difflib
import hashlib


class ResponseDiff:
    def __init__(self, base_response: Dict, test_response: Dict):
        """
        base_response: dict with keys 'status_code', 'headers', 'body'
        test_response: dict with keys 'status_code', 'headers', 'body'
        """
        self.base_response = base_response
        self.test_response = test_response

    def compare_status(self) -> bool:
        """Compare HTTP status codes."""
        return self.base_response.get("status_code") == self.test_response.get("status_code")

    def compare_headers(self, ignore_headers: List[str] = None) -> Dict[str, Dict[str, str]]:
        """
        Compare headers and return differences.
        ignore_headers: list of headers to ignore during comparison
        """
        ignore_headers = ignore_headers or []
        diffs = {}
        for key in set(self.base_response["headers"].keys()).union(self.test_response["headers"].keys()):
            if key.lower() in map(str.lower, ignore_headers):
                continue
            base_val = self.base_response["headers"].get(key)
            test_val = self.test_response["headers"].get(key)
            if base_val != test_val:
                diffs[key] = {"base": base_val, "test": test_val}
        return diffs

    def compare_body(self, method: str = "diff") -> Dict:
        """
        Compare body content.
        method: "diff" returns unified diff, "hash" returns boolean match based on hash
        """
        base_body = self.base_response.get("body", "")
        test_body = self.test_response.get("body", "")

        if method == "hash":
            base_hash = hashlib.sha256(base_body.encode()).hexdigest()
            test_hash = hashlib.sha256(test_body.encode()).hexdigest()
            return {"match": base_hash == test_hash, "base_hash": base_hash, "test_hash": test_hash}

        elif method == "diff":
            diff = list(difflib.unified_diff(
                base_body.splitlines(),
                test_body.splitlines(),
                lineterm='',
            ))
            return {"diff": diff, "is_different": bool(diff)}

        else:
            raise ValueError("Invalid method. Use 'diff' or 'hash'.")

    def summary(self) -> Dict:
        """Return a combined summary of status, headers, and body differences."""
        return {
            "status_match": self.compare_status(),
            "header_diff": self.compare_headers(),
            "body_diff": self.compare_body()
        }


if __name__ == "__main__":
    # Example usage
    base = {
        "status_code": 200,
        "headers": {"Server": "nginx", "Content-Type": "text/html"},
        "body": "<html><body>Hello</body></html>"
    }
    test = {
        "status_code": 200,
        "headers": {"Server": "nginx", "Content-Type": "text/html"},
        "body": "<html><body>Hello world!</body></html>"
    }

    rd = ResponseDiff(base, test)
    result = rd.summary()
    print(result)
