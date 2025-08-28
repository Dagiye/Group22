import unittest
from backend.reporting.normalize import Normalizer

class TestNormalizer(unittest.TestCase):

    def test_normalize_single_finding(self):
        finding = {
            "uuid": "123",
            "type": "sqli",
            "target": "/login",
            "description": "SQL injection possible",
            "evidence": ["payload=' OR 1=1 --"]
        }
        normalized = Normalizer.normalize_finding(finding)
        self.assertEqual(normalized["id"], "123")
        self.assertEqual(normalized["severity"], "medium")
        self.assertEqual(normalized["type"], "sqli")
        self.assertIn("payload", normalized["evidence"][0])

    def test_normalize_list(self):
        findings = [
            {"uuid": "1", "type": "xss", "target": "/", "description": "XSS", "evidence": []},
            {"uuid": "2", "type": "csrf", "target": "/form", "description": "CSRF", "evidence": []}
        ]
        normalized = Normalizer.normalize_findings(findings)
        self.assertEqual(len(normalized), 2)
        self.assertEqual(normalized[0]["type"], "xss")
        self.assertEqual(normalized[1]["type"], "csrf")

if __name__ == "__main__":
    unittest.main()
