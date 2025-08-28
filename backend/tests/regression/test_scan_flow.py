import unittest
import os
from backend.reporting.builder_html import HTMLReportBuilder
from backend.reporting.normalize import Normalizer

class TestHTMLReportBuilder(unittest.TestCase):

    def setUp(self):
        self.builder = HTMLReportBuilder(template_dir="backend/payloads/templates")
        self.findings = Normalizer.normalize_findings([
            {"uuid": "1", "type": "xss", "target": "/", "description": "XSS", "evidence": []}
        ])
        self.output_file = "tests/output/report.html"

    def test_html_build(self):
        path = self.builder.build(self.findings, self.output_file)
        self.assertTrue(os.path.exists(path))
        with open(path, "r") as f:
            content = f.read()
            self.assertIn("XSS", content)

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

if __name__ == "__main__":
    unittest.main()

