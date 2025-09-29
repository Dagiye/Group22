# backend/core/pipeline.py

import asyncio
from typing import List, Dict, Any
from backend.core.engine import ScanEngine
from backend.core.context import ScanContext
from reporting.builder_json import JsonReportBuilder
from reporting.builder_html import HtmlReportBuilder
from reporting.builder_pdf import PdfReportBuilder

class ScanPipeline:
    """
    Orchestrates the complete scanning process:
    - Initializes scan context
    - Runs multiple scan engines (e.g., full, quick, targeted)
    - Processes findings
    - Generates reports in multiple formats
    """

    def __init__(self, target_url: str, scan_id: str, scan_mode: str = "full"):
        self.target_url = target_url
        self.scan_id = scan_id
        self.scan_mode = scan_mode  # full, quick, or custom ruleset
        self.context = ScanContext(scan_id=scan_id, target_url=target_url)
        self.findings: List[Dict[str, Any]] = []

    async def run(self):
        """Main entrypoint to execute the scan pipeline"""
        print(f"[PIPELINE] Starting scan pipeline for {self.target_url} in {self.scan_mode} mode")
        engine = ScanEngine(self.target_url, self.scan_id)
        await engine.run()
        self.findings = await engine.report_findings()
        print(f"[PIPELINE] Scan pipeline complete for {self.target_url}")
        return self.findings

    def generate_reports(self, output_dir: str):
        """Generate reports in JSON, HTML, and PDF formats"""
        print(f"[PIPELINE] Generating reports for scan {self.scan_id}...")

        json_builder = JsonReportBuilder(self.findings, self.context)
        json_path = json_builder.build(output_dir)
        print(f"[PIPELINE] JSON report saved at: {json_path}")

        html_builder = HtmlReportBuilder(self.findings, self.context)
        html_path = html_builder.build(output_dir)
        print(f"[PIPELINE] HTML report saved at: {html_path}")

        pdf_builder = PdfReportBuilder(self.findings, self.context)
        pdf_path = pdf_builder.build(output_dir)
        print(f"[PIPELINE] PDF report saved at: {pdf_path}")

        return {
            "json": json_path,
            "html": html_path,
            "pdf": pdf_path
        }

    async def run_full_scan(self, output_dir: str):
        """Helper to run scan and generate reports"""
        await self.run()
        return self.generate_reports(output_dir)

# Example usage
# asyncio.run(ScanPipeline("https://example.com", "scan_001").run_full_scan("./reports"))
