from weasyprint import HTML
from typing import List, Dict

class PDFReportBuilder:
    def __init__(self, html_builder: HTMLReportBuilder):
        self.html_builder = html_builder

    def build(self, findings: List[Dict], output_path: str):
        # Generate HTML first
        html_file = "temp_report.html"
        self.html_builder.build(findings, html_file)

        # Convert HTML to PDF
        HTML(html_file).write_pdf(output_path)
        return output_path
