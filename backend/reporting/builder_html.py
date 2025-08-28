from jinja2 import Environment, FileSystemLoader
from typing import List, Dict
import os

class HTMLReportBuilder:
    def __init__(self, template_dir: str = "backend/payloads/templates"):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def build(self, findings: List[Dict], output_path: str):
        template = self.env.get_template("report_section.md.j2")
        report_html = template.render(findings=findings)
        
        # Save HTML
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_html)
        return output_path
