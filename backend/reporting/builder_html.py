from jinja2 import Environment, FileSystemLoader
from typing import List, Dict
import os

class HTMLReportBuilder:
    def __init__(self, template_dir: str = "backend/payloads/templates"):
        """
        template_dir: directory containing `report_section.md.j2`
        """
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def build(self, findings: List[Dict], output_path: str):
        """
        Render the report template once per find
        ]]]]"ing and concatenate sections.
        - findings: list of normalized finding dicts (see backend/reporting/normalize.py)
        - output_path: path to write the generated report (HTML/Markdown)
        Returns the output_path on success.
        """
        template = self.env.get_template("report_section.md.j2")
        sections: List[str] = []

        # If findings is None or not a list, handle gracefully
        for f in findings or []:
            ctx = {
                "title": (f.get("type") or "").upper() or "Finding",
                "severity": (f.get("severity") or "unknown").capitalize(),
                "vuln_type": f.get("type") or "unknown",
                "description": f.get("description") or "",
                "url": f.get("target") or "",
                # Evidence can be a list of strings; join with newlines for display
                "evidence": "\n".join(f.get("evidence", []) or []),
            }
            sections.append(template.render(**ctx))

        report_html = "\n\n".join(sections)

        # Ensure directory exists and write file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report_html)

        return output_path
