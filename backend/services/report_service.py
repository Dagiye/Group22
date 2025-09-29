# services/report_service.py
from reporting import builder_html, builder_pdf, builder_json

class ReportService:
    def __init__(self):
        self.builders = {
            "html": builder_html,
            "pdf": builder_pdf,
            "json": builder_json,
        }

    def generate_report(self, scan_id: str, fmt: str = "json") -> dict:
        """
        Build a report for a scan in the desired format.
        """
        if fmt not in self.builders:
            raise ValueError(f"Unsupported report format: {fmt}")

        builder = self.builders[fmt]
        report = builder.build(scan_id)
        return {"scan_id": scan_id, "format": fmt, "report": report}
