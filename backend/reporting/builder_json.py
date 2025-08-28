import json
from typing import List, Dict

class JSONReportBuilder:
    @staticmethod
    def build(findings: List[Dict], output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=4)
        return output_path
