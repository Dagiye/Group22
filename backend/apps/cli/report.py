import argparse
from reporting.builder_json import build_json_report
from reporting.builder_html import build_html_report
from reporting.builder_pdf import build_pdf_report
from reporting.normalize import normalize_findings
from backend.core.datastore import DataStore

def parse_args():
    parser = argparse.ArgumentParser(
        description="CLI for generating and exporting scan reports"
    )
    parser.add_argument(
        "action",
        choices=["generate", "export", "view"],
        help="Action to perform on reports"
    )
    parser.add_argument(
        "--scan_id",
        type=str,
        required=True,
        help="ID of the scan to process"
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "html", "pdf"],
        default="json",
        help="Format to export report"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output file path (for export)"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    datastore = DataStore()

    # Load findings for the given scan
    findings = datastore.get_findings(scan_id=args.scan_id)
    if not findings:
        print(f"[!] No findings found for scan ID {args.scan_id}")
        return

    # Normalize findings
    normalized = normalize_findings(findings)

    if args.action == "generate":
        print(f"[+] Generated report for scan {args.scan_id}")
        print(normalized)

    elif args.action == "export":
        if args.format == "json":
            content = build_json_report(normalized)
        elif args.format == "html":
            content = build_html_report(normalized)
        elif args.format == "pdf":
            content = build_pdf_report(normalized)
        else:
            print("[!] Unsupported format")
            return

        if args.output:
            with open(args.output, "wb" if args.format == "pdf" else "w") as f:
                f.write(content)
            print(f"[+] Report exported to {args.output}")
        else:
            print("[!] Output path required for export")

    elif args.action == "view":
        print(f"[+] Scan {args.scan_id} findings:")
        for f in normalized:
            print(f"- {f['vulnerability']} on {f['target']} | Severity: {f['severity']}")

if __name__ == "__main__":
    main()
