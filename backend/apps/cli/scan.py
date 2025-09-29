import argparse
from backend.core.engine import ScanEngine
from backend.core.config import load_scan_config

def parse_args():
    parser = argparse.ArgumentParser(
        description="CLI for starting web application scans"
    )
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target URL or domain to scan"
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Optional path to a custom scan configuration file"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=3,
        help="Depth of crawling for the scan"
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        default=5,
        help="Number of concurrent scan threads"
    )
    parser.add_argument(
        "--report",
        type=str,
        default="json",
        choices=["json", "html", "pdf"],
        help="Report format after scan"
    )
    return parser.parse_args()

def main():
    args = parse_args()

    # Load configuration
    if args.config:
        config = load_scan_config(args.config)
    else:
        config = load_scan_config()  # Load default

    # Initialize scan engine
    engine = ScanEngine(
        target=args.target,
        config=config,
        depth=args.depth,
        concurrent=args.concurrent
    )

    print(f"[+] Starting scan on {args.target} with depth {args.depth}...")
    results = engine.start_scan()

    print(f"[+] Scan completed. Found {len(results)} potential issues.")

    # Optionally, export results
    if args.report:
        from reporting.builder_json import build_json_report
        from reporting.builder_html import build_html_report
        from reporting.builder_pdf import build_pdf_report
        from reporting.normalize import normalize_findings

        normalized = normalize_findings(results)

        if args.report == "json":
            report_content = build_json_report(normalized)
            filename = f"{args.target.replace('://','_')}_report.json"
            with open(filename, "w") as f:
                f.write(report_content)
        elif args.report == "html":
            report_content = build_html_report(normalized)
            filename = f"{args.target.replace('://','_')}_report.html"
            with open(filename, "w") as f:
                f.write(report_content)
        elif args.report == "pdf":
            report_content = build_pdf_report(normalized)
            filename = f"{args.target.replace('://','_')}_report.pdf"
            with open(filename, "wb") as f:
                f.write(report_content)

        print(f"[+] Report saved as {filename}")

if __name__ == "__main__":
    main()
