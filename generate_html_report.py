#!/usr/bin/env python3
"""
generate_html_report.py

Builds a standalone, self-contained HTML dashboard report from an IIS
W3C Extended Log Format log file: KPI summary cards, four charts (status
donut, top pages, traffic-over-time, top error pages), and detail tables.
Charts are embedded inline as base64 PNGs, so the resulting .html file has
no external dependencies - you can email it, drop it on a share, or open
it straight from disk.

Usage:
    python generate_html_report.py <path_to_log_file> [options]

Examples:
    python generate_html_report.py u_ex260718.log
    python generate_html_report.py u_ex260718.log --out report.html --top 20
    python generate_html_report.py "u_ex2607*.log" --title "GlobalTel Weekly IIS Report"
"""

import argparse
import sys
import webbrowser

from iis_report_lib import load_logs, compute_summary, generate_charts, build_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Generate a standalone HTML dashboard report from an IIS log file."
    )
    parser.add_argument(
        "log_file",
        help="Path to an IIS log file (.log or .log.gz), a directory of logs, or a glob pattern.",
    )
    parser.add_argument("--out", default="iis_report.html", help="Output HTML file path (default: iis_report.html)")
    parser.add_argument("--top", type=int, default=15, help="Number of rows in each ranked table/chart (default: 15)")
    parser.add_argument("--title", default="IIS Log Report", help="Report title shown at the top of the page")
    parser.add_argument("--open", action="store_true", help="Open the generated report in the default browser")
    args = parser.parse_args()

    try:
        df, paths, parse_errors = load_logs(args.log_file)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    for err in parse_errors:
        print(f"Warning: {err}", file=sys.stderr)

    print(f"Parsed {len(df):,} requests from {len(paths)} file(s): {', '.join(paths)}")

    summary = compute_summary(df, top_n=args.top)
    charts = generate_charts(summary)
    html = build_html_report(
        summary,
        charts,
        title=args.title,
        embed="base64",
        source_note=", ".join(paths),
    )

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report written to: {args.out}")

    if args.open:
        webbrowser.open(args.out)


if __name__ == "__main__":
    main()
