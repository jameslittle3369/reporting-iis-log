#!/usr/bin/env python3
"""
analyze_iis_log.py

Analyzes a Microsoft IIS W3C Extended Log Format file for page hits and errors.

Usage:
    python analyze_iis_log.py <path_to_log_file> [options]

Examples:
    python analyze_iis_log.py u_ex260718.log
    python analyze_iis_log.py u_ex260718.log --top 20
    python analyze_iis_log.py u_ex260718.log --export-dir report_out
    python analyze_iis_log.py "C:\\logs\\*.log"        (Windows glob, quote it)

The script auto-detects the column layout from the file's "#Fields:" header
line(s), so it works whether the log has the default IIS field set or a
custom one. It supports files that contain multiple concatenated log
sessions (multiple #Fields/#Software blocks), and gzip-compressed logs
(.gz), and can accept a folder or glob pattern to analyze many files at once.
"""

import argparse
import os
import sys

import pandas as pd

from iis_report_lib import compute_summary, parse_iis_log, resolve_input_paths

pd.set_option("display.width", 120)
pd.set_option("display.max_colwidth", 60)


def fmt_bytes_or_none(v):
    return "n/a" if pd.isna(v) else f"{v:,.0f}"


def print_header(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def analyze(df, top_n=15):
    total = len(df)
    print_header("IIS LOG ANALYSIS SUMMARY")
    print(f"Total requests parsed : {total:,}")

    if "timestamp" in df.columns and df["timestamp"].notna().any():
        print(f"Date range             : {df['timestamp'].min()}  ->  {df['timestamp'].max()}")

    if "_real_client_ip" in df.columns:
        print(f"Unique client IPs      : {df['_real_client_ip'].nunique():,} (via X-Forwarded-For)")
    elif "c-ip" in df.columns:
        print(f"Unique client IPs      : {df['c-ip'].nunique():,}")

    # ---- Status code overview ------------------------------------------------
    if "sc-status" in df.columns:
        print_header("HTTP STATUS CODE BREAKDOWN")
        status_counts = df["sc-status"].value_counts().sort_index()
        status_pct = (status_counts / total * 100).round(2)
        summary = pd.DataFrame({"count": status_counts, "pct": status_pct})
        print(summary.to_string())

        # _status_bucket is already added by iis_report_lib.parse_iis_log()
        print("\nBy category:")
        bucket_counts = df["_status_bucket"].value_counts()
        bucket_pct = (bucket_counts / total * 100).round(2)
        print(pd.DataFrame({"count": bucket_counts, "pct": bucket_pct}).to_string())

        error_count = df["_status_bucket"].isin(["4xx client error", "5xx server error"]).sum()
        print(f"\nOverall error rate: {error_count:,} / {total:,} ({error_count/total*100:.2f}%)")

    # ---- Top pages by hits ----------------------------------------------------
    uri_col = "cs-uri-stem" if "cs-uri-stem" in df.columns else None
    if uri_col:
        print_header(f"TOP {top_n} PAGES BY HITS")
        top_pages = df[uri_col].value_counts().head(top_n)
        print(top_pages.to_string())

    # ---- Top pages generating errors ------------------------------------------
    if uri_col and "sc-status" in df.columns:
        print_header(f"TOP {top_n} PAGES BY ERROR COUNT (4xx/5xx)")
        err_df = df[df["_status_bucket"].isin(["4xx client error", "5xx server error"])]
        if len(err_df):
            top_err_pages = err_df[uri_col].value_counts().head(top_n)
            print(top_err_pages.to_string())

            print(f"\nTOP {top_n} SPECIFIC (PAGE, STATUS) ERROR COMBINATIONS")
            combo = (
                err_df.groupby([uri_col, "sc-status"])
                .size()
                .sort_values(ascending=False)
                .head(top_n)
            )
            print(combo.to_string())
        else:
            print("No 4xx/5xx errors found.")

    # ---- Custom error page redirects ------------------------------------------
    if "_error_redirect" in df.columns and df["_error_redirect"].any():
        summary = compute_summary(df, top_n)
        print_header(f"CUSTOM ERROR PAGE REDIRECTS ({summary['error_redirect_total']:,})")
        print("Logged as hits on: " + ", ".join(
            f"{p} ({c:,})" for p, c in summary["error_redirect_target_pages"].items()
        ))
        print("(counted under their original status in the sections above)")
        print(f"\nTOP {top_n} ORIGINAL RESOURCES")
        print(summary["error_redirect_sources"].to_string(index=False))
        if summary["error_redirect_referers"] is not None:
            print(f"\nTOP {top_n} REFERRING PAGES -> MISSING RESOURCES")
            print(summary["error_redirect_referers"].to_string(index=False))

    # ---- Slowest requests -------------------------------------------------
    if "time-taken" in df.columns and df["time-taken"].notna().any():
        print_header("RESPONSE TIME (time-taken, ms)")
        print(df["time-taken"].describe().to_string())

        print(f"\nTOP {top_n} SLOWEST REQUESTS")
        slow_cols = [c for c in [uri_col, "sc-status", "time-taken", "timestamp", "c-ip"] if c and c in df.columns]
        slowest = df.sort_values("time-taken", ascending=False).head(top_n)[slow_cols]
        print(slowest.to_string(index=False))

    # ---- Traffic over time --------------------------------------------------
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        print_header("HITS BY HOUR OF DAY")
        by_hour = df["timestamp"].dt.hour.value_counts().sort_index()
        print(by_hour.to_string())

        print_header("HITS BY DAY")
        by_day = df["timestamp"].dt.date.value_counts().sort_index()
        print(by_day.to_string())

    # ---- Top client IPs ------------------------------------------------------
    if "_real_client_ip" in df.columns:
        # c-ip is behind a proxy/ARR and not useful on its own here - note it,
        # then report the real client IPs pulled from X-Forwarded-For.
        if "c-ip" in df.columns and df["c-ip"].nunique() == 1:
            print_header("NOTE: PROXIED TRAFFIC DETECTED")
            print(
                f"c-ip is a single address ({df['c-ip'].iloc[0]}) for all requests - "
                f"this site is behind a reverse proxy/load balancer. "
                f"Client IPs below are extracted from X-Forwarded-For instead."
            )
        print_header(f"TOP {top_n} CLIENT IPs BY REQUEST COUNT (from X-Forwarded-For)")
        print(df["_real_client_ip"].value_counts().head(top_n).to_string())
    elif "c-ip" in df.columns:
        print_header(f"TOP {top_n} CLIENT IPs BY REQUEST COUNT")
        print(df["c-ip"].value_counts().head(top_n).to_string())

    # ---- Top user agents -------------------------------------------------
    ua_col = next((c for c in df.columns if c.lower().startswith("cs(user-agent)")), None)
    if ua_col:
        print_header(f"TOP {top_n} USER AGENTS")
        print(df[ua_col].value_counts().head(top_n).to_string())

    # ---- HTTP methods ----------------------------------------------------
    if "cs-method" in df.columns:
        print_header("REQUESTS BY HTTP METHOD")
        print(df["cs-method"].value_counts().to_string())

    return df


def export_reports(df, export_dir, top_n=15):
    os.makedirs(export_dir, exist_ok=True)

    df.to_csv(os.path.join(export_dir, "all_requests_parsed.csv"), index=False)

    if "cs-uri-stem" in df.columns:
        df["cs-uri-stem"].value_counts().head(top_n).rename("hits").to_csv(
            os.path.join(export_dir, "top_pages.csv")
        )

    if "sc-status" in df.columns:
        df["sc-status"].value_counts().sort_index().rename("count").to_csv(
            os.path.join(export_dir, "status_code_breakdown.csv")
        )
        if "cs-uri-stem" in df.columns:
            err_df = df[df["_status_bucket"].isin(["4xx client error", "5xx server error"])]
            err_df["cs-uri-stem"].value_counts().head(top_n).rename("errors").to_csv(
                os.path.join(export_dir, "top_error_pages.csv")
            )

    if "_real_client_ip" in df.columns:
        df["_real_client_ip"].value_counts().head(top_n).rename("hits").to_csv(
            os.path.join(export_dir, "top_client_ips.csv")
        )
    elif "c-ip" in df.columns:
        df["c-ip"].value_counts().head(top_n).rename("hits").to_csv(
            os.path.join(export_dir, "top_client_ips.csv")
        )

    print(f"\nReports exported to: {os.path.abspath(export_dir)}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze an IIS W3C Extended Log Format log file for page hits and errors."
    )
    parser.add_argument(
        "log_file",
        help="Path to an IIS log file (.log or .log.gz), a directory of logs, or a glob pattern.",
    )
    parser.add_argument(
        "--top", type=int, default=15, help="Number of top rows to show in each ranked section (default: 15)"
    )
    parser.add_argument(
        "--export-dir",
        default=None,
        help="If set, also writes CSV reports (top pages, errors, status codes, client IPs) to this directory.",
    )
    args = parser.parse_args()

    paths = resolve_input_paths(args.log_file)
    if not paths:
        print(f"No log files found matching: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    frames = []
    for p in paths:
        try:
            print(f"Parsing: {p}")
            frames.append(parse_iis_log(p))
        except ValueError as e:
            print(f"  Skipped ({e})", file=sys.stderr)

    if not frames:
        print("No valid log data parsed from any input file.", file=sys.stderr)
        sys.exit(1)

    df = pd.concat(frames, ignore_index=True)
    df = analyze(df, top_n=args.top)

    if args.export_dir:
        export_reports(df, args.export_dir, top_n=args.top)


if __name__ == "__main__":
    main()
