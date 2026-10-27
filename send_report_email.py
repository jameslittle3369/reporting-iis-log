#!/usr/bin/env python3
"""
send_report_email.py

Builds the same KPI + chart dashboard as generate_html_report.py and sends
it as an HTML email via Amazon SES, with the charts embedded inline (MIME
multipart/related, Content-ID references - no attachments the recipient
has to open separately).

Credentials: uses the standard boto3 credential chain (environment
variables, ~/.aws/credentials, IAM role, etc). Easiest one-time setup:

    aws configure

See README.md for full SES sender/recipient verification steps.

Usage:
    python send_report_email.py <log_file> --to a@x.com,b@x.com --from reports@yourdomain.com

Examples:
    python send_report_email.py u_ex260718.log --to ops@globaltel.com --from reports@globaltel.com
    python send_report_email.py u_ex260718.log --to ops@globaltel.com --from reports@globaltel.com --dry-run
    python send_report_email.py u_ex260718.log --to ops@globaltel.com --from reports@globaltel.com \\
        --subject "Daily IIS Report" --region us-east-1 --top 20
"""

import argparse
import os
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.utils import formataddr

from iis_report_lib import load_logs, compute_summary, generate_charts, build_html_report

# ---------------------------------------------------------------------------
# .env config
#
# Sender name/address and default recipients live in a .env file next to
# this script (not in source) so they can differ per-deployment without
# editing code, and so real addresses don't end up hardcoded/committed.
# See .env.example for the template. Precedence: real environment variables
# > .env file > built-in fallback. CLI flags (--from, --to, etc.) always
# win over all of the above when explicitly passed.
# ---------------------------------------------------------------------------

def _load_env_file(path=None):
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)  # real env vars still take precedence


_load_env_file()

DEFAULT_SENDER_NAME = os.environ.get("IIS_SENDER_NAME", "James Little")
DEFAULT_SENDER_EMAIL = os.environ.get("IIS_SENDER_EMAIL")
DEFAULT_TO = os.environ.get("IIS_DEFAULT_TO")
DEFAULT_CC = os.environ.get("IIS_DEFAULT_CC")


def build_mime_message(subject, sender, sender_name, recipients, html_body, charts, cc=None):
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, sender)) if sender_name else sender
    msg["To"] = ", ".join(recipients)
    if cc:
        msg["Cc"] = ", ".join(cc)

    msg_body = MIMEMultipart("alternative")
    plain_text = (
        "This report contains an HTML dashboard with charts. "
        "Please view it in an HTML-capable email client."
    )
    msg_body.attach(MIMEText(plain_text, "plain"))

    msg_related = MIMEMultipart("related")
    msg_related.attach(MIMEText(html_body, "html"))

    for name, png_bytes in charts.items():
        img = MIMEImage(png_bytes, _subtype="png")
        img.add_header("Content-ID", f"<chart_{name}>")
        img.add_header("Content-Disposition", "inline", filename=f"{name}.png")
        msg_related.attach(img)

    msg_body.attach(msg_related)
    msg.attach(msg_body)
    return msg


def main():
    parser = argparse.ArgumentParser(
        description="Email an IIS log HTML dashboard report via Amazon SES."
    )
    parser.add_argument(
        "log_file",
        help="Path to an IIS log file (.log or .log.gz), a directory of logs, or a glob pattern.",
    )
    parser.add_argument(
        "--to",
        default=DEFAULT_TO,
        required=False,
        help="Comma-separated recipient email address(es). Falls back to IIS_DEFAULT_TO in .env.",
    )
    parser.add_argument(
        "--cc",
        default=DEFAULT_CC,
        help="Comma-separated CC email address(es). Falls back to IIS_DEFAULT_CC in .env.",
    )
    parser.add_argument(
        "--from",
        dest="sender",
        default=DEFAULT_SENDER_EMAIL,
        required=False,
        help="Verified SES sender email address. Falls back to IIS_SENDER_EMAIL in .env.",
    )
    parser.add_argument(
        "--from-name",
        dest="sender_name",
        default=DEFAULT_SENDER_NAME,
        help=f"Display name shown for the sender (default: {DEFAULT_SENDER_NAME}; falls back to IIS_SENDER_NAME in .env).",
    )
    parser.add_argument("--subject", default=None, help="Email subject (default: auto-generated with the log date range).")
    parser.add_argument("--title", default="IIS Log Report", help="Report title shown at the top of the HTML body.")
    parser.add_argument("--top", type=int, default=15, help="Number of rows in each ranked table/chart (default: 15)")
    parser.add_argument("--slow-ms", type=int, default=10000, help="Threshold in ms for the slow-request analysis (default: 10000)")
    parser.add_argument("--region", default=None, help="AWS region for SES (default: from AWS config/env, e.g. us-east-1).")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the email and save it as a .eml file locally instead of sending via SES.",
    )
    parser.add_argument(
        "--dry-run-out",
        default="report_preview.eml",
        help="Output path for --dry-run (default: report_preview.eml). Open it in any email client / most browsers to preview.",
    )
    args = parser.parse_args()

    if not args.sender:
        parser.error("--from is required (or set IIS_SENDER_EMAIL in .env). See .env.example.")
    if not args.to:
        parser.error("--to is required (or set IIS_DEFAULT_TO in .env). See .env.example.")

    try:
        df, paths, parse_errors = load_logs(args.log_file)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    for err in parse_errors:
        print(f"Warning: {err}", file=sys.stderr)

    print(f"Parsed {len(df):,} requests from {len(paths)} file(s): {', '.join(paths)}")

    summary = compute_summary(df, top_n=args.top, slow_ms=args.slow_ms)
    charts = generate_charts(summary)
    html_body = build_html_report(
        summary,
        charts,
        title=args.title,
        embed="cid",
        source_note=", ".join(paths),
    )

    recipients = [addr.strip() for addr in args.to.split(",") if addr.strip()]
    cc = [addr.strip() for addr in args.cc.split(",") if addr.strip()] if args.cc else None

    subject = args.subject
    if not subject:
        if summary.get("date_min") is not None:
            subject = f"IIS Log Report - {summary['date_min']:%Y-%m-%d} ({summary['total_requests']:,} requests)"
        else:
            subject = "IIS Log Report"

    msg = build_mime_message(subject, args.sender, args.sender_name, recipients, html_body, charts, cc=cc)

    if args.dry_run:
        with open(args.dry_run_out, "wb") as f:
            f.write(msg.as_bytes())
        print(f"[DRY RUN] No email sent. Preview saved to: {args.dry_run_out}")
        print(f"[DRY RUN] Would send to: {', '.join(recipients)}" + (f" (cc: {', '.join(cc)})" if cc else ""))
        print(f"[DRY RUN] From: {msg['From']}")
        print(f"[DRY RUN] Subject: {subject}")
        print(f"[DRY RUN] Charts embedded: {', '.join(charts.keys()) if charts else '(none)'}")
        return

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError, BotoCoreError
    except ImportError:
        print(
            "Error: boto3 is not installed. Run setup_venv.ps1/.bat or "
            "'pip install -r requirements.txt' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    all_recipients = recipients + (cc or [])
    try:
        ses = boto3.client("ses", region_name=args.region) if args.region else boto3.client("ses")
        response = ses.send_raw_email(
            Source=msg["From"],
            Destinations=all_recipients,
            RawMessage={"Data": msg.as_bytes()},
        )
    except NoCredentialsError:
        print(
            "Error: No AWS credentials found. Run 'aws configure' first, or set "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables. "
            "See README.md for details.",
            file=sys.stderr,
        )
        sys.exit(1)
    except NoRegionError:
        print(
            "Error: No AWS region configured. Run 'aws configure' to set a default "
            "region, or pass --region (e.g. --region us-east-1).",
            file=sys.stderr,
        )
        sys.exit(1)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        message = e.response.get("Error", {}).get("Message", str(e))
        print(f"Error sending email via SES ({code}): {message}", file=sys.stderr)
        if code == "MessageRejected" and "not verified" in message.lower():
            print(
                "Hint: In SES sandbox mode, BOTH the sender and every recipient address "
                "must be verified. See README.md for verification steps.",
                file=sys.stderr,
            )
        sys.exit(1)
    except BotoCoreError as e:
        print(f"Error sending email via SES: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Email sent. SES MessageId: {response['MessageId']}")
    print(f"To: {', '.join(recipients)}" + (f" (cc: {', '.join(cc)})" if cc else ""))


if __name__ == "__main__":
    main()
