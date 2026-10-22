#!/usr/bin/env python3
"""
iis_report_lib.py

Shared engine for the IIS log reporting tools in this project:
  - analyze_iis_log.py    (console report)
  - generate_html_report.py (standalone HTML dashboard)
  - send_report_email.py    (same report, emailed via Amazon SES)

This module owns:
  - Log parsing (W3C Extended Log Format, multi-block, gzip, reverse-proxy
    X-Forwarded-For handling)
  - Summary statistics / KPI computation
  - Chart generation (matplotlib, returned as PNG bytes)
  - HTML report assembly (KPI cards + charts + detail tables)

Nothing in here talks to the network or touches argv - it's pure
parsing/reporting logic so it can be reused and unit-tested independently
of any particular CLI or delivery mechanism.
"""

import base64
import glob
import gzip
import io
import os
from datetime import datetime

import pandas as pd

import matplotlib
matplotlib.use("Agg")  # headless - no display needed
import matplotlib.pyplot as plt

pd.set_option("display.width", 120)
pd.set_option("display.max_colwidth", 60)

STATUS_BUCKET_COLORS = {
    "2xx success": "#2ecc71",
    "3xx redirect": "#3498db",
    "4xx client error": "#f39c12",
    "5xx server error": "#e74c3c",
    "unknown": "#95a5a6",
    "other": "#9b59b6",
}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _open_maybe_gzip(path):
    if path.lower().endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_iis_log(path):
    """Parse a W3C Extended Log Format IIS log file into a DataFrame.

    Handles:
      - '#Fields:' header lines that define column names (required per W3C spec)
      - Multiple concatenated #Fields blocks in one file (log rollover / merges)
      - '-' as a null placeholder
      - Missing/blank lines and other '#' comment lines
    """
    fields = None
    rows = []

    with _open_maybe_gzip(path) as f:
        for raw_line in f:
            line = raw_line.rstrip("\n\r")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:"):].strip().split(" ")
                continue
            if fields is None:
                # No #Fields header seen yet; can't reliably map columns.
                continue
            parts = line.split(" ")
            if len(parts) != len(fields):
                # Malformed/truncated line (common at end of live logs) - skip it.
                continue
            rows.append(parts)

    if fields is None:
        raise ValueError(
            f"No '#Fields:' header found in {path}. This doesn't look like a "
            f"W3C Extended Log Format IIS log."
        )
    if not rows:
        raise ValueError(f"No parsable log entries found in {path}.")

    df = pd.DataFrame(rows, columns=fields)
    df.replace("-", pd.NA, inplace=True)

    # Build a proper timestamp column if date/time fields are present.
    if "date" in df.columns and "time" in df.columns:
        df["timestamp"] = pd.to_datetime(
            df["date"] + " " + df["time"], errors="coerce", utc=False
        )
    elif "time" in df.columns:
        df["timestamp"] = pd.to_datetime(df["time"], errors="coerce")

    # Numeric conversions for fields commonly used in analysis.
    for col in ("sc-status", "sc-substatus", "sc-win32-status", "time-taken", "s-port", "sc-bytes", "cs-bytes"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # If the site sits behind a reverse proxy / load balancer (common with
    # Application Request Routing, CDNs, etc.), c-ip will just be the proxy's
    # address for every request. X-Forwarded-For (when present) carries the
    # real chain of client IPs, comma-separated, left-most = original client.
    xff_col = next((c for c in df.columns if c.lower() == "x-forwarded-for"), None)
    if xff_col:
        df["_real_client_ip"] = (
            df[xff_col]
            .astype("string")
            .str.split(",")
            .str[0]
            .str.strip()
            .str.split(":")
            .str[0]  # drop a trailing :port if present
        )

    # Status bucket, used throughout analysis/reporting.
    if "sc-status" in df.columns:
        df["_status_bucket"] = df["sc-status"].apply(_status_bucket)

    return df


def _status_bucket(code):
    if pd.isna(code):
        return "unknown"
    code = int(code)
    if 200 <= code < 300:
        return "2xx success"
    if 300 <= code < 400:
        return "3xx redirect"
    if 400 <= code < 500:
        return "4xx client error"
    if 500 <= code < 600:
        return "5xx server error"
    return "other"


def resolve_input_paths(path_arg):
    """Expand a file, directory, or glob pattern into a list of log file paths."""
    if os.path.isdir(path_arg):
        candidates = sorted(
            glob.glob(os.path.join(path_arg, "*.log"))
            + glob.glob(os.path.join(path_arg, "*.log.gz"))
        )
    else:
        candidates = sorted(glob.glob(path_arg))
        if not candidates and os.path.isfile(path_arg):
            candidates = [path_arg]
    return candidates


def load_logs(path_arg):
    """Resolve a path/glob/dir to log files, parse and concatenate them."""
    paths = resolve_input_paths(path_arg)
    if not paths:
        raise ValueError(f"No log files found matching: {path_arg}")

    frames = []
    errors = []
    for p in paths:
        try:
            frames.append(parse_iis_log(p))
        except ValueError as e:
            errors.append(str(e))

    if not frames:
        raise ValueError("No valid log data parsed from any input file. " + "; ".join(errors))

    df = pd.concat(frames, ignore_index=True)
    return df, paths, errors


# ---------------------------------------------------------------------------
# Summary statistics / KPIs
# ---------------------------------------------------------------------------

def compute_summary(df, top_n=15):
    """Compute all summary stats/tables used by both the console and HTML reports."""
    total = len(df)
    summary = {"total_requests": total, "top_n": top_n}

    if "timestamp" in df.columns and df["timestamp"].notna().any():
        summary["date_min"] = df["timestamp"].min()
        summary["date_max"] = df["timestamp"].max()
    else:
        summary["date_min"] = summary["date_max"] = None

    ip_col = "_real_client_ip" if "_real_client_ip" in df.columns else ("c-ip" if "c-ip" in df.columns else None)
    summary["ip_col"] = ip_col
    summary["unique_ips"] = df[ip_col].nunique() if ip_col else None
    summary["proxied"] = bool(
        "_real_client_ip" in df.columns and "c-ip" in df.columns and df["c-ip"].nunique() == 1
    )
    summary["proxy_ip"] = df["c-ip"].iloc[0] if summary["proxied"] else None

    # Status codes
    if "sc-status" in df.columns:
        status_counts = df["sc-status"].value_counts().sort_index()
        summary["status_counts"] = status_counts
        summary["status_pct"] = (status_counts / total * 100).round(2)

        bucket_counts = df["_status_bucket"].value_counts()
        summary["bucket_counts"] = bucket_counts
        summary["bucket_pct"] = (bucket_counts / total * 100).round(2)

        error_mask = df["_status_bucket"].isin(["4xx client error", "5xx server error"])
        summary["error_count"] = int(error_mask.sum())
        summary["error_rate_pct"] = round(summary["error_count"] / total * 100, 2) if total else 0.0
    else:
        summary["status_counts"] = None
        summary["error_count"] = None
        summary["error_rate_pct"] = None

    # Top pages
    uri_col = "cs-uri-stem" if "cs-uri-stem" in df.columns else None
    summary["uri_col"] = uri_col
    if uri_col:
        summary["top_pages"] = df[uri_col].value_counts().head(top_n)
    else:
        summary["top_pages"] = None

    # Top error pages / combos
    if uri_col and "sc-status" in df.columns:
        err_df = df[df["_status_bucket"].isin(["4xx client error", "5xx server error"])]
        top_error_pages = err_df[uri_col].value_counts().head(top_n) if len(err_df) else None
        summary["top_error_pages"] = top_error_pages
        if len(err_df):
            summary["top_error_combos"] = (
                err_df.groupby([uri_col, "sc-status"]).size().sort_values(ascending=False).head(top_n)
            )
        else:
            summary["top_error_combos"] = None

        # Same table, with a 2xx column alongside the error count so it's
        # easy to see whether an "error page" is actually mostly fine
        # (occasional 404 on an otherwise healthy page) or fully broken.
        if top_error_pages is not None and len(top_error_pages):
            ok_df = df[df["_status_bucket"] == "2xx success"]
            ok_counts = ok_df[uri_col].value_counts()
            summary["top_error_pages_table"] = pd.DataFrame({
                "Page": top_error_pages.index,
                "Errors": top_error_pages.values,
                "2xx": [int(ok_counts.get(p, 0)) for p in top_error_pages.index],
            })
        else:
            summary["top_error_pages_table"] = None
    else:
        summary["top_error_pages"] = None
        summary["top_error_combos"] = None
        summary["top_error_pages_table"] = None

    # IIS custom error page redirects: when a request 404s (or otherwise
    # errors) behind a configured custom error page, IIS internally
    # redirects to that page and stows the original status + URL in
    # cs-uri-query as "STATUS;http://host:port/original/path". The referer
    # is empty for these (it's a server-side redirect, not a browser nav),
    # so this query string is the only record of what page actually 404'd.
    if uri_col and "cs-uri-query" in df.columns:
        redirect_pattern = df["cs-uri-query"].astype("string").str.match(r"^\d{3};https?://", na=False)
        redirects = df[redirect_pattern].copy()
        if len(redirects):
            extracted = redirects["cs-uri-query"].str.extract(r"^(?P<orig_status>\d{3});(?P<orig_url>https?://\S+)$")
            redirects["_orig_status"] = extracted["orig_status"]
            redirects["_orig_path"] = extracted["orig_url"].str.replace(r"^https?://[^/]+", "", regex=True)
            summary["error_redirect_total"] = len(redirects)
            summary["error_redirect_target_pages"] = redirects[uri_col].value_counts()
            summary["error_redirect_sources"] = redirects["_orig_path"].value_counts().head(top_n)
        else:
            summary["error_redirect_total"] = 0
            summary["error_redirect_target_pages"] = None
            summary["error_redirect_sources"] = None
    else:
        summary["error_redirect_total"] = 0
        summary["error_redirect_target_pages"] = None
        summary["error_redirect_sources"] = None

    # Response time
    if "time-taken" in df.columns and df["time-taken"].notna().any():
        summary["response_time_stats"] = df["time-taken"].describe()
        summary["avg_response_ms"] = round(df["time-taken"].mean(), 1)
        slow_cols = [c for c in [uri_col, "sc-status", "time-taken", "timestamp", ip_col] if c and c in df.columns]
        summary["slowest_requests"] = df.sort_values("time-taken", ascending=False).head(top_n)[slow_cols]
    else:
        summary["response_time_stats"] = None
        summary["avg_response_ms"] = None
        summary["slowest_requests"] = None

    # Bandwidth
    if "sc-bytes" in df.columns and df["sc-bytes"].notna().any():
        summary["total_bytes_sent"] = int(df["sc-bytes"].sum())
    else:
        summary["total_bytes_sent"] = None

    # Traffic over time
    if "timestamp" in df.columns and df["timestamp"].notna().any():
        summary["by_hour"] = df["timestamp"].dt.hour.value_counts().sort_index()
        summary["by_day"] = df["timestamp"].dt.date.value_counts().sort_index()
        # Hourly bins across the actual timespan (handles multi-day logs sanely).
        span_hours = (df["timestamp"].max() - df["timestamp"].min()).total_seconds() / 3600
        if span_hours <= 48:
            summary["timeline"] = df.set_index("timestamp").resample("1h").size()
        else:
            summary["timeline"] = df.set_index("timestamp").resample("1D").size()
    else:
        summary["by_hour"] = summary["by_day"] = summary["timeline"] = None

    # Top client IPs
    if ip_col:
        summary["top_ips"] = df[ip_col].value_counts().head(top_n)
    else:
        summary["top_ips"] = None

    # Top user agents
    ua_col = next((c for c in df.columns if c.lower().startswith("cs(user-agent)")), None)
    summary["ua_col"] = ua_col
    summary["top_user_agents"] = df[ua_col].value_counts().head(top_n) if ua_col else None

    # HTTP methods
    summary["methods"] = df["cs-method"].value_counts() if "cs-method" in df.columns else None

    return summary


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def _fig_to_png_bytes(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def chart_status_donut(summary):
    bucket_counts = summary.get("bucket_counts")
    if bucket_counts is None or bucket_counts.empty:
        return None
    # Largest slice first so the donut reads clockwise from most to least common.
    bucket_counts = bucket_counts.sort_values(ascending=False)
    labels = list(bucket_counts.index)
    values = list(bucket_counts.values)
    total = sum(values)
    colors = [STATUS_BUCKET_COLORS.get(l, "#7f8c8d") for l in labels]

    # No on-wedge labels/percentages - slices for rare status codes (e.g. a
    # handful of 4xx out of hundreds of requests) are too thin to hold
    # legible text. Instead, put "label - count (pct%)" in a legend, which
    # stays readable no matter how small a slice is.
    fig, ax = plt.subplots(figsize=(6.5, 5))
    wedges, _texts = ax.pie(
        values,
        colors=colors,
        startangle=90,
        wedgeprops=dict(width=0.4, edgecolor="white"),
    )
    legend_labels = [
        f"{label} — {count:,} ({count / total * 100:.2f}%)"
        for label, count in zip(labels, values)
    ]
    ax.legend(
        wedges,
        legend_labels,
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
        fontsize=9,
        frameon=False,
    )
    ax.set_title("HTTP Status Breakdown", fontsize=13, fontweight="bold")
    return _fig_to_png_bytes(fig)


def chart_top_pages_bar(summary):
    top_pages = summary.get("top_pages")
    if top_pages is None or top_pages.empty:
        return None
    data = top_pages.sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(7, max(3, 0.35 * len(data))))
    ax.barh([str(x) for x in data.index], data.values, color="#3498db")
    ax.set_xlabel("Hits")
    ax.set_title(f"Top {len(data)} Pages by Hits", fontsize=13, fontweight="bold")
    ax.tick_params(axis="y", labelsize=8)
    return _fig_to_png_bytes(fig)


def chart_traffic_timeline(summary):
    timeline = summary.get("timeline")
    if timeline is None or timeline.empty:
        return None
    fig, ax = plt.subplots(figsize=(7.5, 3.5))
    ax.plot(timeline.index, timeline.values, color="#2ecc71", linewidth=2, marker="o", markersize=3)
    ax.fill_between(timeline.index, timeline.values, color="#2ecc71", alpha=0.15)
    ax.set_ylabel("Requests")
    ax.set_title("Traffic Over Time", fontsize=13, fontweight="bold")
    fig.autofmt_xdate()
    return _fig_to_png_bytes(fig)


def chart_top_error_pages_bar(summary):
    top_error_pages = summary.get("top_error_pages")
    if top_error_pages is None or top_error_pages.empty:
        return None
    data = top_error_pages.sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(7, max(3, 0.35 * len(data))))
    ax.barh([str(x) for x in data.index], data.values, color="#e74c3c")
    ax.set_xlabel("Error count (4xx/5xx)")
    ax.set_title(f"Top {len(data)} Error Pages", fontsize=13, fontweight="bold")
    ax.tick_params(axis="y", labelsize=8)
    return _fig_to_png_bytes(fig)


def generate_charts(summary):
    """Return an ordered dict of chart name -> PNG bytes (skips charts with no data)."""
    charts = {}
    for name, fn in (
        ("status_donut", chart_status_donut),
        ("top_pages", chart_top_pages_bar),
        ("traffic_timeline", chart_traffic_timeline),
        ("top_error_pages", chart_top_error_pages_bar),
    ):
        png = fn(summary)
        if png:
            charts[name] = png
    return charts


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

CHART_TITLES = {
    "status_donut": "Status Code Breakdown",
    "top_pages": "Top Pages by Hits",
    "traffic_timeline": "Traffic Over Time",
    "top_error_pages": "Top Error Pages",
}

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       background: #f4f6f8; color: #1f2933; margin: 0; padding: 24px; }
.container { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 22px; margin-bottom: 4px; }
.subtitle { color: #64748b; font-size: 13px; margin-bottom: 24px; }
.kpi-grid { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }
.kpi-card { background: #fff; border-radius: 10px; padding: 16px 20px; flex: 1 1 160px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08); border-top: 3px solid #3498db; }
.kpi-card.error { border-top-color: #e74c3c; }
.kpi-card .value { font-size: 24px; font-weight: 700; }
.kpi-card .label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .03em; margin-top: 4px; }
.chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 28px; }
.chart-card { background: #fff; border-radius: 10px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }
.chart-card img { max-width: 100%; height: auto; }
.section { background: #fff; border-radius: 10px; padding: 16px 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.section h2 { font-size: 15px; margin: 0 0 12px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #e2e8f0; }
th { background: #f8fafc; font-weight: 600; color: #475569; }
tr:hover td { background: #f8fafc; }
.note { background: #fff8e6; border: 1px solid #f5d98b; border-radius: 8px; padding: 10px 14px;
        font-size: 12.5px; margin-bottom: 20px; }
.footer { color: #94a3b8; font-size: 11px; text-align: center; margin-top: 20px; }
"""


def _kpi_cards_html(summary):
    cards = []
    cards.append(("Total Requests", f"{summary['total_requests']:,}", False))
    if summary.get("date_min") is not None:
        span = f"{summary['date_min']:%Y-%m-%d %H:%M} &rarr; {summary['date_max']:%Y-%m-%d %H:%M}"
        cards.append(("Date Range", span, False))
    if summary.get("unique_ips") is not None:
        cards.append(("Unique Client IPs", f"{summary['unique_ips']:,}", False))
    if summary.get("error_rate_pct") is not None:
        cards.append((
            "Error Rate",
            f"{summary['error_rate_pct']:.2f}% ({summary['error_count']:,})",
            summary["error_rate_pct"] >= 1.0,
        ))
    if summary.get("avg_response_ms") is not None:
        cards.append(("Avg Response Time", f"{summary['avg_response_ms']:.0f} ms", False))
    if summary.get("total_bytes_sent") is not None:
        mb = summary["total_bytes_sent"] / (1024 * 1024)
        cards.append(("Total Bandwidth Sent", f"{mb:,.1f} MB", False))

    html = ['<div class="kpi-grid">']
    for label, value, is_error in cards:
        cls = "kpi-card error" if is_error else "kpi-card"
        html.append(f'<div class="{cls}"><div class="value">{value}</div><div class="label">{label}</div></div>')
    html.append("</div>")
    return "\n".join(html)


def _series_table_html(series, col_names=("Value", "Count")):
    if series is None or (hasattr(series, "empty") and series.empty):
        return "<p><em>No data.</em></p>"
    rows = "\n".join(
        f"<tr><td>{_esc(idx)}</td><td>{val:,}</td></tr>" for idx, val in series.items()
    )
    return f"<table><thead><tr><th>{col_names[0]}</th><th>{col_names[1]}</th></tr></thead><tbody>{rows}</tbody></table>"


def _df_table_html(df):
    if df is None or df.empty:
        return "<p><em>No data.</em></p>"
    return df.to_html(index=False, classes="", border=0, escape=True, na_rep="n/a")


def _error_redirect_section_html(summary):
    sources = summary.get("error_redirect_sources")
    if sources is None or sources.empty:
        return ""
    total = summary.get("error_redirect_total", 0)
    targets = summary.get("error_redirect_target_pages")
    target_note = ""
    if targets is not None and not targets.empty:
        target_list = ", ".join(f"{_esc(p)} ({c:,})" for p, c in targets.items())
        target_note = f'<p style="color:#64748b;font-size:12.5px;margin-top:-4px;">Redirect target page(s): {target_list}</p>'
    return f"""
  <div class="section">
    <h2>Pages That Redirected to a Custom Error Page ({total:,} redirects)</h2>
    <p style="color:#64748b;font-size:12.5px;">
      IIS redirects failed requests to a configured custom error page and records the
      original URL and status in the query string. This table shows what actually
      404'd (or errored), not just hits on the error page itself.
    </p>
    {target_note}
    {_series_table_html(sources, ("Original Page", "Redirects"))}
  </div>
"""


def _esc(v):
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html_report(summary, charts, title="IIS Log Report", embed="base64", source_note=None):
    """Assemble the full HTML report.

    embed:
      - "base64": inline <img src="data:image/png;base64,..."> (standalone file)
      - "cid":    <img src="cid:chart_NAME"> (for MIME email embedding)
    """
    def img_tag(name):
        if name not in charts:
            return ""
        if embed == "cid":
            src = f"cid:chart_{name}"
        else:
            b64 = base64.b64encode(charts[name]).decode("ascii")
            src = f"data:image/png;base64,{b64}"
        return f'<div class="chart-card"><h3>{CHART_TITLES.get(name, name)}</h3><img src="{src}" alt="{CHART_TITLES.get(name, name)}"></div>'

    chart_html = "\n".join(img_tag(n) for n in ("status_donut", "top_pages", "traffic_timeline", "top_error_pages") if n in charts)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_note_html = f'<div class="subtitle">Source: {_esc(source_note)}</div>' if source_note else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <h1>{_esc(title)}</h1>
  <div class="subtitle">Generated {generated_at}</div>
  {src_note_html}

  {_kpi_cards_html(summary)}

  <div class="chart-grid">
    {chart_html}
  </div>

  <div class="section">
    <h2>Status Code Breakdown</h2>
    {_series_table_html(summary.get("status_counts"), ("Status Code", "Count"))}
  </div>

  <div class="section">
    <h2>Top {summary['top_n']} Pages by Hits</h2>
    {_series_table_html(summary.get("top_pages"), ("Page", "Hits"))}
  </div>

  <div class="section">
    <h2>Top {summary['top_n']} Error Pages (4xx/5xx)</h2>
    {_df_table_html(summary.get("top_error_pages_table"))}
  </div>

  {_error_redirect_section_html(summary)}

  <div class="section">
    <h2>Slowest Requests</h2>
    {_df_table_html(summary.get("slowest_requests"))}
  </div>

  <div class="section">
    <h2>Top {summary['top_n']} Client IPs</h2>
    {_series_table_html(summary.get("top_ips"), ("Client IP", "Hits"))}
  </div>

  <div class="section">
    <h2>Top {summary['top_n']} User Agents</h2>
    {_series_table_html(summary.get("top_user_agents"), ("User Agent", "Hits"))}
  </div>

  <div class="footer">IIS Log Report &middot; generated by generate_html_report.py / send_report_email.py</div>
</div>
</body>
</html>
"""
    return html
