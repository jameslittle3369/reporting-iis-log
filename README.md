# IIS Log Reporting Toolkit

Parses Microsoft IIS W3C Extended Log Format logs and produces three kinds
of report from the same underlying engine:

| Script                    | Output                                                          |
|----------------------------|-----------------------------------------------------------------|
| `analyze_iis_log.py`       | Plain-text console report                                       |
| `generate_html_report.py`  | Standalone HTML dashboard (KPI cards + charts + tables)          |
| `send_report_email.py`     | Same HTML dashboard, emailed via Amazon SES with inline charts   |

All three share `iis_report_lib.py`, which handles log parsing, KPI/summary
computation, chart generation, and HTML assembly.

## Setup (one-time, on Windows)

Everything below lives in `d:\projects\reporting\iis` alongside your log
file(s) (e.g. `u_ex260718.log`):

- `analyze_iis_log.py`
- `iis_report_lib.py`
- `generate_html_report.py`
- `send_report_email.py`
- `requirements.txt`
- `setup_venv.ps1` / `setup_venv.bat`

From that folder:

```powershell
cd d:\projects\reporting\iis
powershell -ExecutionPolicy Bypass -File .\setup_venv.ps1
```

(or double-click / run `setup_venv.bat` if you prefer cmd.exe)

This creates a `venv\` folder and installs `pandas`, `matplotlib`, and
`boto3` into it.

Then activate it before running anything:

```powershell
.\venv\Scripts\Activate.ps1
```

```cmd
.\venv\Scripts\activate.bat
```

## 1. Console report — `analyze_iis_log.py`

```powershell
python analyze_iis_log.py u_ex260718.log
```

Options:

- `--top N` — rows shown in each ranked section (default 15)
  ```
  python analyze_iis_log.py u_ex260718.log --top 25
  ```
- `--export-dir <folder>` — also write CSV reports (top pages, top error
  pages, status code breakdown, top client IPs, full parsed data)
  ```
  python analyze_iis_log.py u_ex260718.log --export-dir report_out
  ```

Includes: total requests, date range, unique client IPs, HTTP status
breakdown (raw codes + 2xx/3xx/4xx/5xx buckets + error rate), top pages,
top error pages and (page, status) combos, response time stats and
slowest requests, hits by hour/day, top client IPs, top user agents, and
requests by HTTP method.

## 2. HTML dashboard — `generate_html_report.py`

```powershell
python generate_html_report.py u_ex260718.log --open
```

Produces a single self-contained `.html` file (charts embedded as base64
PNGs, no external files needed) with:

- KPI summary cards (total requests, date range, unique IPs, error rate,
  avg response time, total bandwidth)
- Four charts: status code donut, top pages bar, traffic-over-time line,
  top error pages bar
- Detail tables: status breakdown, top pages, top error pages, pages that
  redirected to a custom error page, slowest requests, top client IPs, top
  user agents

Options:

- `--out <file>` — output path (default: `iis_report.html`)
- `--top N` — rows in each ranked table/chart (default 15)
- `--title "..."` — report title
- `--open` — open the file in your default browser once it's written

```powershell
python generate_html_report.py u_ex260718.log --out report.html --top 20 --title "GlobalTel IIS Report - July 18"
```

## 3. Email delivery via Amazon SES — `send_report_email.py`

Builds the identical dashboard and emails it with the charts inline
(MIME `multipart/related`, referenced by Content-ID — not attachments the
recipient has to click open).

### Email config (.env)

Sender name/address and default recipients are read from a `.env` file
next to the scripts, not hardcoded — copy the template once:

```powershell
copy .env.example .env
```

Then edit `.env`:

```
IIS_SENDER_NAME=James Little
IIS_SENDER_EMAIL=reports@globaltel.com
IIS_DEFAULT_TO=ops@globaltel.com
IIS_DEFAULT_CC=
```

`.env` is loaded automatically. Precedence is: real OS environment
variables (if set) > `.env` file > built-in default (`James Little` for
the sender name only — `--from`/`--to` have no built-in default and must
come from `.env` or a CLI flag). Passing `--to`, `--from`, or `--from-name`
on the command line always overrides `.env` for that run.

`.env` isn't meant to be shared/committed — it's config for this
particular install. Only `.env.example` (the template, no real addresses)
should be treated as shared.

With `.env` set up, the simplest run is just:

```powershell
python send_report_email.py u_ex260718.log
```

Or override per-run without touching `.env`:

```powershell
python send_report_email.py u_ex260718.log --to ops@globaltel.com --from reports@globaltel.com
```

Options:

- `--to` — comma-separated recipient address(es) (falls back to `IIS_DEFAULT_TO` in `.env`; required one way or the other)
- `--from` — verified SES sender address (falls back to `IIS_SENDER_EMAIL` in `.env`; required one way or the other)
- `--from-name` — display name shown for the sender (falls back to `IIS_SENDER_NAME` in `.env`, default: `James Little`)
- `--cc` — comma-separated CC address(es) (falls back to `IIS_DEFAULT_CC` in `.env`)
- `--subject` — defaults to `IIS Log Report - <date> (<N> requests)`
- `--title` — title shown in the HTML body
- `--top N` — rows in each ranked table/chart (default 15)
- `--region` — SES region (defaults to your AWS config/env, e.g. `us-east-1`)
- `--dry-run` — build the full email (with inline charts) and save it as a
  local `.eml` file instead of sending. Open it in most email clients (or
  drag it into a browser tab) to preview exactly what would be sent.
- `--dry-run-out <file>` — output path for `--dry-run` (default:
  `report_preview.eml`)

Always preview first:

```powershell
python send_report_email.py u_ex260718.log --dry-run
```

Then send for real by dropping `--dry-run`.

### AWS credentials

`send_report_email.py` uses the standard boto3 credential chain. The
simplest one-time setup:

```powershell
pip install awscli   # if you don't already have the AWS CLI
aws configure
```

You'll be prompted for an Access Key ID, Secret Access Key, default
region (e.g. `us-east-1`), and output format. These are stored in
`%USERPROFILE%\.aws\credentials` and `%USERPROFILE%\.aws\config`.
Alternatively, set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_DEFAULT_REGION` as environment variables.

The IAM user/role needs at minimum the `ses:SendRawEmail` permission.

### SES sender/recipient verification

New SES accounts start in the **sandbox**, which restricts you to:

1. **Verified sender identities only.** In the SES console (or via
   `aws ses verify-email-identity --email-address reports@globaltel.com`),
   verify the `--from` address (or the whole domain, which also lets you
   use any address `@yourdomain.com` as a sender). You'll get a
   confirmation email/link to click.
2. **Verified recipient addresses only**, while still in the sandbox.
   Every `--to`/`--cc` address must also be verified the same way until
   you request production access.
3. **Request production access** (SES console → *Account dashboard* →
   *Request production access*) once you're ready to send to arbitrary
   recipients without verifying each one. This typically requires a short
   use-case description and is approved within a day or so.

If you see a `MessageRejected` error mentioning an unverified address,
that's the sandbox restriction — verify the address or request production
access.

## Notes on log format

All three scripts share the same parser (`iis_report_lib.parse_iis_log`),
which reads the `#Fields:` header line(s) to determine column layout, so
it works with IIS's default field set or a customized one. It also
handles:

- Multiple `#Fields:` blocks concatenated in one file (log rollovers
  merged together)
- Gzip-compressed logs (`.log.gz`)
- A folder or glob pattern as input, combining multiple files into one
  report (`python analyze_iis_log.py .` or `"u_ex2607*.log"`)

### Reverse proxy / X-Forwarded-For

If the site sits behind a reverse proxy or load balancer, `c-ip` will be
the same proxy address on every line and isn't useful for client
analysis. When an `X-Forwarded-For` field is present, all three reports
detect this automatically and use the left-most (original client) address
from `X-Forwarded-For` instead — this is called out explicitly in the
console output.

### Custom error page redirects

When IIS redirects a failed request to a configured custom error page
(e.g. `/error.htm`), it stows the original status and URL in
`cs-uri-query` as `STATUS;http://host:port/original/path` - the referer is
empty since it's a server-side redirect, not a browser navigation. The
HTML/email reports parse this automatically and add a "Pages That
Redirected to a Custom Error Page" table showing what actually 404'd,
distinct from raw hit counts on the error page itself.

## Troubleshooting

- **`ModuleNotFoundError`** — the venv isn't activated, or setup didn't
  finish; re-run `setup_venv.ps1`/`.bat` and activate before running
  scripts.
- **No charts in the HTML/email report** — a chart is skipped silently if
  its underlying data is empty (e.g. no errors in the log means no "top
  error pages" chart). This is expected, not a bug.
- **SES `MessageRejected` / address not verified** — see the SES
  verification steps above.
- **`NoCredentialsError`** — run `aws configure` or set the `AWS_*`
  environment variables.
