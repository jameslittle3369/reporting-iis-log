# setup_venv.ps1
# One-time environment setup for the IIS log reporting tools.
# Run from this folder:
#   powershell -ExecutionPolicy Bypass -File .\setup_venv.ps1

$ErrorActionPreference = "Stop"

Write-Host "Creating virtual environment in .\venv ..."
python -m venv venv

Write-Host "Upgrading pip ..."
.\venv\Scripts\python.exe -m pip install --upgrade pip

Write-Host "Installing requirements.txt (pandas, matplotlib, boto3) ..."
.\venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host ""
Write-Host "Done. Activate the environment with:"
Write-Host "  .\venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "Then run, for example:"
Write-Host "  python analyze_iis_log.py u_ex260718.log"
Write-Host "  python generate_html_report.py u_ex260718.log --open"
Write-Host "  python send_report_email.py u_ex260718.log --to you@example.com --from reports@example.com --dry-run"
