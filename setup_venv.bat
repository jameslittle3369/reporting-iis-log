@echo off
REM setup_venv.bat
REM One-time environment setup for the IIS log reporting tools.
REM Run from this folder: setup_venv.bat

echo Creating virtual environment in .\venv ...
python -m venv venv
if errorlevel 1 goto :error

echo Upgrading pip ...
.\venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto :error

echo Installing requirements.txt (pandas, matplotlib, boto3) ...
.\venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo.
echo Done. Activate the environment with:
echo   .\venv\Scripts\activate.bat
echo.
echo Then run, for example:
echo   python analyze_iis_log.py u_ex260718.log
echo   python generate_html_report.py u_ex260718.log --open
echo   python send_report_email.py u_ex260718.log --to you@example.com --from reports@example.com --dry-run
goto :eof

:error
echo Setup failed. See error output above.
exit /b 1
