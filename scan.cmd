@echo off
rem Repo Status launcher for Windows (Command Prompt or PowerShell). macOS/Linux: use scan.sh.
rem   scan.cmd check
rem   scan.cmd ACCOUNT-OR-ORG [options]
rem   scan.cmd ACCOUNT-OR-ORG deep REPO
rem   scan.cmd ACCOUNT-OR-ORG uses OWNER/ACTION [--since YYYY-MM-DD] [--until YYYY-MM-DD]
rem zizmor is pinned here, in scan.sh and in repostatus\zizmor.py (a test checks they agree).
setlocal
where uv >nul 2>nul
if errorlevel 1 (
  echo Missing: uv. Install it with:  winget install --id astral-sh.uv -e
  echo Then close and reopen this window.
  exit /b 1
)
uv run -q --python 3.12 --with pyyaml --with zizmor==1.32.0 "%~dp0scan.py" %*
exit /b %ERRORLEVEL%
