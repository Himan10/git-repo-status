@echo off
rem Repo Status launcher for Windows (Command Prompt or PowerShell). macOS/Linux: use scan.sh.
rem   scan.cmd check
rem   scan.cmd ACCOUNT-OR-ORG [options]
rem   scan.cmd ACCOUNT-OR-ORG deep REPO
setlocal
where uv >nul 2>nul
if errorlevel 1 (
  echo Missing: uv. Install it with:  winget install --id astral-sh.uv -e
  echo Then close and reopen this window.
  exit /b 1
)
uv run -q --python 3.12 --with pyyaml "%~dp0scan.py" %*
exit /b %ERRORLEVEL%
