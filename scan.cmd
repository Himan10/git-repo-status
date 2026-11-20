@echo off
rem Repo Status launcher for Windows (Command Prompt or PowerShell). macOS/Linux: use scan.sh.
rem   scan.cmd check
rem   scan.cmd ACCOUNT-OR-ORG [options]          scan every repository
rem   scan.cmd ACCOUNT-OR-ORG report [options]   rebuild the report from the last scan
rem   scan.cmd ACCOUNT-OR-ORG deep REPO          investigate one repository
rem   scan.cmd ACCOUNT-OR-ORG uses OWNER/ACTION [--since YYYY-MM-DD] [--until YYYY-MM-DD]
rem Python and package versions live in pyproject.toml; uv.lock pins exact versions and checksums.
setlocal
where uv >nul 2>nul
if errorlevel 1 (
  echo Missing: uv. Install it with:  winget install --id astral-sh.uv -e
  echo Then close and reopen this window.
  exit /b 1
)
rem Use the Windows certificate store, so uv's downloads work behind a company proxy that inspects HTTPS.
rem Set UV_NATIVE_TLS=0 before running to turn this off.
if not defined UV_NATIVE_TLS set UV_NATIVE_TLS=1
rem "%~dp0." not "%~dp0": a trailing backslash before the closing quote would escape it
uv run --quiet --locked --directory "%~dp0." python -m repostatus %*
exit /b %ERRORLEVEL%
