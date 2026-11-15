@echo off
rem One command to run Repo Status on Windows (macOS and Linux: ./scan.sh).
rem
rem   scan check                         check that everything is installed
rem   scan ^<account or org^> [options]    scan every repository
rem   scan ^<account or org^> deep ^<repo^>  investigate one flagged repository
rem   scan ^<account or org^> uses ^<owner/action^> [--since YYYY-MM-DD]  who uses an action
rem
rem Works from Command Prompt and PowerShell. The work is done by scan.py.
setlocal
cd /d "%~dp0"
where uv >nul 2>nul
if errorlevel 1 (
  echo Missing: uv. Install it with:  winget install --id astral-sh.uv
  exit /b 1
)
uv run -q --python 3.12 --with pyyaml --with zizmor==1.32.0 scan.py %*
exit /b %errorlevel%
