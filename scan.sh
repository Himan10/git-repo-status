#!/usr/bin/env bash
# Repo Status launcher for macOS and Linux. Windows: use scan.cmd.
#   ./scan.sh check
#   ./scan.sh <account or org> [options]          scan every repository
#   ./scan.sh <account or org> report [options]   rebuild the report from the last scan
#   ./scan.sh <account or org> deep <repo>        investigate one repository
#   ./scan.sh <account or org> uses <owner/action> [--since YYYY-MM-DD] [--until YYYY-MM-DD]
# Python and package versions live in pyproject.toml; uv.lock pins exact versions and checksums.
if ! command -v uv >/dev/null; then
  echo "Missing: uv. Install it with:  brew install uv   (Linux: curl -LsSf https://astral.sh/uv/install.sh | sh)"
  exit 1
fi
exec uv run --quiet --locked --directory "$(dirname "$0")" python -m repostatus "$@"
