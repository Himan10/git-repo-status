#!/usr/bin/env bash
# One command to run Repo Status on macOS and Linux (Windows: scan.cmd).
#
#   ./scan.sh check                         check that everything is installed
#   ./scan.sh <account or org> [options]    scan every repository
#   ./scan.sh <account or org> deep <repo>  investigate one flagged repository
#   ./scan.sh <account or org> uses <owner/action> [--since YYYY-MM-DD] [--until YYYY-MM-DD]
#
# The work is done by scan.py, so every operating system behaves the same.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v uv >/dev/null; then
  if [ "$(uname)" = "Darwin" ]; then
    echo "Missing: uv. Install it with:  brew install uv"
  else
    echo "Missing: uv. Install it: see https://docs.astral.sh/uv/getting-started/installation/"
  fi
  exit 1
fi
exec uv run -q --python 3.12 --with pyyaml --with zizmor==1.32.0 scan.py "$@"
