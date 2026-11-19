#!/usr/bin/env bash
# Repo Status launcher for macOS and Linux. Windows: use scan.cmd.
#   ./scan.sh check | ./scan.sh <account or org> [options] | ./scan.sh <account or org> deep <repo>
#   ./scan.sh <account or org> uses <owner/action> [--since YYYY-MM-DD] [--until YYYY-MM-DD]
# zizmor is pinned here, in scan.cmd and in repostatus/zizmor.py (a test checks they agree).
if ! command -v uv >/dev/null; then
  echo "Missing: uv. Install it with:  brew install uv   (Linux: curl -LsSf https://astral.sh/uv/install.sh | sh)"
  exit 1
fi
exec uv run -q --python 3.12 --with pyyaml --with zizmor==1.32.0 "$(dirname "$0")/scan.py" "$@"
