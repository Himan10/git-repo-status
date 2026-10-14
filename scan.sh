#!/usr/bin/env bash
# Repo Status launcher for macOS and Linux. Windows: use scan.cmd.
#   ./scan.sh check | ./scan.sh <account or org> [options] | ./scan.sh <account or org> deep <repo>
if ! command -v uv >/dev/null; then
  echo "Missing: uv. Install it with:  brew install uv   (Linux: curl -LsSf https://astral.sh/uv/install.sh | sh)"
  exit 1
fi
exec uv run -q --python 3.12 --with pyyaml "$(dirname "$0")/scan.py" "$@"
