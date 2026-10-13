#!/usr/bin/env bash
# One command to run Repo Status.
#
#   ./scan.sh check                       check that everything is installed
#   ./scan.sh <account or org> [options]  scan every repository
#   ./scan.sh <account or org> deep <repo>  investigate one flagged repository
#
# Options for a scan: --skip-forks  --skip-archived  --repo NAME (repeatable)
#                     --dead-days N  --dormant-days N  --ignore-rate-limit
set -euo pipefail
cd "$(dirname "$0")"

UV_RUN=(uv run -q --python 3.12 --with pyyaml)

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

check() {
  local ok=1
  if ! command -v gh >/dev/null; then
    echo "Missing: GitHub CLI (gh). Install it with:  brew install gh"; ok=0
  fi
  if ! command -v uv >/dev/null; then
    echo "Missing: uv. Install it with:  brew install uv"; ok=0
  fi
  if [ "$ok" = 1 ] && [ -z "${GH_TOKEN:-}" ] && ! gh auth status >/dev/null 2>&1; then
    echo "Not logged in to GitHub. Run:  gh auth login   (choose GitHub.com, HTTPS, log in with a web browser)"; ok=0
  fi
  [ "$ok" = 1 ] || exit 1
}

[ $# -ge 1 ] || usage
case "$1" in -h|--help|help) usage ;; esac

check
if [ "$1" = "check" ]; then
  echo "GitHub CLI: $(gh --version | head -1)"
  echo "uv: $(uv --version)"
  echo "Logged in to GitHub as: $(gh api user --jq .login)"
  "${UV_RUN[@]}" python -m unittest discover -s tests 2>&1 | tail -1 | sed 's/^OK$/Self-test: passed/'
  exit 0
fi

OWNER="$1"; shift
if [ "${1:-}" = "deep" ]; then
  [ -n "${2:-}" ] || { echo "Which repository? Example: ./scan.sh $OWNER deep my-repo"; exit 1; }
  exec "${UV_RUN[@]}" deep_dive.py --owner "$OWNER" --repo "$2"
fi
exec "${UV_RUN[@]}" run.py all --owner "$OWNER" "$@"
