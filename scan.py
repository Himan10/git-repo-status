"""One command to run Repo Status, the same on macOS, Linux and Windows.

  scan check                          check that everything is installed
  scan <account or org> [options]     scan every repository
  scan <account or org> deep <repo>   investigate one flagged repository
  scan <account or org> uses <owner/action> [--since YYYY-MM-DD] [--until YYYY-MM-DD]
                                      which repos use an action, and did it run in that window

Options for a scan: --skip-forks  --skip-archived  --repo NAME (repeatable)
                    --dead-days N  --dormant-days N  --ignore-rate-limit
                    --no-zizmor  --skip-action-check

Start it with ./scan.sh on macOS and Linux, or scan (scan.cmd) on Windows.
"""
import io
import os
import shutil
import subprocess
import sys
import unittest

from repostatus import zizmor
from repostatus.oscompat import scan_cmd, utf8_console

HERE = os.path.dirname(os.path.abspath(__file__))

INSTALL = {
    "gh": {"darwin": "brew install gh",
           "win32": "winget install --id GitHub.cli",
           "linux": "see https://github.com/cli/cli#installation (apt, dnf, ...)"},
}


def _platform():
    return "darwin" if sys.platform == "darwin" else "win32" if sys.platform == "win32" else "linux"


def _gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, encoding="utf-8", errors="replace")


def check():
    """True when gh is installed and logged in (uv is already running this script)."""
    if not shutil.which("gh"):
        print(f"Missing: GitHub CLI (gh). Install it with:  {INSTALL['gh'][_platform()]}")
        return False
    if not os.environ.get("GH_TOKEN") and _gh("auth", "status").returncode != 0:
        print("Not logged in to GitHub. Run:  gh auth login   "
              "(choose GitHub.com, HTTPS, log in with a web browser)")
        return False
    return True


def self_test():
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(os.path.join(HERE, "tests"))
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    if result.wasSuccessful():
        return f"passed ({result.testsRun} tests)"
    return (f"FAILED ({len(result.failures)} failures, {len(result.errors)} errors). "
            f"Details:\n{stream.getvalue()}")


def show_check():
    uv = shutil.which("uv")
    print(f"GitHub CLI: {_gh('--version').stdout.splitlines()[0]}")
    print(f"uv: {subprocess.run([uv, '--version'], capture_output=True, encoding='utf-8').stdout.strip()}"
          if uv else "uv: running, but not on PATH")
    print(f"Logged in to GitHub as: {_gh('api', 'user', '--jq', '.login').stdout.strip()}")
    exe = zizmor.find()
    v = zizmor.version(exe) if exe else None
    print(f"zizmor: {v}" if v == zizmor.VERSION else
          f"zizmor: {'not found' if not v else v} (expected {zizmor.VERSION}; start with scan.sh or scan.cmd)")
    print(f"Self-test: {self_test()}")


def main(argv):
    utf8_console()
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 1
    if not check():
        return 1
    if argv[0] == "check":
        show_check()
        return 0
    owner, rest = argv[0], argv[1:]
    if rest[:1] == ["deep"]:
        if len(rest) < 2:
            print(f"Which repository? Example: {scan_cmd()} {owner} deep my-repo")
            return 1
        import deep_dive
        deep_dive.main(["--owner", owner, "--repo", rest[1], *rest[2:]])
        return 0
    import run
    if rest[:1] == ["uses"]:
        if len(rest) < 2:
            print(f"Which action? Example: {scan_cmd()} {owner} uses aquasecurity/trivy-action --since 2026-03-19")
            return 1
        run.main(["uses", "--owner", owner, "--action", rest[1], *rest[2:]])
        return 0
    run.main(["all", "--owner", owner, *rest])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
