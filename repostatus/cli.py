"""Repo Status commands, shared by scan.sh (macOS/Linux) and scan.cmd (Windows).

  scan check                          check that everything is installed
  scan <account or org> [options]     scan every repository
  scan <account or org> report [...]  rebuild the report from the last scan (no API calls), e.g. with
                                      other thresholds: report --dormant-days 60
  scan <account or org> deep <repo>   investigate one repository
  scan <account or org> uses <owner/action> [--since YYYY-MM-DD] [--until YYYY-MM-DD]
                                      which repos use an action, and did it run in that window

Options for a scan: --skip-forks  --skip-archived  --repo NAME (repeatable)
                    --dead-days N  --dormant-days N  --ignore-rate-limit
                    --no-zizmor  --no-online-audits  --skip-action-check  --skip-branches  --max-branches N
                    --resume (continue a scan that stopped)
"""
import os
import platform
import subprocess
import sys
import unittest

from repostatus.collect import zizmor_runner
from repostatus.github.api_client import gh_path
from repostatus.output_paths import PROJECT_ROOT

os.chdir(PROJECT_ROOT)  # results go to out/ at the project root, wherever the command was started

WINDOWS = platform.system() == "Windows"
LAUNCHER = "scan.cmd" if WINDOWS else "./scan.sh"
INSTALL_GH = {
    "Windows": "winget install --id GitHub.cli -e   (then close and reopen the window)",
    "Darwin": "brew install gh",
}.get(platform.system(), "see https://github.com/cli/cli#installation")

# Console output on older Windows terminals may not handle every character; never crash on printing
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(errors="replace")
    except AttributeError:
        pass


def usage():
    print(__doc__.replace("scan ", LAUNCHER + " ").strip())
    sys.exit(1)


def check_gh():
    gh = gh_path()
    if not gh:
        sys.exit(f"Missing: GitHub CLI (gh). Install it with:  {INSTALL_GH}")
    if gh.lower().endswith((".cmd", ".bat")):
        sys.exit(f"gh was found as a batch file ({gh}). Batch files break on '&' in arguments.\n"
                 f"Install the regular gh program with:  {INSTALL_GH}")
    if not os.environ.get("GH_TOKEN"):
        ok = subprocess.run([gh, "auth", "status"], capture_output=True).returncode == 0
        if not ok:
            sys.exit("Not logged in to GitHub. Run:  gh auth login   "
                     "(choose GitHub.com, HTTPS, log in with a web browser)")
    return gh


def self_test():
    suite = unittest.defaultTestLoader.discover(os.path.join(PROJECT_ROOT, "tests"))
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        result = unittest.TextTestRunner(stream=devnull, verbosity=0).run(suite)
    if result.wasSuccessful():
        return f"passed ({result.testsRun} tests)"
    return f"FAILED ({len(result.failures) + len(result.errors)} of {result.testsRun} tests)"


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        usage()
    gh = check_gh()

    if args[0] == "check":
        version = subprocess.run([gh, "--version"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace").stdout.splitlines()[0]
        login = subprocess.run([gh, "api", "user", "--jq", ".login"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace").stdout.strip()
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"GitHub CLI: {version}")
        print(f"Python: {platform.python_version()}")
        print(f"Logged in to GitHub as: {login or 'unknown (check gh auth status)'}")
        try:
            from repostatus.github.api_client import GitHub
            rl = GitHub().rate_limit()
            note = ("Enterprise Cloud app limit" if rl["limit"] >= 15000 else
                    "personal limit; see Rate Limits in the wiki for 15,000" if rl["limit"] else "could not be read")
            print(f"GitHub API allowance: {rl['remaining']:,} of {rl['limit']:,} per hour left ({note})")
        except (OSError, ValueError):
            print("GitHub API allowance: could not be read")
        exe = zizmor_runner.find()
        zv = zizmor_runner.version(exe) if exe else None
        print(f"zizmor: {zv}" if zv == zizmor_runner.VERSION else
              f"zizmor: {zv or 'not found'} (expected {zizmor_runner.VERSION}; start with {LAUNCHER})")
        print(f"Self-test: {self_test()}")
        return

    owner, rest = args[0], args[1:]
    if rest and rest[0] == "deep":
        if len(rest) < 2:
            sys.exit(f"Which repository? Example: {LAUNCHER} {owner} deep my-repo")
        from repostatus import deep_dive
        sys.argv = ["deep_dive.py", "--owner", owner, "--repo", rest[1], *rest[2:]]
        deep_dive.main()
        return

    from repostatus import scan_org
    if rest and rest[0] == "report":
        sys.argv = ["scan_org", "report", "--owner", owner, *rest[1:]]
        scan_org.main()
        return
    if rest and rest[0] == "uses":
        if len(rest) < 2:
            sys.exit(f"Which action? Example: {LAUNCHER} {owner} uses aquasecurity/trivy-action --since 2026-03-19")
        sys.argv = ["scan_org", "uses", "--owner", owner, "--action", rest[1], *rest[2:]]
        scan_org.main()
        return
    sys.argv = ["scan_org", "all", "--owner", owner, *rest]
    scan_org.main()


if __name__ == "__main__":
    main()
