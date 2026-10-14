"""Repo Status launcher, shared by scan.sh (macOS/Linux) and scan.cmd (Windows).

  scan check                        check that everything is installed
  scan <account or org> [options]   scan every repository
  scan <account or org> deep <repo> investigate one flagged repository

Options for a scan: --skip-forks  --skip-archived  --repo NAME (repeatable)
                    --dead-days N  --dormant-days N  --ignore-rate-limit
"""
import os
import platform
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

from repostatus.ghapi import gh_path  # noqa: E402

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
    suite = unittest.defaultTestLoader.discover(os.path.join(HERE, "tests"))
    result = unittest.TextTestRunner(stream=open(os.devnull, "w"), verbosity=0).run(suite)
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
        print(f"Self-test: {self_test()}")
        return

    owner, rest = args[0], args[1:]
    if rest and rest[0] == "deep":
        if len(rest) < 2:
            sys.exit(f"Which repository? Example: {LAUNCHER} {owner} deep my-repo")
        import deep_dive
        sys.argv = ["deep_dive.py", "--owner", owner, "--repo", rest[1]]
        deep_dive.main()
        return

    import run
    sys.argv = ["run.py", "all", "--owner", owner, *rest]
    run.main()


if __name__ == "__main__":
    main()
