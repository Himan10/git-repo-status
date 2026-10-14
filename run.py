"""GitHub repository status: dead repos, Actions, branch rules, CODEOWNERS, images,
and history-tampering signals. Read-only.

  uv run --python 3.12 --with pyyaml run.py collect --owner acme-corp
  uv run --python 3.12 --with pyyaml run.py report  --owner acme-corp [--dead-days 365 ...]
"""
import argparse
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from repostatus.ghapi import ApiError, GitHub
from repostatus import flags, report
from repostatus.collect import collect_repo, owner_context

HERE = os.path.dirname(os.path.abspath(__file__))
CALLS_PER_REPO = 15  # measured: about 12 per repo plus 2 to 3 per workflow


def display_path(path):
    """Path relative to the current folder when possible (fails across Windows drives)."""
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def out_dir(owner, create=True):
    """Results folder for an owner. Names are matched without regard to case, so
    'acme-corp' finds out/ACME-Corp on any operating system."""
    base = os.path.join(HERE, "out")
    if os.path.isdir(base):
        for name in os.listdir(base):
            if name.lower() == owner.lower() and os.path.isdir(os.path.join(base, name)):
                return os.path.join(base, name)
    d = os.path.join(base, owner)
    if create:
        os.makedirs(d, exist_ok=True)
    return d


def cmd_collect(a):
    gh = GitHub()
    ctx = owner_context(gh, a.owner)
    a.owner = ctx["owner"]
    d = out_dir(a.owner)
    raw = os.path.join(d, "raw")

    def recorder_for(repo):
        rd = os.path.join(raw, repo)
        os.makedirs(rd, exist_ok=True)

        def rec(name, data):
            with open(os.path.join(rd, f"{name}.json"), "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1)
        return rec

    allrepos = ctx.pop("repos")
    repos = [r for r in allrepos
             if (not a.repo or r["name"] in a.repo)
             and not (a.skip_forks and r.get("fork"))
             and not (a.skip_archived and r.get("archived"))]
    forks = sum(1 for r in allrepos if r.get("fork"))
    kind = "organisation" if ctx["type"] == "Organization" else (
        "your own account (public and private repos you own)" if a.owner.lower() == ctx["viewer"].lower()
        else "someone else's account (public repos only)")
    print(f"{a.owner}: {kind}. {len(allrepos)} repos found ({forks} forks); scanning {len(repos)}.",
          file=sys.stderr)
    print(f"Organisation audit log: {ctx['audit_log']}", file=sys.stderr)

    # GitHub allows a fixed number of API calls per hour; check before starting
    need = len(repos) * CALLS_PER_REPO
    core = gh.rate_limit()
    reset = datetime.fromtimestamp(core["reset"]).strftime("%H:%M")
    print(f"Estimated API calls: about {need}. Available this hour: {core['remaining']} of {core['limit']}.",
          file=sys.stderr)
    if need > core["remaining"] and not a.ignore_rate_limit:
        sys.exit(f"\nNot enough API calls left this hour (limit resets at {reset}).\n"
                 f"Options: wait until {reset}; scan fewer repos with --skip-forks or --repo NAME; "
                 f"or add --ignore-rate-limit to try anyway (some repos may then show errors).")

    done = [0]
    lock = threading.Lock()

    def one(meta):
        f = collect_repo(gh, a.owner, meta, recorder_for)
        with lock:
            done[0] += 1
            state = "errors: " + "; ".join(f["errors"]) if f["errors"] else "ok"
            print(f"  [{done[0]}/{len(repos)}] {meta['name']}: {state}", file=sys.stderr)
        return f

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        facts = list(ex.map(one, repos))
    ctx["collected_at"] = datetime.now(timezone.utc).isoformat()
    ctx["api_calls"] = gh.calls
    with open(os.path.join(d, "facts.json"), "w", encoding="utf-8") as fh:
        json.dump({"context": ctx, "repos": facts}, fh, indent=1)
    print(f"Done: {gh.calls} API calls. Facts saved to {d}/facts.json", file=sys.stderr)


def cmd_report(a):
    d = out_dir(a.owner, create=False)
    path = os.path.join(d, "facts.json")
    if not os.path.exists(path):
        sys.exit(f"No collected data for {a.owner}. Run the scan first (./scan.sh {a.owner}).")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    ctx = data["context"]
    now = datetime.fromisoformat(ctx["collected_at"])
    cfg = {k: getattr(a, k) for k in flags.DEFAULTS if getattr(a, k, None) is not None}
    rows, cfg = flags.evaluate(data["repos"], ctx, now, cfg)
    report.write_csv(os.path.join(d, "repo-status.csv"), rows, now)
    report.write_summary(os.path.join(d, "summary.md"), ctx, rows, cfg, now, ctx.get("api_calls"))
    rel = display_path(d)
    print(f"\nResults:\n  {rel}/summary.md        (read this first)\n  {rel}/repo-status.csv   (open in Excel)",
          file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("collect", "report", "all"):
        s = sub.add_parser(name)
        s.add_argument("--owner", required=True, help="organisation or user")
        if name in ("collect", "all"):
            s.add_argument("--repo", action="append", help="limit to these repos (repeatable)")
            s.add_argument("--workers", type=int, default=4)
            s.add_argument("--skip-forks", action="store_true", help="leave out forks")
            s.add_argument("--skip-archived", action="store_true", help="leave out archived repos")
            s.add_argument("--ignore-rate-limit", action="store_true", help="start even if the hourly API limit may run out")
        if name in ("report", "all"):
            for k, v in flags.DEFAULTS.items():
                s.add_argument("--" + k.replace("_", "-"), dest=k, type=type(v), default=None, help=f"default {v}")
    a = p.parse_args()
    try:
        if a.cmd in ("collect", "all"):
            cmd_collect(a)
        if a.cmd in ("report", "all"):
            cmd_report(a)
    except ApiError as e:
        if e.path.startswith("users/") and e.status == "404":
            sys.exit(f"GitHub account or organisation '{a.owner}' not found. Check the spelling.")
        sys.exit(f"GitHub API error: {e}")


if __name__ == "__main__":
    main()
