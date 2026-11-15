"""GitHub repository status: dead repos, Actions, branch rules, CODEOWNERS, images,
history-tampering signals and workflow security (with zizmor). Read-only.

  uv run --python 3.12 --with pyyaml --with zizmor==1.32.0 run.py collect --owner acme-corp
  uv run --python 3.12 --with pyyaml run.py report  --owner acme-corp [--dead-days 365 ...]
  uv run --python 3.12 --with pyyaml run.py uses    --owner acme-corp --action aquasecurity/trivy-action \
      [--since 2026-03-19 --until 2026-03-20]
"""
import argparse
import json
import os
import re
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from repostatus.ghapi import ApiError, GitHub
from repostatus import flags, report, zizmor
from repostatus.collect import action_index, all_uses, collect_repo, owner_context
from repostatus.oscompat import scan_cmd, utf8_console

HERE = os.path.dirname(os.path.abspath(__file__))
CALLS_PER_REPO = 18  # about 15 per repo plus 2 to 3 per workflow; zizmor itself makes none (runs offline)
UNSAFE_NAME = re.compile(r'[<>:"\\|?*\x00-\x1f]')  # characters Windows does not allow in file names


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


def make_saver(base):
    """save(path, text) writing a repo's files under base, byte for byte (zizmor reports line numbers).
    Starts from an empty folder so files deleted upstream do not linger from an earlier scan."""
    shutil.rmtree(base, ignore_errors=True)

    def save(path, text):
        parts = path.split("/")
        if any(p in ("", ".", "..") or UNSAFE_NAME.search(p) for p in parts):
            return False  # never write outside the folder; skip names Windows cannot store
        target = os.path.join(base, *parts)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return True
    return save


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

    wf_root = os.path.join(d, "workflows")

    def files_for(repo):
        return make_saver(os.path.join(wf_root, repo))

    zz_exe, zz_version, zz_status = None, None, "not run (--no-zizmor)"
    if not a.no_zizmor:
        zz_exe = zizmor.find()
        zz_version = zizmor.version(zz_exe) if zz_exe else None
        if not zz_exe:
            zz_status = "not run: zizmor not found (start Repo Status with scan.sh or scan.cmd, which install it)"
        elif zz_version != zizmor.VERSION:
            zz_status, zz_exe = f"not run: found zizmor {zz_version}, Repo Status expects {zizmor.VERSION}", None
        else:
            zz_status = "ok"
    ctx["zizmor"] = {"version": zz_version, "status": zz_status}

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
    print(f"zizmor: {'v' + zz_version + ', offline (no token, no network)' if zz_exe else zz_status}",
          file=sys.stderr)

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
        f = collect_repo(gh, a.owner, meta, recorder_for, files_for)
        if zz_exe and "history" in f and not f.get("empty"):
            f["zizmor"] = zizmor.run(zz_exe, os.path.join(wf_root, meta["name"]),
                                     raw_path=os.path.join(d, "zizmor", f"{meta['name']}.json"))
            if f["zizmor"]["status"] != "ok":
                f["errors"].append(f"zizmor: {f['zizmor']['status']}")
        else:
            f["zizmor"] = {"status": zz_status, "findings": []}
        with lock:
            done[0] += 1
            state = "errors: " + "; ".join(f["errors"]) if f["errors"] else "ok"
            print(f"  [{done[0]}/{len(repos)}] {meta['name']}: {state}", file=sys.stderr)
        return f

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        facts = list(ex.map(one, repos))
    if not a.skip_action_check:
        before = gh.calls
        print("Checking the upstream actions these repos use (once per action)...", file=sys.stderr)
        ctx["action_index"] = action_index(gh, facts, a.workers)
        print(f"  {len(ctx['action_index']['repos'])} actions, {len(ctx['action_index']['tags'])} tags: "
              f"{gh.calls - before} API calls", file=sys.stderr)
    ctx["collected_at"] = datetime.now(timezone.utc).isoformat()
    ctx["api_calls"] = gh.calls
    with open(os.path.join(d, "facts.json"), "w", encoding="utf-8") as fh:
        json.dump({"context": ctx, "repos": facts}, fh, indent=1)
    print(f"Done: {gh.calls} API calls. Facts saved to {os.path.join(d, 'facts.json')}", file=sys.stderr)


def cmd_report(a):
    d = out_dir(a.owner, create=False)
    path = os.path.join(d, "facts.json")
    if not os.path.exists(path):
        sys.exit(f"No collected data for {a.owner}. Run the scan first ({scan_cmd()} {a.owner}).")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    ctx = data["context"]
    now = datetime.fromisoformat(ctx["collected_at"])
    cfg = {k: getattr(a, k) for k in flags.DEFAULTS if getattr(a, k, None) is not None}
    rows, cfg = flags.evaluate(data["repos"], ctx, now, cfg)
    report.write_csv(os.path.join(d, "repo-status.csv"), rows, now)
    report.write_inventory(os.path.join(d, "actions-inventory.csv"), rows, ctx)
    report.write_summary(os.path.join(d, "summary.md"), ctx, rows, cfg, now, ctx.get("api_calls"),
                         generated=datetime.now(timezone.utc))
    rel = os.path.relpath(d)
    print(f"\nResults:\n  {os.path.join(rel, 'summary.md')}        (read this first)\n"
          f"  {os.path.join(rel, 'repo-status.csv')}   (open in Excel)\n"
          f"  {os.path.join(rel, 'actions-inventory.csv')}   (every action used, and where)",
          file=sys.stderr)


def _load(owner):
    d = out_dir(owner, create=False)
    path = os.path.join(d, "facts.json")
    if not os.path.exists(path):
        sys.exit(f"No collected data for {owner}. Run the scan first ({scan_cmd()} {owner}).")
    with open(path, encoding="utf-8") as fh:
        return d, json.load(fh)


def _lock_paths(lock, target):
    """Lockfile entries that run target, directly or through other actions: {workflow path: via}."""
    deps = lock.get("dependencies") or {}

    def reaches(key, seen=()):
        d = deps.get(key) or {}
        if d.get("slug") == target or d.get("target", "").lower() == target:
            return key
        for sub in d.get("uses") or []:
            if sub not in seen and reaches(sub, seen + (key,)):
                return key
        return None
    out = {}
    for path, keys in (lock.get("workflows") or {}).items():
        for k in keys:
            if reaches(k) and (deps.get(k) or {}).get("slug") != target:
                out[path] = f"through {k} (actions.lock)"
    return out


def cmd_uses(a):
    """Which repos use an action, and (with --since) did those workflows run in a time window."""
    d, data = _load(a.owner)
    owner = data["context"]["owner"]
    target = a.action.lower().split("@")[0].rstrip("/")
    hits = []
    for f in data["repos"]:
        items = {w["path"]: w for w in (f.get("actions") or {}).get("items") or []}
        for path, u in all_uses(f):
            if u.get("slug") and (u["slug"] == target or u["target"].lower() == target):
                hits.append({"repo": f["repo"], "path": path, "ref": u["ref"], "where": u.get("where", ""),
                             "via": "direct", "wf": items.get(path)})
        for path, via in _lock_paths((f.get("actions") or {}).get("lockfile") or {}, target).items():
            hits.append({"repo": f["repo"], "path": path, "ref": "", "where": "", "via": via, "wf": items.get(path)})
    since, until = a.since, a.until or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    L = [f"# Who uses {target} in {owner}\n",
         f"From the scan of {data['context']['collected_at'][:10]} (default branch, as it was then). "
         f"{len({h['repo'] for h in hits})} repo(s), {len(hits)} place(s).\n"]
    if since:
        L.append(f"Runs between {since} and {until} (UTC), from the GitHub API.\n")
        gh = GitHub()
    L.append("| Repo | File | Ref | Step | How | Runs in window |\n|---|---|---|---|---|---|")
    run_lines = []
    for h in sorted(hits, key=lambda h: (h["repo"].lower(), h["path"])):
        runs = "-"
        if since and h["wf"] and h["path"].startswith(".github/workflows/"):
            pages, err = gh.try_get(f"repos/{owner}/{h['repo']}/actions/workflows/{h['wf']['id']}/runs"
                                    f"?created={since}..{until}&per_page=100", paginate=True)
            found = [r for p in pages or [] for r in (p.get("workflow_runs") or [])]
            runs = f"error: {err}" if err else str(len(found))
            run_lines += [f"- {h['repo']} {h['path']}: {r['created_at']} {r['event']} {r.get('conclusion')} "
                          f"{r['html_url']}" for r in found]
        elif since:
            runs = "n/a (composite action: see the workflows that call it)"
        L.append(f"| {h['repo']} | {h['path']} | {h['ref']} | {h['where']} | {h['via']} | {runs} |")
    if run_lines:
        L += ["\n## Runs\n"] + run_lines
    text = "\n".join(L) + "\n"
    os.makedirs(os.path.join(d, "uses"), exist_ok=True)
    path = os.path.join(d, "uses", re.sub(r"[^A-Za-z0-9_.-]+", "_", target) + ".md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    print(f"Saved: {os.path.relpath(path)}", file=sys.stderr)


def main(argv=None):
    utf8_console()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("uses", help="which repos use an action (incident lookup)")
    u.add_argument("--owner", required=True)
    u.add_argument("--action", required=True, help="owner/repo of the action, e.g. aquasecurity/trivy-action")
    u.add_argument("--since", help="YYYY-MM-DD: also list workflow runs from this date")
    u.add_argument("--until", help="YYYY-MM-DD (default: today)")
    for name in ("collect", "report", "all"):
        s = sub.add_parser(name)
        s.add_argument("--owner", required=True, help="organisation or user")
        if name in ("collect", "all"):
            s.add_argument("--repo", action="append", help="limit to these repos (repeatable)")
            s.add_argument("--workers", type=int, default=4)
            s.add_argument("--skip-forks", action="store_true", help="leave out forks")
            s.add_argument("--skip-archived", action="store_true", help="leave out archived repos")
            s.add_argument("--ignore-rate-limit", action="store_true", help="start even if the hourly API limit may run out")
            s.add_argument("--no-zizmor", action="store_true", help="do not run zizmor")
            s.add_argument("--skip-action-check", action="store_true",
                           help="do not look up the upstream actions repos use (saves API calls)")
        if name in ("report", "all"):
            for k, v in flags.DEFAULTS.items():
                s.add_argument("--" + k.replace("_", "-"), dest=k, type=type(v), default=None, help=f"default {v}")
    a = p.parse_args(argv)
    try:
        if a.cmd == "uses":
            cmd_uses(a)
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
