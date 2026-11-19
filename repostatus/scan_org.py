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
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from repostatus.checks import repository_checks
from repostatus.collect import zizmor_runner
from repostatus.collect.repository_facts import action_index, all_uses, collect_repo, owner_context
from repostatus.collect.scan_progress import Progress
from repostatus.github.api_client import ApiError, GitHub, gh_token
from repostatus.github.rate_limit import Pacer
from repostatus.output_paths import display_path, make_saver, out_dir
from repostatus.platform_support import scan_cmd, utf8_console
from repostatus.reports import org_summary

CALLS_PER_REPO = 26  # measured: about 23 per repo plus 2 to 3 per workflow; actions and zizmor online are counted after
_hard_exit = os._exit  # tests replace this


def _online_audits(a, d, wf_root, facts, zz_exe, pacer):
    """zizmor's online audits (known-vulnerable actions, impostor commits, ref confusion) over every repository
    at once. zizmor makes its own calls to GitHub, so the allowance is re-read before and after."""
    if a.no_online_audits or not zz_exe:
        return {"status": "not run (--no-online-audits)" if a.no_online_audits else "not run: zizmor unavailable"}
    roots = {f["repo"]: os.path.join(wf_root, f["repo"]) for f in facts if "history" in f and not f.get("empty")}
    if not a.ignore_rate_limit:
        pacer.before()
    start = pacer.refresh()["remaining"]
    print("Running zizmor's online audits (asks GitHub about each action once)...", file=sys.stderr)
    res = zizmor_runner.run_online(zz_exe, roots, gh_token(), cache_dir=os.path.join(d, "zizmor-cache"),
                                   raw_path=os.path.join(d, "zizmor", "online.json"))
    used = max(0, start - pacer.refresh()["remaining"])
    for f in facts:
        found = res["findings"].get(f["repo"]) or []
        if found and (f.get("zizmor") or {}).get("status") == "ok":
            f["zizmor"]["findings"] += found
    n = sum(len(v) for v in res["findings"].values())
    print(f"  {res['status']}: {n} finding(s), about {used} API calls", file=sys.stderr)
    return {"status": res["status"], "findings": n, "api_calls": used}


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

    br_root = os.path.join(d, "branch-workflows")

    def files_for(repo, kind="default"):
        return make_saver(os.path.join(wf_root if kind == "default" else br_root, repo))

    zz_exe, zz_version, zz_status = None, None, "not run (--no-zizmor)"
    if not a.no_zizmor:
        zz_exe = zizmor_runner.find()
        zz_version = zizmor_runner.version(zz_exe) if zz_exe else None
        if not zz_exe:
            zz_status = "not run: zizmor not found (start Repo Status with scan.sh or scan.cmd, which install it)"
        elif zz_version != zizmor_runner.VERSION:
            zz_status, zz_exe = f"not run: found zizmor {zz_version}, Repo Status expects {zizmor_runner.VERSION}", None
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

    progress = Progress(d, a.resume)
    todo = [r for r in repos if r["name"] not in progress.done]
    if a.resume:
        print(f"Resuming the scan started {progress.started[:16].replace('T', ' ')}: "
              f"{len(repos) - len(todo)} repos already done, {len(todo)} to go.", file=sys.stderr)

    # GitHub allows a fixed number of API calls per hour: plan the scan around it
    pacer = Pacer(gh, a.workers)
    core = pacer.refresh()
    need = len(todo) * CALLS_PER_REPO
    reset = datetime.fromtimestamp(core["reset"]).strftime("%H:%M")
    print(f"Estimated API calls: about {need}. Allowance: {core['remaining']} of {core['limit']} left this hour "
          f"(resets at {reset}).", file=sys.stderr)
    if need > core["remaining"] - pacer.reserve:
        if a.ignore_rate_limit:
            print("Not enough for the whole scan; --ignore-rate-limit: not pausing, so later repos may show errors.",
                  file=sys.stderr)
        else:
            hours = max(1, -(-(need - core["remaining"]) // max(core["limit"] - pacer.reserve, 1)))
            print(f"That is more than this hour's allowance. The scan will pause when it runs low and continue "
                  f"after GitHub's reset (about {hours} pause(s) of up to an hour). Every finished repository is "
                  f"saved: if the scan stops, run the same command with --resume.", file=sys.stderr)

    done = [len(repos) - len(todo)]
    lock = threading.Lock()
    stopping = threading.Event()  # set on Ctrl+C: repos still running are not saved

    def collect_with_retry(meta):
        for attempt in range(3):
            if not a.ignore_rate_limit:
                pacer.before()
            rgh = gh.fork()
            f = collect_repo(rgh, a.owner, meta, recorder_for, files_for, branches=not a.skip_branches,
                             max_branches=a.max_branches)
            if not rgh.rate_limited or a.ignore_rate_limit:
                return f, False
            if attempt < 2:
                pacer.wait_after_refusal()
        f["errors"].append("GitHub kept refusing calls (rate limit); run the same command with --resume later")
        return f, True

    def one(meta):
        if stopping.is_set():
            return None
        f, limited = collect_with_retry(meta)
        if stopping.is_set():
            return None  # Ctrl+C also reaches the gh calls of this repo, so its facts may be incomplete
        if zz_exe and "history" in f and not f.get("empty"):
            f["zizmor"] = zizmor_runner.run(zz_exe, os.path.join(wf_root, meta["name"]),
                                     raw_path=os.path.join(d, "zizmor", f"{meta['name']}.json"))
            if f["zizmor"]["status"] != "ok":
                f["errors"].append(f"zizmor: {f['zizmor']['status']}")
            if (f.get("branch_workflows") or {}).get("blobs"):
                f["branch_workflows"]["zizmor"] = zizmor_runner.run(
                    zz_exe, os.path.join(br_root, meta["name"]),
                    raw_path=os.path.join(d, "zizmor", f"{meta['name']}.branches.json"))
        else:
            f["zizmor"] = {"status": zz_status, "findings": []}
        if not limited:
            progress.save(f)  # a rate-limited repo is not saved, so --resume collects it again
        with lock:
            done[0] += 1
            state = "errors: " + "; ".join(f["errors"]) if f["errors"] else "ok"
            print(f"  [{done[0]}/{len(repos)}] {meta['name']}: {state}", file=sys.stderr)
        return f

    ex = ThreadPoolExecutor(max_workers=a.workers)
    try:
        new = {f["repo"]: f for f in ex.map(one, todo) if f}
    except KeyboardInterrupt:
        stopping.set()
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl+C arrives once more through uv; ignore it
        except ValueError:
            pass  # not the main thread (tests)
        ex.shutdown(wait=False, cancel_futures=True)
        progress.record_calls(gh.calls)
        print(f"\nStopped. {len(progress.done)} of {len(repos)} repositories are saved in "
              f"{display_path(progress.dir)}; repositories that were still running will be collected again.\n"
              f"Run the same command with --resume to continue.", file=sys.stderr)
        sys.stderr.flush()
        _hard_exit(130)  # do not wait for the repositories still running: their results are discarded
    ex.shutdown()
    facts = [new.get(r["name"]) or progress.done[r["name"]] for r in repos]
    if not a.skip_action_check:
        before = gh.calls
        print("Checking the upstream actions these repos use (once per action)...", file=sys.stderr)
        ctx["action_index"] = action_index(gh, facts, a.workers,
                                           pace=None if a.ignore_rate_limit else pacer.before)
        print(f"  {len(ctx['action_index']['repos'])} actions, {len(ctx['action_index']['tags'])} tags: "
              f"{gh.calls - before} API calls", file=sys.stderr)
    ctx["zizmor"]["online"] = _online_audits(a, d, wf_root, facts, zz_exe, pacer)
    ctx["collected_at"] = datetime.now(timezone.utc).isoformat()
    ctx["collection_started"] = progress.started
    ctx["resumed"] = bool(a.resume and len(todo) < len(repos))
    ctx["pauses"] = {"count": pacer.pauses, "minutes": round(pacer.waited / 60)}
    ctx["api_calls"] = gh.calls + progress.earlier_calls
    with open(os.path.join(d, "facts.json"), "w", encoding="utf-8") as fh:
        json.dump({"context": ctx, "repos": facts}, fh, indent=1)
    progress.finish()
    paused = f", paused {pacer.pauses} time(s) for the hourly limit" if pacer.pauses else ""
    print(f"Done: {ctx['api_calls']} API calls{paused}. Facts saved to {os.path.join(d, 'facts.json')}", file=sys.stderr)


def cmd_report(a):
    d = out_dir(a.owner, create=False)
    path = os.path.join(d, "facts.json")
    if not os.path.exists(path):
        sys.exit(f"No collected data for {a.owner}. Run the scan first ({scan_cmd()} {a.owner}).")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    ctx = data["context"]
    now = datetime.fromisoformat(ctx["collected_at"])
    cfg = {k: getattr(a, k) for k in repository_checks.DEFAULTS if getattr(a, k, None) is not None}
    rows, cfg = repository_checks.evaluate(data["repos"], ctx, now, cfg, owner_dir=d)
    org_summary.write_csv(os.path.join(d, "repo-status.csv"), rows, now, cfg)
    org_summary.write_branch_csv(os.path.join(d, "branch-workflows.csv"), rows, now, cfg)
    org_summary.write_runs_csv(os.path.join(d, "runs-worth-a-look.csv"), rows, now, cfg)
    org_summary.write_inventory(os.path.join(d, "actions-inventory.csv"), rows, ctx, now)
    org_summary.write_summary(os.path.join(d, "summary.md"), ctx, rows, cfg, now, ctx.get("api_calls"),
                         generated=datetime.now(timezone.utc))
    rel = display_path(d)
    print(f"\nResults:\n  {os.path.join(rel, 'summary.md')}        (read this first)\n"
          f"  {os.path.join(rel, 'repo-status.csv')}   (open in Excel)\n"
          f"  {os.path.join(rel, 'actions-inventory.csv')}   (every action used, and where)\n"
          f"  {os.path.join(rel, 'branch-workflows.csv')}   (every workflow copy on other branches)\n"
          f"  {os.path.join(rel, 'runs-worth-a-look.csv')}   (workflow runs with something unusual about them)",
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
    print(f"Saved: {display_path(path)}", file=sys.stderr)


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
            s.add_argument("--ignore-rate-limit", action="store_true",
                           help="do not pause when the hourly API limit runs low (later repos may show errors)")
            s.add_argument("--resume", action="store_true",
                           help="continue a scan that stopped; repositories already finished are not collected again")
            s.add_argument("--max-branches", type=int, default=1000,
                           help="branches per repository whose workflows are checked, newest first (default 1000)")
            s.add_argument("--no-zizmor", action="store_true", help="do not run zizmor")
            s.add_argument("--skip-action-check", action="store_true",
                           help="do not look up the upstream actions repos use (saves API calls)")
            s.add_argument("--no-online-audits", action="store_true",
                           help="do not run zizmor's online audits (known-vulnerable actions, impostor commits)")
            s.add_argument("--skip-branches", action="store_true",
                           help="do not check workflows on other branches, run history or environments")
        if name in ("report", "all"):
            for k, v in repository_checks.DEFAULTS.items():
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
