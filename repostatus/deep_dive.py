"""Level 2: investigate one flagged repository. Read-only, API only; nothing is cloned, so nothing
from the repository can execute on this machine.

Sections: force pushes; workflow changes (commit links, who pushed them, what ran afterwards); workflow
copies on other branches (links, who can start them, which secrets they can read); zizmor with every
audit online; upstream actions whose version tags moved.

For each force push it answers:
  1. Was history rewritten (old head no longer an ancestor of new head)?
  2. Which commits disappeared, which appeared, and which look like the same commit
     rewritten (same message and author, different hash)?
  3. Do the commit dates of the new commits fit the server-side push time?
  4. Which files changed between old and new head, and are any of them auto-run or CI files?
  5. What else happened in the repo around that time (pushes, branches, package publishes)?

  uv run --python 3.12 --with pyyaml deep_dive.py --owner jdoe --repo cli-tool
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import textwrap
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from repostatus.reports import deep_dive_verdict
from repostatus.reports.github_links import SHA, commit_link, compare_url, file_url, finding_commits, linkify
from repostatus.collect import zizmor_runner
from repostatus.collect.repository_facts import all_uses
from repostatus.checks.repository_checks import evaluate, is_github_commit, ts
from repostatus.github.api_client import ApiError, GitHub, gh_token
from repostatus.reports.org_summary import _last_run_text, _reach
from repostatus.checks.workflow_checks import _runs, branch_copies, runs_worth_a_look
from repostatus.collect.workflow_parser import FULL_VERSION
from repostatus.platform_support import scan_cmd, utf8_console

SENSITIVE = re.compile(
    r"(^|/)(\.vscode/|\.github/workflows/|\.github/actions/|\.devcontainer/|\.husky/|"
    r"package\.json$|setup\.py$|setup\.cfg$|pyproject\.toml$|Makefile$|Dockerfile|"
    r"[^/]+\.(sh|bat|cmd|ps1)$|\.npmrc$|\.yarnrc)")

COMMIT_QUERY = """
query($owner:String!, $name:String!, $oid:GitObjectID!) {
  repository(owner:$owner, name:$name) { object(oid:$oid) { ... on Commit {
    oid messageHeadline committedDate
    author { date email name user { login } } committer { date email name }
    signature { isValid state }
    parents(first:3) { nodes { oid } }
  } } }
}"""


def commit_detail(gh, owner, repo, oid):
    try:
        c = gh.graphql(COMMIT_QUERY, owner=owner, name=repo, oid=oid)["repository"]["object"]
    except ApiError:
        return None
    if not c:
        return None
    return {
        "oid": c["oid"], "headline": c["messageHeadline"], "committed_utc": c["committedDate"],
        "author_date": c["author"]["date"], "committer_date": c["committer"]["date"],
        "author_email": c["author"]["email"], "author_login": (c["author"].get("user") or {}).get("login"),
        "committer_email": c["committer"]["email"],
        "signature": (c.get("signature") or {}).get("state", "UNSIGNED"),
        "signature_valid": (c.get("signature") or {}).get("isValid", False),
        "parents": [p["oid"] for p in c["parents"]["nodes"]],
    }


def compare(gh, full, base, head):
    data, err = gh.try_get(f"repos/{full}/compare/{base}...{head}")
    return data, err


def investigate(gh, owner, repo, event, all_events, packages):
    full = f"{owner}/{repo}"
    before, after, when = event["before"], event["after"], ts(event["ts"])
    r = {"event": event, "findings": []}

    old = commit_detail(gh, owner, repo, before)
    new = commit_detail(gh, owner, repo, after)
    r["old_head"], r["new_head"] = old, new
    if not old:
        r["findings"].append("Old head is no longer retrievable from GitHub; compare needs a copy taken before the push.")
        return r

    def slim(c):
        return {"oid": c["sha"], "headline": c["commit"]["message"].splitlines()[0],
                "author": c["commit"]["author"]["email"]}

    fwd, err = compare(gh, full, before, after)
    if err and "No common ancestor" in err:
        # Entire history replaced: list each side from its own head
        r["status"], r["merge_base"] = "unrelated", None
        r["added"] = [slim(c) for c in gh.get(f"repos/{full}/commits?sha={after}&per_page=100") or []]
        r["removed"] = [slim(c) for c in gh.get(f"repos/{full}/commits?sha={before}&per_page=100") or []]
        old_tree = gh.get(f"repos/{full}/git/trees/{before}?recursive=1").get("tree", [])
        new_tree = gh.get(f"repos/{full}/git/trees/{after}?recursive=1").get("tree", [])
        o = {t["path"]: t["sha"] for t in old_tree if t["type"] == "blob"}
        n = {t["path"]: t["sha"] for t in new_tree if t["type"] == "blob"}
        r["files"] = ([{"name": k, "status": "added", "+": "", "-": ""} for k in sorted(n.keys() - o.keys())] +
                      [{"name": k, "status": "removed", "+": "", "-": ""} for k in sorted(o.keys() - n.keys())] +
                      [{"name": k, "status": "modified", "+": "", "-": ""} for k in sorted(o.keys() & n.keys()) if o[k] != n[k]])
        r["findings"].append(f"Entire history replaced: old and new heads share no common ancestor "
                             f"({len(r['removed'])} old commit(s), {len(r['added'])} new commit(s)).")
    elif err:
        r["findings"].append(f"Compare failed: {err}")
        return r
    else:
        r["status"] = fwd["status"]                 # ahead = fast-forward; diverged = rewritten
        r["merge_base"] = fwd["merge_base_commit"]["sha"]
        r["added"] = [slim(c) for c in fwd["commits"]]
        back, _ = compare(gh, full, after, before)
        r["removed"] = [slim(c) for c in (back or {}).get("commits", [])]
        r["files"] = [{"name": f["filename"], "status": f["status"], "+": f["additions"], "-": f["deletions"]}
                      for f in fwd.get("files", [])]

    if r["status"] == "unrelated":
        pass
    elif r["status"] in ("ahead", "identical"):
        r["findings"].append("Not a rewrite: old head is still in history (force flag used on a fast-forward).")
    else:
        r["findings"].append(f"History rewritten: {len(r['removed'])} commit(s) removed, {len(r['added'])} added "
                             f"since common ancestor {r['merge_base'][:7]}.")

    # Same commit, different hash: the "fold changes into an existing commit" pattern
    removed_by_key = {(c["headline"], c["author"]): c for c in r["removed"]}
    r["rewritten_pairs"] = []
    for c in r["added"]:
        o = removed_by_key.get((c["headline"], c["author"]))
        if o:
            pair_cmp, _ = compare(gh, full, o["oid"], c["oid"])
            files = [f["filename"] for f in (pair_cmp or {}).get("files", [])]
            od, nd = commit_detail(gh, owner, repo, o["oid"]), commit_detail(gh, owner, repo, c["oid"])
            r["rewritten_pairs"].append({"old": od, "new": nd, "files_differ": files})
            if files:
                r["findings"].append(f"Commit \"{c['headline']}\" was rewritten ({o['oid'][:7]} -> {c['oid'][:7]}) "
                                     f"and its content changed: {', '.join(files[:8])}")
            else:
                r["findings"].append(f"Commit \"{c['headline']}\" was rewritten ({o['oid'][:7]} -> {c['oid'][:7]}) "
                                     f"with identical content (metadata-only rewrite).")

    # Commit dates of new commits vs the server-side push time
    r["added_detail"] = []
    for c in r["added"][:30]:
        d = commit_detail(gh, owner, repo, c["oid"])
        if not d:
            continue
        gap = (when - ts(d["committed_utc"])).total_seconds() / 86400
        d["gap_days"] = round(gap, 1)
        r["added_detail"].append(d)
        if gap > 7 and not is_github_commit(d):
            r["findings"].append(f"{d['oid'][:7]} \"{d['headline']}\" is dated {d['committed_utc'][:10]} "
                                 f"but first reached GitHub {event['ts'][:10]} ({gap:.0f} days later).")
        if d["author_email"] != d["committer_email"] and not is_github_commit(d):
            r["findings"].append(f"{d['oid'][:7]} author {d['author_email']} differs from committer {d['committer_email']}.")

    # Forks: a force push that makes the fork match upstream is usually "Sync fork -> Discard commits"
    meta, _ = gh.try_get(f"repos/{full}")
    parent = ((meta or {}).get("parent") or {}).get("full_name")
    if parent:
        _, perr = gh.try_get(f"repos/{parent}/commits/{after}")
        r["fork_parent"] = parent
        if perr is None:
            r["findings"].append(f"Repository is a fork of {parent} and the new head {after[:7]} exists upstream: "
                                 f"consistent with syncing the fork after upstream rewrote its history.")
        else:
            r["findings"].append(f"Repository is a fork of {parent} but the new head {after[:7]} is not in upstream: "
                                 f"the rewrite was made in this fork.")

    sens = [f["name"] for f in r["files"] if SENSITIVE.search(f["name"])]
    if sens:
        r["findings"].append(f"Auto-run / CI / build files changed: {', '.join(sens[:10])}")

    # Everything else that happened within a day either side, by GitHub's clock
    lo, hi = when - timedelta(days=1), when + timedelta(days=1)
    r["timeline"] = sorted(
        [{"ts": e["ts"], "what": f"{e['type']} {e['ref'].replace('refs/heads/', '')} by {e['actor']} "
                                 f"({(e['before'] or '')[:7]} -> {(e['after'] or '')[:7]})"}
         for e in all_events if lo <= ts(e["ts"]) <= hi] +
        [{"ts": p["latest_published"], "what": f"{p['type']} package {p['name']} published"}
         for p in packages if p.get("latest_published") and lo <= ts(p["latest_published"]) <= hi],
        key=lambda x: x["ts"])
    same_sha = [e for e in all_events if e["after"] == after and e["ref"] != event["ref"]
                and abs((ts(e["ts"]) - when).total_seconds()) < 60]
    if same_sha:
        r["findings"].append(f"Same commit pushed to {len(same_sha)} other branch(es) within a minute.")
    return r


def workflow_changes(gh, owner, repo, f, events, since_days):
    """Recent commits that touched .github/, with diffs of workflow files, the push GitHub recorded for
    each, and the runs of the changed workflows since then."""
    full = f"{owner}/{repo}"
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    commits, err = gh.try_get(f"repos/{full}/commits?path=.github&sha={quote(f['default_branch'], safe='')}"
                              f"&since={since}&per_page=30")
    pushed = {e["after"]: e for e in events if e.get("after")}
    items = {w["path"]: w for w in (f.get("actions") or {}).get("items") or []}
    out = {"error": err, "since_days": since_days, "commits": [], "runs": {}}
    for c in (commits or [])[:15]:
        detail, derr = gh.try_get(f"repos/{full}/commits/{c['sha']}")
        if derr:
            out["commits"].append({"oid": c["sha"], "error": derr, "files": []})
            continue
        cm, e = detail["commit"], pushed.get(c["sha"])
        out["commits"].append({
            "oid": c["sha"], "headline": (cm["message"] or "").splitlines()[0][:100] if cm["message"] else "",
            "author": (detail.get("author") or {}).get("login") or cm["author"]["email"],
            "date": cm["committer"]["date"],
            "verified": (cm.get("verification") or {}).get("verified"),
            "pushed_at": e["ts"] if e else None, "pushed_by": e["actor"] if e else None,
            "files": [{"name": x["filename"], "status": x["status"], "+": x["additions"], "-": x["deletions"]}
                      for x in detail.get("files") or []],
        })
    dated = [c["date"] for c in out["commits"] if c.get("date")]
    changed = sorted({x["name"] for c in out["commits"] for x in c["files"] if x["name"] in items})
    for path in changed:
        runs, rerr = gh.try_get(f"repos/{full}/actions/workflows/{items[path]['id']}/runs"
                                f"?created=%3E%3D{min(dated)[:10]}&per_page=30")
        out["runs"][path] = {"error": rerr, "items": [{
            "created_at": r["created_at"], "event": r["event"], "conclusion": r.get("conclusion"),
            "actor": (r.get("triggering_actor") or r.get("actor") or {}).get("login"),
            "head_sha": r["head_sha"], "url": r["html_url"]} for r in (runs or {}).get("workflow_runs") or []]}
    return out


def workflow_markdown(wf, f, findings=None):
    full = f["full_name"]
    L = ["## Workflow changes\n",
         f"Commits that changed `.github/` in the last {wf['since_days']} days. Each commit links to GitHub, which "
         f"shows its changes; commits that are themselves a finding are marked FINDING: with the reason.\n"]
    wakes = [w for w in f.get("idle_wakeups") or [] if w.get("files")]
    if wakes:
        L.append("**Pushes after a quiet period** (server-side times)\n")
        for w in wakes:
            codes = (findings or {}).get((w["after"] or "")[:7]) or []
            L.append(f"- {w['ts']} {w['actor']} after {w['gap_days']:.0f} quiet days: "
                     f"[changes in this push]({compare_url(full, w['before'], w['after'])})"
                     + (f" FINDING: {', '.join(codes)}" if codes else "")
                     + f"; files: {', '.join(w['files'][:8])}"
                     + (f" (commits by {', '.join(w.get('authors') or [])})" if w.get("authors") else ""))
        L.append("")
    if wf.get("error"):
        L.append(f"Commit list could not be read: {wf['error']}\n")
    if not wf["commits"]:
        L.append("No commits changed `.github/` in this period.\n")
    else:
        L.append("| Commit | Message | Author | Commit date (claimed) | Pushed (GitHub) | Verified | Files |")
        L.append("|---|---|---|---|---|---|---|")
        for c in wf["commits"]:
            if c.get("error"):
                L.append(f"| {commit_link(full, c['oid'], findings)} | could not be read: {c['error']} | | | | | |")
                continue
            pushed = f"{c['pushed_at']} by {c['pushed_by']}" if c["pushed_at"] else "not the head of a recorded push"
            files = ", ".join(x["name"] for x in c["files"][:5]) + (f" and {len(c['files']) - 5} more"
                                                                   if len(c["files"]) > 5 else "")
            L.append(f"| {commit_link(full, c['oid'], findings)} | {c['headline'].replace('|', '/')} | {c['author']} | "
                     f"{c['date']} | {pushed} | {'yes' if c['verified'] else 'no'} | {files} |")
    items = {w["path"]: w for w in (f.get("actions") or {}).get("items") or []}
    for path, runs in wf["runs"].items():
        w = items.get(path, {})
        L.append(f"\n**Runs of {path} since the first change above**"
                 + (f" (secrets it can read: {', '.join(w['secrets'])})" if w.get("secrets") else "") + "\n")
        if runs["error"]:
            L.append(f"Could not be read: {runs['error']}")
        elif not runs["items"]:
            L.append("None.")
        else:
            L.append("| Started | Event | By | Result | Commit | Link |\n|---|---|---|---|---|---|")
            L += [f"| {r['created_at']} | {r['event']} | {r['actor']} | {r['conclusion']} | "
                  f"{commit_link(full, r['head_sha'], findings)} | [run]({r['url']}) |" for r in runs["items"]]
    risky = [(w["path"], where, d) for w in items.values() for code, where, d in w.get("script") or []
             if code == "EXFIL_PATTERN"]
    if risky:
        L.append("\n**Steps that send secrets or the environment to an outside address** (read these first)\n")
        L += [f"- {p} ({where}): {d}" for p, where, d in risky]
    L.append("")
    return L


def zizmor_online(owner_dir, repo, d):
    """zizmor with every audit, including those that ask GitHub, and ignore comments disregarded."""
    root = os.path.join(owner_dir, "workflows", repo)
    if not os.path.isdir(root):
        return {"status": "not run: no workflow files in the last scan", "findings": []}
    exe = zizmor_runner.find()
    v = zizmor_runner.version(exe) if exe else None
    if v != zizmor_runner.VERSION:
        return {"status": f"not run: zizmor {v or 'not found'} (expected {zizmor_runner.VERSION}; "
                          f"start with scan.sh or scan.cmd)", "findings": []}
    token = gh_token()
    res = zizmor_runner.run(exe, root, raw_path=os.path.join(d, f"{repo}.zizmor.json"), online_token=token,
                     cache_dir=os.path.join(owner_dir, "zizmor-cache"), persona="auditor", no_ignores=True)
    res["online"] = bool(token)
    return res


def zizmor_markdown(zz):
    L = ["## zizmor: every finding\n"]
    if zz["status"] != "ok":
        L.append(f"zizmor {zz['status']}.\n")
        return L
    L.append(("Online audits included (impostor commits, known-vulnerable actions, ref confusion). " if zz.get("online")
              else "No GitHub token found, so online audits did not run. ")
             + "Auditor persona, `# zizmor: ignore` comments disregarded. Files as of the last scan.\n")
    found = sorted(zz["findings"], key=lambda x: (-zizmor_runner.LEVELS.get(x["severity"], 0),
                                                  -zizmor_runner.LEVELS.get(x["confidence"], 0), x["file"], x["line"] or 0))
    if not found:
        L.append("No findings.\n")
        return L
    L.append("| Severity | Confidence | Rule | Where | Note |\n|---|---|---|---|---|")
    L += [f"| {x['severity']} | {x['confidence']} | [{x['rule']}](https://docs.zizmor.sh/audits/#{x['rule']}) | "
          f"{x['file']}:{x['line']} | {(x['note'] or '').replace('|', '/')} |" for x in found[:150]]
    if len(found) > 150:
        L.append(f"\n{len(found) - 150} more in the JSON file next to this report.")
    L.append("")
    return L


def upstream_actions(f, index):
    """Pinned or locked commits whose version tag now points elsewhere, with a link to compare them."""
    if not index:
        return {"checked": False, "moved": [], "problems": []}
    repos, tags = index.get("repos") or {}, index.get("tags") or {}
    moved, problems = [], []
    for path, u in all_uses(f):
        r = repos.get(u.get("slug") or "")
        if r and r["status"] != "ok":
            problems.append({"action": u["slug"], "where": path, "state": r["status"]})
        if u.get("ref_type") == "sha" and u.get("version_comment") and FULL_VERSION.match(u["version_comment"]):
            now_at = (tags.get(f"{u['slug']}@{u['version_comment']}") or {}).get("commit")
            if now_at and r and now_at.lower() != u["ref"].lower():
                moved.append({"action": u["slug"], "tag": u["version_comment"], "pinned": u["ref"], "now": now_at,
                              "where": path, "source": "version comment",
                              "compare": f"https://github.com/{r['full_name']}/compare/{u['ref']}...{now_at}"})
    for key, dep in (((f.get("actions") or {}).get("lockfile") or {}).get("dependencies") or {}).items():
        now_at = (tags.get(f"{dep['slug']}@{dep['ref']}") or {}).get("commit")
        r = repos.get(dep["slug"]) or {}
        if now_at and dep.get("commit") and now_at.lower() != dep["commit"].lower() and r.get("full_name"):
            moved.append({"action": dep["slug"], "tag": dep["ref"], "pinned": dep["commit"], "now": now_at,
                          "where": "actions.lock", "source": "lockfile" if FULL_VERSION.match(dep["ref"])
                          else "lockfile (major-version tag: moving is normal)",
                          "compare": f"https://github.com/{r['full_name']}/compare/{dep['commit']}...{now_at}"})
    return {"checked": True, "moved": moved, "problems": problems}


def upstream_markdown(up):
    L = ["## Upstream actions\n"]
    if not up["checked"]:
        L.append("Not checked in the last scan (--skip-action-check).\n")
        return L
    if not up["moved"] and not up["problems"]:
        L.append("Every action this repo uses still exists, and no pinned or locked version tag has moved.\n")
        return L
    if up["moved"]:
        L.append("| Action | Tag | Pinned / locked | Tag now | Where | Source | Compare |\n|---|---|---|---|---|---|---|")
        L += [f"| {m['action']} | {m['tag']} | {m['pinned'][:7]} | {m['now'][:7]} | {m['where']} | {m['source']} | "
              f"[diff]({m['compare']}) |" for m in up["moved"]]
        L.append("\nOpen each diff before running the workflow again: a version tag that moved can mean the "
                 "upstream project was compromised (as with trivy-action in March 2026).\n")
    if up["problems"]:
        L.append("| Action | Where | State |\n|---|---|---|")
        L += [f"| {p['action']} | {p['where']} | {p['state']} |" for p in up["problems"]]
    L.append("")
    return L


def branches_markdown(owner_dir, repo, f, now, cfg):
    """Workflow copies on other branches: what differs from the default branch's copy, who can start it,
    which secrets it can read. Built from the files the scan saved; no API calls."""
    L = ["## Workflows on other branches\n"]
    if not f.get("branch_workflows"):
        L.append("Not checked in the last scan (--skip-branches).\n")
        return L
    rows = branch_copies(f, now, cfg)
    if not rows:
        L.append(f"All {f['branch_workflows']['scanned']} branches have the same workflow files as the default "
                 f"branch.\n")
    else:
        groups = {g: len({r["branch"] for r in rows if r.get("group") == g}) for g in ("flagged", "active", "stale")}
        L.append(f"Branches with a differing copy: {groups['flagged']} flagged, {groups['active']} active (a commit or "
                 f"run in the last {cfg['dormant_days']} days, or running now), {groups['stale']} stale.\n")
    by_version = defaultdict(list)
    for r in rows:
        by_version[(r["file"], r["oid"])].append(r)
    zz = defaultdict(list)
    for z in (f["branch_workflows"].get("zizmor") or {}).get("findings") or []:
        zz[z["file"].split("/", 1)[0]].append(z)
    rank = {"flagged": 0, "active": 1, "stale": 2}
    for (name, oid), rs in sorted(by_version.items(),
                                  key=lambda kv: (min(rank.get(x.get("group"), 1) for x in kv[1]), -len(kv[1]), kv[0])):
        rs = sorted(rs, key=lambda x: (rank.get(x.get("group"), 1), x["branch"]))
        r = rs[0]
        L.append(f"### {name}: version {oid[:7]} ({r['copy']}) on {len(rs)} branch(es)\n")
        L.append("| Branch | Group | Last commit | Last run | Can be started by | Secrets it can read | This copy | "
                 "Compare with default |")
        L.append("|---|---|---|---|---|---|---|---|")
        full, default = f["full_name"], f.get("default_branch")
        L += [f"| {x['branch']} | {x.get('group')} | {(x['committed'] or '')[:10]} | {_last_run_text(x)} | "
              f"{', '.join(x.get('runs_via') or []) or 'no'} | "
              f"{_reach(x).replace('|', '/')} | [{name}]({file_url(full, x['branch'], '.github/workflows/' + name)}) | "
              f"[compare]({compare_url(full, default, x['branch'])}) |" for x in rs]
        found = zz.get(oid[:12]) or []
        if found:
            L.append("\nzizmor (offline) on this version: " + ", ".join(
                f"{z['rule']} ({z['severity']}) line {z['line']}" for z in found[:12]))
        L.append("")
    ran = [d for code, _, d in _runs(f, now, cfg)]
    runs = [x for x in (f.get("recent_runs") or {}).get("items") or []
            if (x["path"] or "").startswith(".github/workflows/")
            and x["path"] not in {f".github/workflows/{n}" for n in f["branch_workflows"].get("default_files") or []}
            and x["head_branch"] != f.get("default_branch") and not x["from_fork"]]
    if runs:
        L.append("**Runs of workflow files that are not on the default branch** (from the last 100 runs)\n")
        if ran:
            L += [f"- {d}" for d in ran] + [""]
        L.append("| Started | Workflow | Branch | Event | By | Result | Link |\n|---|---|---|---|---|---|---|")
        L += [f"| {x['created_at']} | {x['path']} | {x['head_branch']} | {x['event']} | {x['actor']} | "
              f"{x['conclusion']} | [run]({x['url']}) |" for x in runs[:40]]
    L.append("")
    return L


MAX_RUN_COMMIT_CHECKS = 20  # runs worth a look whose commit is opened to see if it changed the workflow itself


def runs_markdown(gh, f, row, now, cfg, findings=None):
    """Runs worth a look, and for each (up to 20) whether the commit it ran changed that same workflow:
    the pattern of a planted workflow that is pushed and runs straight away."""
    full = f["full_name"]
    runs = runs_worth_a_look(f, row["status"], now, cfg, row["flags"])
    L = ["## Runs worth a look\n",
         f"From the last 100 runs within {cfg['live_days']} days, the runs with something unusual about them.\n"]
    if not runs:
        L.append("None.\n")
        return L, runs
    for x in runs[:MAX_RUN_COMMIT_CHECKS]:
        c, err = gh.try_get(f"repos/{full}/commits/{x['head_sha']}")
        if not err and x["path"] in {fl["filename"] for fl in (c or {}).get("files") or []}:
            x["reasons"].append(("CHANGED_ITSELF", "the commit it ran changed this workflow file"))
    L.append("| Started | Workflow | Branch | Event | By | Commit | Why | Run |\n|---|---|---|---|---|---|---|---|")
    L += [f"| {x['created_at']} | {x['path']} | {x['head_branch']} | {x['event']} | {x['actor']} | "
          f"{commit_link(full, x['head_sha'], findings)} | {'; '.join(t for _, t in x['reasons'])} | "
          f"[run]({x['url']}) |" for x in runs]
    L.append("")
    return L, runs


def logs_markdown(checked, f):
    """The Run logs evidence section, and the flags for the report: secrets visible in a log, attack indicators."""
    public = f.get("visibility") == "public"
    L = ["## Run logs\n",
         f"{len({x['run']['id'] for x in checked})} run(s) read (runs worth a look, and the latest run of each workflow "
         f"that holds secrets). Logs were scanned in memory and not saved; values are masked.\n"]
    flags = []
    rows = []
    for x in checked:
        run = x["run"]
        where = f"{run['path'].rsplit('/', 1)[-1]} run {run['id']}, job {x['job'] or '-'}"
        if x.get("error"):
            rows.append(f"| [{run['id']}]({run['url']}) | {x['job'] or '-'} | | {x['error']} |")
            continue
        for n, step, kind, detail in x["findings"]:
            rows.append(f"| [{run['id']}]({run['url']}) | {x['job']} | {step or '-'}, line {n} | {detail} |")
            if kind == "attack indicator":
                flags.append(("IOC_MATCH", "high", f"{detail} in the log of {where}"))
            else:
                flags.append(("SECRET_IN_RUN_LOG", "high", f"{detail}; {where}, line {n}"
                              + ("; this repository is public, so anyone can read that log" if public else "")))
    if rows:
        L.append("| Run | Job | Where | Found |\n|---|---|---|---|")
        L += rows
    else:
        L.append("Nothing found: no unmasked tokens, no encoded secrets, no attack indicators.")
    L.append("")
    return L, flags


EVIDENCE_SECTIONS = [("Force pushes", "force-pushes"), ("Workflow changes", "workflow-changes"),
                     ("Workflows on other branches", "workflows-on-other-branches"),
                     ("Runs worth a look", "runs-worth-a-look"), ("Run logs", "run-logs"),
                     ("zizmor: every finding", "zizmor-every-finding"), ("Upstream actions", "upstream-actions")]


def write_markdown(path, owner, repo, results, reasons=(), sections=(), report_name=None, findings=None):
    """The evidence file: everything the deep dive looked at, for verifying the report's claims."""
    L = [f"# {repo}: evidence\n",
         f"Everything behind the deep-dive report" + (f" [{report_name}]({report_name})" if report_name else "")
         + f" for {owner}/{repo}. All times UTC. Push times come from GitHub (server-side); commit dates come from "
           f"the commit itself.\n",
         "Contents: " + " | ".join(f"[{t}](#{a})" for t, a in EVIDENCE_SECTIONS) + "\n"]
    if reasons:
        L.append("**Why this repo is on the list** (from the last scan)\n")
        L += [f"- {c} ({s}): {linkify(d, f'{owner}/{repo}', findings)}" for c, s, d in reasons] + [""]
    if not results:
        L.append("## Force pushes\n\nGitHub has no record of a force push to the default branch.\n")
    full = f"{owner}/{repo}"
    for i, r in enumerate(results, 1):
        e = r["event"]
        L.append(f"## Force push {i}: {e['ts']} by {e['actor']}\n")
        L.append(f"{commit_link(full, e['before'] or '')} -> {commit_link(full, e['after'] or '', findings)} "
                 f"on `{e['ref']}` ([compare]({compare_url(full, e['before'] or '', e['after'] or '')}))\n")
        L.append("**Findings**\n")
        L += [f"- {x}" for x in r["findings"]]
        for label, c in (("Old head", r.get("old_head")), ("New head", r.get("new_head"))):
            if c:
                L.append(f"\n**{label}** {commit_link(full, c['oid'], findings)} \"{c['headline']}\"  ")
                L.append(f"author {c['author_email']} at {c['author_date']}; committer {c['committer_email']} "
                         f"at {c['committer_date']}; signature {c['signature']}")
        if r.get("removed") or r.get("added"):
            L.append("\n| Side | Commit | Message | Author |\n|---|---|---|---|")
            L += [f"| removed | {commit_link(full, c['oid'])} | {c['headline'][:70]} | {c['author']} |"
                  for c in r.get("removed", [])]
            L += [f"| added | {commit_link(full, c['oid'], findings)} | {c['headline'][:70]} | {c['author']} |"
                  for c in r.get("added", [])]
        if r.get("added_detail"):
            L.append("\n| Added commit | Commit date (claimed) | Pushed (GitHub) | Gap days | Signature |\n|---|---|---|---|---|")
            L += [f"| {commit_link(full, d['oid'], findings)} | {d['committed_utc']} | {e['ts']} | {d['gap_days']} | "
                  f"{d['signature']} |" for d in r["added_detail"]]
        if r.get("files"):
            L.append(f"\n**Files changed between old and new head ({len(r['files'])})**\n")
            L.append("| File | Change | + | - |\n|---|---|---|---|")
            L += [f"| {f['name']} | {f['status']} | {f['+']} | {f['-']} |" for f in r["files"][:40]]
        if r.get("timeline"):
            L.append("\n**Timeline (one day either side)**\n")
            L += [f"- {t['ts']} {t['what']}" for t in r["timeline"]]
        L.append("")
    for s in sections:
        L += s
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def _item_lines(a, full=None):
    """The body of one action in the report: quoted lines, who, what it can reach, fix, where, evidence."""
    L = []
    if a.get("lines"):
        L.append(f"In `{a['file']}`" + (f", step \"{a['step']}\"" if a.get("step") else "") + ":\n")
        for ln in a["lines"]:
            note = " (a value GitHub generates, such as a commit hash: it cannot carry code, so this line is low " \
                   "risk; change it the same way for consistency)" if ln["harmless"] else ""
            L.append(f"- line {ln['line']}: `{(ln['text'] or '').replace('`', chr(39))}`{note}")
        L.append("")
    elif a.get("where") and not a.get("items"):
        for w in a["where"][:8]:  # every commit named in a finding's own details is part of that finding
            own = {sha[:7]: [a["code"]] for sha in SHA.findall(w)}
            L.append(f"- {linkify(w, full, own) if full else w}")
        L.append("")
    for item in a.get("items") or []:
        link = f" Where: {item['settings'][0]} ({item['settings'][1]})" if item.get("settings") else ""
        L.append(f"- {item['text']}.{link}")
    if a.get("items"):
        L.append("")
    if a.get("why"):
        L.append(f"**What it means:** {a['why']}  ")
    if a.get("who"):
        L.append(f"**Who can exploit it:** {a['who']}. {'This workflow still runs and can read' if a.get('live') else 'It can read'}: "
                 f"{a['reach']}.  ")
    if a.get("fix"):
        L.append(f"**Fix:** {a['fix']}  ")
    for key in ("settings", "settings2"):
        if a.get(key):
            L.append(f"**Where on GitHub:** {a[key][0]}: {a[key][1]}  ")
    return L


def write_report(path, owner, f, collected_at, result, evidence_name):
    """The deep-dive report: one screen, conclusion first. Details live in the evidence file."""
    L = [f"# {f['repo']}: deep dive\n",
         f"{owner}/{f['repo']}, {f.get('visibility') or ''} repository, data from {collected_at[:16].replace('T', ' ')} UTC\n",
         f"**{result['verdict']}**\n",
         "| Area | Result | In short |", "|---|---|---|"]
    for ar in result["areas"]:
        name = f"[{ar['name']}]({evidence_name}#{ar['evidence']})" if ar.get("evidence") else ar["name"]
        L.append(f"| {name} | {ar['result']} | {ar['short'].replace('|', '/')} |")
    L.append("")
    if result["actions"]:
        L.append("## What to do\n")
        for i, a in enumerate(result["actions"], 1):
            L.append(f"### {i}. {a['level']}: {a['title']}\n")
            L += _item_lines(a, f"{owner}/{f['repo']}")
            if a.get("evidence"):
                L.append(f"**Evidence:** [{evidence_name}]({evidence_name}#{a['evidence']})")
            L.append("")
    L.append("## Checked, nothing found\n")
    L += [f"- {c}" for c in result["clean"]] + [""]
    L.append("## What this cannot see\n")
    L += [f"- {x}" for x in result["limits"]] + [""]
    L.append(f"Every commit, run and finding behind this report: [{evidence_name}]({evidence_name})")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def console_table(result, width=None):
    """The verdict and the eight areas for the terminal. Long text wraps at word boundaries under its
    column, to the terminal's width, instead of being cut off."""
    w = max(len(a["name"]) for a in result["areas"])
    indent = 2 + w + 2 + 11 + 2
    width = width or shutil.get_terminal_size(fallback=(120, 24)).columns
    text_width = max(40, width - indent)
    lines = [result["verdict"], ""]
    for a in result["areas"]:
        wrapped = textwrap.wrap(a["short"], text_width) or [""]
        lines.append(f"  {a['name']:<{w}}  {a['result']:<11}  {wrapped[0]}")
        lines += [" " * indent + more for more in wrapped[1:]]
    if result["actions"]:
        lines += ["", "To do:"] + [f"  {i}. {a['level']}: {a['title']}" for i, a in enumerate(result["actions"], 1)]
    return "\n".join(lines)


def main(argv=None):
    utf8_console()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--all-branches", action="store_true", help="include force pushes to non-default branches")
    p.add_argument("--since-days", type=int, default=365, help="workflow changes from this many days back")
    p.add_argument("--logs", action="store_true",
                   help="also read run logs (runs worth a look and the latest run of workflows with secrets, up to 20) "
                        "for secrets GitHub's masking missed; logs are never saved")
    a = p.parse_args(argv)

    from repostatus.output_paths import display_path, out_dir
    owner_dir = out_dir(a.owner, create=False)
    facts_path = os.path.join(owner_dir, "facts.json")
    if not os.path.exists(facts_path):
        sys.exit(f"No scan found for {a.owner}. Run {scan_cmd()} {a.owner} first.")
    with open(facts_path, encoding="utf-8") as fh:
        data = json.load(fh)
    f = next((x for x in data["repos"] if x["repo"].lower() == a.repo.lower()), None)
    if not f:
        sys.exit(f"'{a.repo}' is not in the last scan of {a.owner}. Check the name in "
                 f"{os.path.join('out', a.owner, 'repo-status.csv')} (first column).")
    a.repo = f["repo"]
    a.owner = data["context"]["owner"]
    pkgs = [x for x in data["context"].get("packages", []) if x["repo"] == a.repo]
    gh = GitHub()
    events = gh.get(f"repos/{a.owner}/{a.repo}/activity?per_page=100", paginate=True) or []
    events = [{"ts": e["timestamp"], "type": e["activity_type"], "ref": e["ref"],
               "actor": (e.get("actor") or {}).get("login"), "before": e.get("before"), "after": e.get("after")}
              for e in events]
    fps = [e for e in events if e["type"] == "force_push"
           and (a.all_branches or e["ref"] == f"refs/heads/{f['default_branch']}")]
    results = [investigate(gh, a.owner, a.repo, e, events, pkgs) for e in sorted(fps, key=lambda e: e["ts"])]

    d = os.path.join(owner_dir, "deep-dive")
    os.makedirs(d, exist_ok=True)
    rows, cfg = evaluate([f], data["context"], ts(data["context"]["collected_at"]), owner_dir=owner_dir)
    row = rows[0]
    reasons = [x for x in row["flags"] if x[1] in ("high", "medium")]

    wf = workflow_changes(gh, a.owner, a.repo, f, events, a.since_days)
    zz = zizmor_online(owner_dir, a.repo, d)
    up = upstream_actions(f, data["context"].get("action_index"))
    with open(os.path.join(d, f"{a.repo}.json"), "w", encoding="utf-8") as fh:
        json.dump({"force_pushes": results, "workflow_changes": wf, "zizmor": zz, "upstream": up}, fh, indent=1)
    evidence_name = f"{a.repo}-evidence.md"
    findings = finding_commits(row["flags"])
    runs_section, worth = runs_markdown(gh, f, row, ts(data["context"]["collected_at"]), cfg, findings)
    logs_section, log_flags, logs_checked = ["## Run logs\n", "Not read: add `--logs` to read them.\n"], [], None
    if a.logs:
        from repostatus.checks.ioc_matching import load_iocs
        from repostatus.collect import run_logs
        strings = sorted({s for c in load_iocs()["campaigns"] for s in c.get("log_strings") or []})
        checked = run_logs.check_runs(gh, f["full_name"], run_logs.candidate_runs(f, worth), strings)
        logs_section, log_flags = logs_markdown(checked, f)
        logs_checked = len({x["run"]["id"] for x in checked})
        row["flags"] = row["flags"] + log_flags
    write_markdown(os.path.join(d, evidence_name), a.owner, a.repo, results, reasons,
                   [workflow_markdown(wf, f, findings), branches_markdown(owner_dir, a.repo, f,
                                                                          ts(data["context"]["collected_at"]), cfg),
                    runs_section, logs_section, zizmor_markdown(zz), upstream_markdown(up)], report_name=f"{a.repo}.md",
                   findings=findings)
    row["now"], row["cfg"], row["logs_checked"] = ts(data["context"]["collected_at"]), cfg, logs_checked
    result = deep_dive_verdict.assess(f, row, f"{a.owner}/{a.repo}", owner_dir, results, wf, zz, up)
    write_report(os.path.join(d, f"{a.repo}.md"), a.owner, f, data["context"]["collected_at"], result, evidence_name)
    summary = (console_table(result) + f"\n\nInvestigated: {len(results)} force push(es), {len(wf['commits'])} "
               f"workflow change(s), {len(zz.get('findings') or [])} zizmor finding(s) ({gh.calls} API calls).\n"
               f"Report:   {display_path(os.path.join(d, a.repo + '.md'))}\n"
               f"Evidence: {display_path(os.path.join(d, evidence_name))}")
    if not results:
        prot = row["prot"] or {}
        lines = [f"GitHub has no record of anyone overwriting the history of '{f['default_branch']}' "
                 f"(0 force pushes)."]
        if prot.get("force_push_blocked") is False:
            why = (" Branch rules are not available for private repositories on GitHub Free."
                   if prot.get("plan_limited") else "")
            lines.append(f"Note: it has not happened, but nothing prevents it. The CSV shows this as "
                         f"'force-push allowed on default branch'.{why}")
        elif prot.get("source") == "unknown":
            lines.append(f"Note: branch rules could not be read ({prot.get('error')}).")
        print("\n".join(lines) + "\n")
    print(summary)


if __name__ == "__main__":
    main()
