"""Level 2: investigate one flagged repository. Read-only, API only; nothing is cloned, so nothing
from the repository can execute on this machine.

Sections: force pushes; workflow changes (diffs, who pushed them, what ran afterwards); zizmor with
every audit online; upstream actions whose version tags moved.

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
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from repostatus import zizmor
from repostatus.collect import all_uses
from repostatus.flags import evaluate, is_github_commit, ts
from repostatus.ghapi import ApiError, GitHub
from repostatus.workflows import FULL_VERSION
from repostatus.oscompat import scan_cmd, utf8_console

HERE = os.path.dirname(os.path.abspath(__file__))
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


def _is_workflow_file(name):
    return name.startswith((".github/workflows/", ".github/actions/")) or name.rsplit("/", 1)[-1] in ("action.yml", "action.yaml")


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
            "files": [{"name": x["filename"], "status": x["status"], "+": x["additions"], "-": x["deletions"],
                       "patch": (x.get("patch") or "")[:4000] if _is_workflow_file(x["filename"]) else ""}
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


def workflow_markdown(wf, f):
    L = [f"## Workflow changes (last {wf['since_days']} days)\n"]
    wakes = [w for w in f.get("idle_wakeups") or [] if w.get("files")]
    if wakes:
        L.append("**Pushes after a quiet period** (server-side times)\n")
        L += [f"- {w['ts']} {w['actor']} after {w['gap_days']:.0f} quiet days: {', '.join(w['files'][:8])}"
              + (f" (commits by {', '.join(w.get('authors') or [])})" if w.get("authors") else "") for w in wakes]
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
                L.append(f"| {c['oid'][:7]} | could not be read: {c['error']} | | | | | |")
                continue
            pushed = f"{c['pushed_at']} by {c['pushed_by']}" if c["pushed_at"] else "not the head of a recorded push"
            L.append(f"| {c['oid'][:7]} | {c['headline'].replace('|', '/')} | {c['author']} | {c['date']} | {pushed} | "
                     f"{'yes' if c['verified'] else 'no'} | {', '.join(x['name'] for x in c['files'][:5])} |")
        for c in wf["commits"]:
            for x in c.get("files") or []:
                if x.get("patch"):
                    L += [f"\n**{c['oid'][:7]} {x['name']}** ({x['status']}, +{x['+']} -{x['-']})\n",
                          "````diff", x["patch"], "````"]
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
            L += [f"| {r['created_at']} | {r['event']} | {r['actor']} | {r['conclusion']} | {r['head_sha'][:7]} | "
                  f"[run]({r['url']}) |" for r in runs["items"]]
    risky = [(w["path"], where, d) for w in items.values() for code, where, d in w.get("script") or []
             if code == "EXFIL_PATTERN"]
    if risky:
        L.append("\n**Steps that send secrets or the environment to an outside address** (read these first)\n")
        L += [f"- {p} ({where}): {d}" for p, where, d in risky]
    L.append("")
    return L


def _token():
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if t:
        return t
    p = subprocess.run(["gh", "auth", "token"], capture_output=True, encoding="utf-8", errors="replace")
    return p.stdout.strip() if p.returncode == 0 else None


def zizmor_online(owner_dir, repo, d):
    """zizmor with every audit, including those that ask GitHub, and ignore comments disregarded."""
    root = os.path.join(owner_dir, "workflows", repo)
    if not os.path.isdir(root):
        return {"status": "not run: no workflow files in the last scan", "findings": []}
    exe = zizmor.find()
    v = zizmor.version(exe) if exe else None
    if v != zizmor.VERSION:
        return {"status": f"not run: zizmor {v or 'not found'} (expected {zizmor.VERSION}; "
                          f"start with scan.sh or scan.cmd)", "findings": []}
    token = _token()
    res = zizmor.run(exe, root, raw_path=os.path.join(d, f"{repo}.zizmor.json"), online_token=token,
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
    found = sorted(zz["findings"], key=lambda x: (-zizmor.LEVELS.get(x["severity"], 0),
                                                  -zizmor.LEVELS.get(x["confidence"], 0), x["file"], x["line"] or 0))
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


def write_markdown(path, owner, repo, results, reasons=(), sections=()):
    L = [f"# Deep dive: {owner}/{repo}\n",
         "All times UTC. Push times come from GitHub (server-side); commit dates come from the commit itself.\n"]
    if reasons:
        L.append("**Why this repo is on the list** (from the last scan)\n")
        L += [f"- {c} ({s}): {d}" for c, s, d in reasons] + [""]
    if not results:
        L.append("## Force pushes\n\nGitHub has no record of a force push to the default branch.\n")
    for i, r in enumerate(results, 1):
        e = r["event"]
        L.append(f"## Force push {i}: {e['ts']} by {e['actor']}\n")
        L.append(f"`{(e['before'] or '')[:7]}` -> `{(e['after'] or '')[:7]}` on `{e['ref']}`\n")
        L.append("**Findings**\n")
        L += [f"- {x}" for x in r["findings"]]
        for label, c in (("Old head", r.get("old_head")), ("New head", r.get("new_head"))):
            if c:
                L.append(f"\n**{label}** `{c['oid'][:7]}` \"{c['headline']}\"  ")
                L.append(f"author {c['author_email']} at {c['author_date']}; committer {c['committer_email']} "
                         f"at {c['committer_date']}; signature {c['signature']}")
        if r.get("removed") or r.get("added"):
            L.append("\n| Side | Commit | Message | Author |\n|---|---|---|---|")
            L += [f"| removed | {c['oid'][:7]} | {c['headline'][:70]} | {c['author']} |" for c in r.get("removed", [])]
            L += [f"| added | {c['oid'][:7]} | {c['headline'][:70]} | {c['author']} |" for c in r.get("added", [])]
        if r.get("added_detail"):
            L.append("\n| Added commit | Commit date (claimed) | Pushed (GitHub) | Gap days | Signature |\n|---|---|---|---|---|")
            L += [f"| {d['oid'][:7]} | {d['committed_utc']} | {e['ts']} | {d['gap_days']} | {d['signature']} |"
                  for d in r["added_detail"]]
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


def main(argv=None):
    utf8_console()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--all-branches", action="store_true", help="include force pushes to non-default branches")
    p.add_argument("--since-days", type=int, default=365, help="workflow changes from this many days back")
    a = p.parse_args(argv)

    from run import display_path, out_dir
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
    rows, _ = evaluate([f], data["context"], ts(data["context"]["collected_at"]))
    row = rows[0]
    reasons = [x for x in row["flags"] if x[1] in ("high", "medium")]

    wf = workflow_changes(gh, a.owner, a.repo, f, events, a.since_days)
    zz = zizmor_online(owner_dir, a.repo, d)
    up = upstream_actions(f, data["context"].get("action_index"))
    with open(os.path.join(d, f"{a.repo}.json"), "w", encoding="utf-8") as fh:
        json.dump({"force_pushes": results, "workflow_changes": wf, "zizmor": zz, "upstream": up}, fh, indent=1)
    write_markdown(os.path.join(d, f"{a.repo}.md"), a.owner, a.repo, results, reasons,
                   [workflow_markdown(wf, f), zizmor_markdown(zz), upstream_markdown(up)])
    report_path = display_path(os.path.join(d, a.repo + ".md"))
    summary = (f"{a.repo}: {len(results)} force push(es), {len(wf['commits'])} workflow change(s) and "
               f"{len(zz.get('findings') or [])} zizmor finding(s) investigated ({gh.calls} API calls).\n"
               f"Report: {report_path}")
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
        print("\n".join(lines))
    if reasons:
        print("Reasons this repository is on the list:\n" + "\n".join(f"  - {c}: {x}" for c, _, x in reasons))
    print(summary)


if __name__ == "__main__":
    main()
