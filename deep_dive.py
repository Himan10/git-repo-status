"""Level 2: investigate force pushes on a repository's default branch. Read-only, API only;
nothing is cloned, so nothing from the repository can execute on this machine.

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
import sys
from datetime import timedelta

from repostatus.flags import evaluate, is_github_commit, ts
from repostatus.ghapi import ApiError, GitHub

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


def write_markdown(path, owner, repo, results):
    L = [f"# Deep dive: {owner}/{repo}\n",
         "All times UTC. Push times come from GitHub (server-side); commit dates come from the commit itself.\n"]
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
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--all-branches", action="store_true", help="include force pushes to non-default branches")
    a = p.parse_args()

    from run import display_path, out_dir
    owner_dir = out_dir(a.owner, create=False)
    facts_path = os.path.join(owner_dir, "facts.json")
    if not os.path.exists(facts_path):
        sys.exit(f"No scan found for {a.owner}. Run ./scan.sh {a.owner} first.")
    with open(facts_path, encoding="utf-8") as fh:
        data = json.load(fh)
    f = next((x for x in data["repos"] if x["repo"].lower() == a.repo.lower()), None)
    if not f:
        sys.exit(f"'{a.repo}' is not in the last scan of {a.owner}. Check the name in "
                 f"out/{a.owner}/repo-status.csv (first column).")
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
    with open(os.path.join(d, f"{a.repo}.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)
    write_markdown(os.path.join(d, f"{a.repo}.md"), a.owner, a.repo, results)
    if not results:
        rows, _ = evaluate([f], data["context"], ts(data["context"]["collected_at"]))
        row = rows[0]
        prot = row["prot"] or {}
        lines = [f"{a.repo}: GitHub has no record of anyone overwriting the history of '{f['default_branch']}' "
                 f"(0 force pushes), so there is nothing to investigate."]
        if prot.get("force_push_blocked") is False:
            why = (" Branch rules are not available for private repositories on GitHub Free."
                   if prot.get("plan_limited") else "")
            lines.append(f"Note: it has not happened, but nothing prevents it. The CSV shows this as "
                         f"'force-push allowed on default branch'.{why}")
        elif prot.get("source") == "unknown":
            lines.append(f"Note: branch rules could not be read ({prot.get('error')}).")
        warnings = [f"{c}: {d}" for c, sev, d in row["flags"] if sev in ("high", "medium")]
        if warnings:
            lines.append("Other warnings for this repository (see summary.md):")
            lines += [f"  - {w}" for w in warnings]
        else:
            lines.append("No other warnings for this repository.")
        print("\n".join(lines))
        return
    print(f"{a.repo}: {len(results)} force push(es) investigated ({gh.calls} API calls).\n"
          f"Report: {display_path(os.path.join(d, a.repo + '.md'))}")


if __name__ == "__main__":
    main()
