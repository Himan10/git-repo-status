"""Collect raw facts per repository. No judgement here; see flags.py and workflow_flags.py."""
import base64
import fnmatch
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import quote

from repostatus.checks.repository_checks import is_bot, ts
from repostatus.github.api_client import ApiError
from repostatus.checks.ioc_matching import file_names as ioc_file_names
from repostatus.collect.workflow_parser import parse_action, parse_lockfile, parse_workflow, ref_type

HISTORY_DEPTH = 50
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
LOCKFILE = ".github/workflows/actions.lock"
DEPENDABOT = (".github/dependabot.yml", ".github/dependabot.yaml")
ACTION_FILE = re.compile(r"(^|/)action\.ya?ml$")
MAX_ACTION_FILES = 25     # composite actions fetched per repo
WAKE_GAP_DAYS = 30        # pushes after at least this much quiet are examined; the report applies --dormant-days
MAX_WAKE_COMPARES = 5

HISTORY_QUERY = """
query($owner:String!, $name:String!, $n:Int!) {
  repository(owner:$owner, name:$name) {
    defaultBranchRef {
      name
      target { ... on Commit { history(first:$n) { nodes {
        oid committedDate
        author { date email name user { login } }
        committer { date email name user { login } }
        signature { isValid state signer { login } }
      } } } }
    }
    refs(refPrefix:"refs/heads/", first:100,
         orderBy:{field:TAG_COMMIT_DATE, direction:DESC}) {
      totalCount
      nodes { name target { ... on Commit { committedDate } } }
    }
  }
}"""

def _b64file(gh, full, path, ref):
    data, err = gh.try_get(f"repos/{full}/contents/{quote(path)}?ref={quote(ref)}")
    if err or not data or data.get("encoding") != "base64":
        return None
    return base64.b64decode(data["content"]).decode("utf-8", "replace")


def owner_context(gh, owner):
    """Facts gathered once per owner (org or user)."""
    info = gh.get(f"users/{owner}")
    viewer = gh.get("user")["login"]
    is_org = info["type"] == "Organization"
    owner = info["login"]  # GitHub's spelling, whatever case was typed
    ctx = {"owner": owner, "type": info["type"], "viewer": viewer}

    if is_org:
        repos = gh.get(f"orgs/{owner}/repos?type=all&per_page=100", paginate=True)
        _, err = gh.try_get(f"orgs/{owner}/audit-log?per_page=1")
        ctx["audit_log"] = "available" if err is None else f"unavailable ({err})"
    elif owner.lower() == viewer.lower():
        repos = gh.get("user/repos?affiliation=owner&per_page=100", paginate=True)
        ctx["audit_log"] = "n/a (user account)"
    else:
        repos = gh.get(f"users/{owner}/repos?type=owner&per_page=100", paginate=True)
        ctx["audit_log"] = "n/a (user account)"
    ctx["repos"] = repos

    base = f"orgs/{owner}" if is_org else ("user" if owner.lower() == viewer.lower() else f"users/{owner}")
    packages = []
    for ptype in ("container", "npm"):
        pkgs, err = gh.try_get(f"{base}/packages?package_type={ptype}&per_page=100", paginate=True)
        if err:
            ctx.setdefault("package_errors", []).append(f"{ptype}: {err}")
            continue
        for p in pkgs or []:
            versions, verr = gh.try_get(
                f"{base}/packages/{ptype}/{quote(p['name'], safe='')}/versions?per_page=100", paginate=True)
            versions = versions or []
            latest = max(versions, key=lambda v: v["created_at"], default=None)
            packages.append({
                "type": ptype,
                "name": p["name"],
                "repo": (p.get("repository") or {}).get("name"),
                "visibility": p.get("visibility"),
                "versions": len(versions),
                "latest_published": latest["created_at"] if latest else None,
                "latest_tags": ((latest or {}).get("metadata", {}).get("container", {}) or {}).get("tags", []),
                "first_published": min((v["created_at"] for v in versions), default=None),
                "error": verr,
            })
    ctx["packages"] = packages
    return ctx


def _activity(gh, full, default_branch):
    a = {}
    a["latest"] = gh.get(f"repos/{full}/activity?per_page=100", record="activity_latest") or []
    a["default_branch"] = gh.get(
        f"repos/{full}/activity?ref={quote(default_branch, safe='')}&per_page=30",
        record="activity_default") or []
    a["force_pushes"] = gh.get(
        f"repos/{full}/activity?activity_type=force_push&per_page=100", paginate=True,
        record="activity_force_push") or []
    oldest = gh.get(f"repos/{full}/activity?direction=asc&per_page=1") or []
    a["oldest_event"] = oldest[0]["timestamp"] if oldest else None

    def slim(e):
        actor = e.get("actor") or {}
        return {"ts": e["timestamp"], "type": e["activity_type"], "ref": e["ref"],
                "actor": actor.get("login"), "actor_type": actor.get("type"),
                "before": e.get("before"), "after": e.get("after")}
    for k in ("latest", "default_branch", "force_pushes"):
        a[k] = [slim(e) for e in a[k]]
    return a


def _workflows(gh, full, ref, paths, save, visibility=None):
    """Workflows with their run state, plus every file zizmor audits (saved through save(path, text))."""
    wfs, err = gh.try_get(f"repos/{full}/actions/workflows?per_page=100", record="workflows")
    if err:
        return {"error": err, "items": []}
    perms, _ = gh.try_get(f"repos/{full}/actions/permissions")
    token, terr = gh.try_get(f"repos/{full}/actions/permissions/workflow", record="token_permissions")
    items = []
    for w in wfs.get("workflows", []):
        item = {"id": w["id"], "name": w["name"], "path": w["path"], "state": w["state"]}
        runs, _ = gh.try_get(f"repos/{full}/actions/workflows/{w['id']}/runs?per_page=1")
        last = (runs or {}).get("workflow_runs") or []
        item["last_run"] = last[0]["created_at"] if last else None
        item["last_run_event"] = last[0]["event"] if last else None
        item["last_run_conclusion"] = last[0]["conclusion"] if last else None

        if w["path"].startswith(".github/workflows/"):
            text = _b64file(gh, full, w["path"], ref) or ""
            if text:
                save(w["path"], text)
            item.update(parse_workflow(text))
            if item["triggers"] and "schedule" in item["triggers"]:
                sruns, _ = gh.try_get(f"repos/{full}/actions/workflows/{w['id']}/runs?event=schedule&per_page=1")
                s = (sruns or {}).get("workflow_runs") or []
                item["last_scheduled_run"] = s[0]["created_at"] if s else None
        else:
            item["dynamic"] = True  # e.g. Dependabot, CodeQL default setup
        items.append(item)

    out = {"enabled": (perms or {}).get("enabled"), "allowed_actions": (perms or {}).get("allowed_actions"),
           "sha_pinning_required": (perms or {}).get("sha_pinning_required"), "items": items}
    # who may run workflows from fork pull requests; a different setting for public and private repositories
    if visibility == "public":
        fork, ferr = gh.try_get(f"repos/{full}/actions/permissions/fork-pr-contributor-approval")
        out["fork_prs"] = {"approval_policy": (fork or {}).get("approval_policy"), "error": ferr}
    elif visibility:
        fork, ferr = gh.try_get(f"repos/{full}/actions/permissions/fork-pr-workflows-private-repos")
        out["fork_prs"] = dict(fork or {}, error=ferr)
    # Actions policies (workflow execution protections), including ones set for the organisation
    pol, perr = gh.try_get(f"repos/{full}/actions/policies?per_page=100", record="actions_policies")
    out["policies"] = {"error": perr, "items": [{
        "name": p.get("name"), "enforcement": p.get("enforcement"),
        "allowed_events": sorted({e for r in p.get("rules") or [] if r.get("type") == "restrict_action_events"
                                  for e in (r.get("parameters") or {}).get("allowed_events") or []}),
        "restricts_events": any(r.get("type") == "restrict_action_events" for r in p.get("rules") or []),
    } for p in (pol or {}).get("policies") or []]}
    out["token"] = ({"default": token.get("default_workflow_permissions"),
                     "can_approve_prs": token.get("can_approve_pull_request_reviews")} if token
                    else {"error": terr})
    if LOCKFILE in paths:
        text = _b64file(gh, full, LOCKFILE, ref) or ""
        save(LOCKFILE, text)
        out["lockfile"] = dict(parse_lockfile(text), path=LOCKFILE)
    for p in DEPENDABOT:
        if p in paths:
            save(p, _b64file(gh, full, p, ref) or "")
    action_files = sorted(p for p in paths if ACTION_FILE.search(p))
    out["composite_actions"] = []
    for p in action_files[:MAX_ACTION_FILES]:
        text = _b64file(gh, full, p, ref) or ""
        save(p, text)
        out["composite_actions"].append(dict(parse_action(text), path=p))
    if len(action_files) > MAX_ACTION_FILES:
        out["composite_actions_skipped"] = len(action_files) - MAX_ACTION_FILES
    return out


def _workflow_history(gh, full, ref):
    """Recent commits that changed a workflow file: who and when (commit metadata, can be forged)."""
    commits, err = gh.try_get(f"repos/{full}/commits?path=.github/workflows&sha={ref}&per_page=20",
                              record="workflow_commits")
    if err:
        return {"error": err, "items": []}
    return {"items": [{
        "oid": c["sha"],
        "date": c["commit"]["committer"]["date"],
        "author_login": (c.get("author") or {}).get("login"),
        "author_email": c["commit"]["author"]["email"],
        "committer_email": c["commit"]["committer"]["email"],
        "headline": c["commit"]["message"].splitlines()[0][:100] if c["commit"]["message"] else "",
    } for c in commits or []]}


def _idle_wakeups(gh, full, activity, branch):
    """Human pushes to the default branch after a long quiet period, with the files each one changed.

    Times are server-side (activity API). Only the last 100 events are known, so a quiet period that
    started before the oldest of them cannot be measured and is skipped."""
    events = activity.get("latest") or []
    human = sorted((e for e in events if not is_bot(e["actor"], e["actor_type"])), key=lambda e: e["ts"])
    out = []
    for prev, e in zip(human, human[1:]):
        if e["ref"] != f"refs/heads/{branch}" or e["type"] not in ("push", "force_push", "pr_merge"):
            continue
        gap = ts(e["ts"]) - ts(prev["ts"])
        if gap < timedelta(days=WAKE_GAP_DAYS) or not e["before"] or not e["after"] or set(e["before"]) == {"0"}:
            continue
        w = {"ts": e["ts"], "actor": e["actor"], "type": e["type"], "prev_ts": prev["ts"],
             "gap_days": round(gap.total_seconds() / 86400, 1), "before": e["before"], "after": e["after"]}
        if len(out) < MAX_WAKE_COMPARES:
            cmp, err = gh.try_get(f"repos/{full}/compare/{e['before']}...{e['after']}")
            if err:
                w["error"] = err
            else:
                w["files"] = [f["filename"] for f in cmp.get("files") or []]
                w["files_truncated"] = len(w["files"]) >= 300
                w["authors"] = sorted({(c.get("author") or {}).get("login") or c["commit"]["author"]["email"]
                                       for c in cmp.get("commits") or []})
        else:
            w["error"] = "not compared (limit per repo reached)"
        out.append(w)
    return out


BRANCHES_QUERY = """
query($owner:String!, $name:String!, $after:String) {
  repository(owner:$owner, name:$name) {
    refs(refPrefix:"refs/heads/", first:100, after:$after, orderBy:{field:TAG_COMMIT_DATE, direction:DESC}) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes { name target { ... on Commit { oid committedDate
        file(path:".github/workflows") { object { ... on Tree { entries { name oid type } } } }
      } } }
    }
  }
}"""
DEFAULT_MAX_BRANCHES = 1000  # branches per repo whose workflows are checked (1 call per 100)
MAX_BRANCH_BLOBS = 60    # distinct workflow versions fetched per repo
MAX_BRANCH_RUN_LOOKUPS = 50  # branches with older copies whose recent runs are read (1 call each)
RUNNING = {"queued", "in_progress", "waiting", "requested", "pending"}
WORKFLOW_FILE = re.compile(r"\.ya?ml$")


def _branch_workflows(gh, owner, name, default_branch, save, max_branches=DEFAULT_MAX_BRANCHES):
    """Workflow files on every branch, compared with the default branch by content hash.

    One GraphQL call per 100 branches lists each branch's .github/workflows folder with git blob ids;
    only versions that differ from the default branch's are fetched, once each however many branches
    share them, and saved through save(oid, file name, text)."""
    branches, after, total, truncated = [], None, 0, False
    for page in range(max(1, -(-max_branches // 100))):
        data, _ = gh.graphql_partial(BRANCHES_QUERY, record=f"branch_workflows_{page}", owner=owner, name=name,
                                     after=after)
        refs = ((data or {}).get("repository") or {}).get("refs") or {}
        total = refs.get("totalCount", 0)
        for n in refs.get("nodes") or []:
            t = n.get("target") or {}
            entries = (((t.get("file") or {}).get("object") or {}).get("entries")) or []
            branches.append({"name": n["name"], "sha": t.get("oid"), "committed": t.get("committedDate"),
                             "files": {e["name"]: e["oid"] for e in entries
                                       if e.get("type") == "blob" and WORKFLOW_FILE.search(e["name"])}})
        info = refs.get("pageInfo") or {}
        if not info.get("hasNextPage"):
            break
        after = info.get("endCursor")
    else:
        truncated = True
    default = next((b for b in branches if b["name"] == default_branch), {"files": {}})
    branches = branches[:max_branches]
    out = {"total": total, "scanned": len(branches), "truncated": truncated or len(branches) < total,
           "max_branches": max_branches,
           "names": sorted(b["name"] for b in branches), "default_files": sorted(default["files"]),
           "branches": [], "blobs": {}}
    wanted = {}
    for b in branches:
        if b["name"] == default_branch:
            continue
        diff = [{"name": fn, "oid": oid, "copy": "older copy" if fn in default["files"] else "only on this branch"}
                for fn, oid in sorted(b["files"].items()) if default["files"].get(fn) != oid]
        if diff:
            out["branches"].append({"name": b["name"], "sha": b["sha"], "committed": b["committed"], "files": diff})
            for d in diff:
                wanted.setdefault(d["oid"], d["name"])
    oids = sorted(wanted)[:MAX_BRANCH_BLOBS]
    out["blobs_skipped"] = max(0, len(wanted) - len(oids))
    for i in range(0, len(oids), 30):
        chunk = oids[i:i + 30]
        q = ("query($owner:String!, $name:String!) { repository(owner:$owner, name:$name) { "
             + " ".join(f'b{j}: object(oid:"{o}") {{ ... on Blob {{ text isBinary }} }}' for j, o in enumerate(chunk))
             + " } }")
        data, _ = gh.graphql_partial(q, owner=owner, name=name)
        repo = (data or {}).get("repository") or {}
        for j, oid in enumerate(chunk):
            blob = repo.get(f"b{j}") or {}
            text = blob.get("text")
            if text is None or blob.get("isBinary"):
                out["blobs"][oid] = {"name": wanted[oid], "error": "content not available"}
                continue
            save(oid, wanted[oid], text)
            out["blobs"][oid] = dict(parse_workflow(text), name=wanted[oid])
    _branch_runs(gh, f"{owner}/{name}", out["branches"])
    return out


def _branch_runs(gh, full, branches):
    """For branches carrying an older workflow copy: has that copy run there, when last, and is it running now.

    One call per branch (the latest runs on it), most recently committed branches first."""
    order = sorted(branches, key=lambda b: b["committed"] or "", reverse=True)
    for i, b in enumerate(order):
        if i >= MAX_BRANCH_RUN_LOOKUPS:
            b["runs_checked"] = False
            continue
        data, err = gh.try_get(f"repos/{full}/actions/runs?branch={quote(b['name'], safe='')}&per_page=30")
        b["runs_checked"] = err is None
        if err:
            b["runs_error"] = err
            continue
        paths = {f".github/workflows/{d['name']}": d["name"] for d in b["files"]}
        b["runs"] = {}
        for r in (data or {}).get("workflow_runs") or []:  # newest first
            name = paths.get(r.get("path"))
            if not name:
                continue
            if name not in b["runs"]:
                b["runs"][name] = {"created_at": r.get("created_at"), "event": r.get("event"),
                                   "actor": (r.get("triggering_actor") or r.get("actor") or {}).get("login"),
                                   "conclusion": r.get("conclusion"), "url": r.get("html_url"), "running": False}
            if r.get("status") in RUNNING:
                b["runs"][name]["running"] = True


def _runners(gh, full):
    """Names of self-hosted runners registered to the repository (compared with iocs.yml)."""
    data, err = gh.try_get(f"repos/{full}/actions/runners?per_page=100")
    return {"error": err, "names": sorted(r.get("name") for r in (data or {}).get("runners") or [])}


def _run_tags(gh, full, f):
    """A run started by pushing a tag reports the tag's name as its branch. Read the tag names (one call)
    when a run's branch is not among the branches, so tag runs are not mistaken for deleted branches."""
    runs, bw = f.get("recent_runs") or {}, f.get("branch_workflows") or {}
    missing = {r["head_branch"] for r in runs.get("items") or [] if r.get("head_branch")} - set(bw.get("names") or [])
    if not missing or not bw:
        return
    tags, err = gh.try_get(f"repos/{full}/tags?per_page=100", paginate=True)
    runs["tags"] = sorted(missing & {t["name"] for t in tags or []})
    runs["tags_complete"] = err is None


def _recent_runs(gh, full):
    """The last 100 workflow runs on any branch. Kept even after a branch is deleted."""
    data, err = gh.try_get(f"repos/{full}/actions/runs?per_page=100", record="recent_runs")
    if err:
        return {"error": err, "items": []}
    return {"items": [{
        "id": r.get("id"), "path": r.get("path"), "head_branch": r.get("head_branch"), "event": r.get("event"),
        "actor": (r.get("triggering_actor") or r.get("actor") or {}).get("login"),  # who started this attempt
        "actor_type": (r.get("triggering_actor") or r.get("actor") or {}).get("type"),
        "started_by": (r.get("actor") or {}).get("login"),  # who started the first attempt
        "run_attempt": r.get("run_attempt") or 1, "status": r.get("status"),
        "created_at": r.get("created_at"), "conclusion": r.get("conclusion"), "url": r.get("html_url"),
        "head_sha": r.get("head_sha"), "from_fork": (r.get("head_repository") or {}).get("full_name") not in (None, full),
    } for r in (data or {}).get("workflow_runs") or []]}


def _secrets_and_environments(gh, full):
    """Where each secret lives (organisation, repository, environment) and which branches each
    environment allows. Names only; secret values are never readable through the API."""
    out = {"repo_secrets": None, "org_secrets": None, "environments": {}, "errors": []}
    for key, path in (("repo_secrets", f"repos/{full}/actions/secrets?per_page=100"),
                      ("org_secrets", f"repos/{full}/actions/organization-secrets?per_page=100")):
        data, err = gh.try_get(path)
        if err:
            out["errors"].append(f"{key}: {err}")
        else:
            out[key] = sorted(s["name"] for s in (data or {}).get("secrets") or [])
    envs, err = gh.try_get(f"repos/{full}/environments?per_page=100", record="environments")
    if err:
        out["errors"].append(f"environments: {err}")
        return out
    for e in (envs or {}).get("environments") or []:
        pol = e.get("deployment_branch_policy") or {}
        env = {"protected_branches_only": bool(pol.get("protected_branches")),
               "custom": bool(pol.get("custom_branch_policies")), "policies": None,
               "rules": sorted({r.get("type") for r in e.get("protection_rules") or []} - {None}),
               "admins_bypass": e.get("can_admins_bypass", True), "secrets": None}
        if env["custom"]:
            p, perr = gh.try_get(f"repos/{full}/environments/{quote(e['name'], safe='')}/deployment-branch-policies"
                                 f"?per_page=100")
            env["policies"] = None if perr else [{"name": x["name"], "type": x.get("type", "branch")}
                                                 for x in (p or {}).get("branch_policies") or []]
            if perr:
                out["errors"].append(f"{e['name']} branch rules: {perr}")
        s, serr = gh.try_get(f"repos/{full}/environments/{quote(e['name'], safe='')}/secrets?per_page=100")
        if serr:
            out["errors"].append(f"{e['name']} secrets: {serr}")
        else:
            env["secrets"] = sorted(x["name"] for x in (s or {}).get("secrets") or [])
        out["environments"][e["name"]] = env
    return out


def _protection(gh, full, branch):
    b = quote(branch, safe="")
    prot, perr = gh.try_get(f"repos/{full}/branches/{b}/protection", record="branch_protection")
    classic = None
    if prot:
        rpr = prot.get("required_pull_request_reviews") or {}
        classic = {
            "allow_force_pushes": (prot.get("allow_force_pushes") or {}).get("enabled", False),
            "allow_deletions": (prot.get("allow_deletions") or {}).get("enabled", False),
            "pr_required": bool(prot.get("required_pull_request_reviews")),
            "approvals": rpr.get("required_approving_review_count", 0),
            "code_owner_review": rpr.get("require_code_owner_reviews", False),
            "dismiss_stale": rpr.get("dismiss_stale_reviews", False),
            "last_push_approval": rpr.get("require_last_push_approval", False),
            "signatures": (prot.get("required_signatures") or {}).get("enabled", False),
            "status_checks": bool(prot.get("required_status_checks")),
            "enforce_admins": (prot.get("enforce_admins") or {}).get("enabled", False),
        }
    elif perr and "Branch not protected" not in perr:
        classic = {"error": perr}  # unreadable (e.g. no admin access), not the same as unprotected

    rules, rerr = gh.try_get(f"repos/{full}/rules/branches/{b}?per_page=100", paginate=True,
                             record="effective_rules")
    eff = None
    if rules is not None:
        types = {r["type"] for r in rules}
        pr = next((r.get("parameters") or {} for r in rules if r["type"] == "pull_request"), {})
        eff = {
            "types": sorted(types),
            "sources": sorted({f"{r.get('ruleset_source_type')}:{r.get('ruleset_source')}" for r in rules}),
            "force_push_blocked": "non_fast_forward" in types,
            "deletion_blocked": "deletion" in types,
            "pr_required": "pull_request" in types,
            "approvals": pr.get("required_approving_review_count", 0),
            "code_owner_review": pr.get("require_code_owner_review", False),
            "dismiss_stale": pr.get("dismiss_stale_reviews_on_push", False),
            "last_push_approval": pr.get("require_last_push_approval", False),
            "signatures": "required_signatures" in types,
            "status_checks": "required_status_checks" in types,
        }
    else:
        eff = {"error": rerr}
    return {"classic": classic, "rulesets": eff}


def _codeowners(gh, full, ref, paths):
    path = next((p for p in CODEOWNERS_PATHS if p in paths), None)
    if not path:
        return {"path": None}
    text = _b64file(gh, full, path, ref) or ""
    errs, eerr = gh.try_get(f"repos/{full}/codeowners/errors?ref={quote(ref)}", record="codeowners_errors")
    rules = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        rules.append((parts[0], parts[1:]))
    owners = sorted({o for _, os_ in rules for o in os_})
    return {
        "path": path,
        "rules": len(rules),
        "owners": owners,
        "catch_all": any(p in ("*", "/*", "**", "/**") and os_ for p, os_ in rules),
        "workflows_owner": _owner_of(rules, ".github/workflows/ci.yml"),
        "codeowners_owner": _owner_of(rules, path),
        "errors": [{"line": e.get("line"), "kind": e.get("kind"), "message": e.get("message", "").splitlines()[0]}
                   for e in (errs or {}).get("errors", [])],
        "errors_api": eerr,
    }


def _owner_of(rules, path):
    """Approximate CODEOWNERS matching: last matching rule wins."""
    owner = None
    for pat, owners in rules:
        p = pat
        anchored = p.startswith("/") or "/" in p.rstrip("/")
        p = p.lstrip("/")
        if p.endswith("/"):
            p += "**"
        cands = [p, p + "/**"] if not p.endswith("**") else [p]
        match = any(fnmatch.fnmatch(path, c.replace("**", "*")) for c in cands)
        if not match and not anchored:
            match = any(fnmatch.fnmatch(path, "*/" + c.replace("**", "*")) for c in cands)
        if match:
            owner = owners
    return owner  # None = no rule matched; [] = rule matched with no owners


def _autorun(gh, full, ref, paths):
    if ".vscode/tasks.json" not in paths:
        return {"tasks_json": False}
    text = _b64file(gh, full, ".vscode/tasks.json", ref) or ""
    return {
        "tasks_json": True,
        "run_on_folder_open": bool(re.search(r'"runOn"\s*:\s*"folderOpen"', text)),
        "size": len(text),
    }


def collect_repo(gh, owner, meta, recorder_for, files_for=None, branches=True, max_branches=DEFAULT_MAX_BRANCHES):
    """All facts for one repo. files_for(repo, kind) returns save(path, text) for files zizmor audits:
    kind "default" for the default branch, "branches" for other branches' differing workflow versions."""
    full = f"{owner}/{meta['name']}"
    gh = gh.with_recorder(recorder_for(meta["name"]))
    f = {
        "repo": meta["name"],
        "full_name": full,
        "visibility": meta.get("visibility"),
        "description": meta.get("description"),
        "archived": meta.get("archived"),
        "fork": meta.get("fork"),
        "created_at": meta.get("created_at"),
        "pushed_at": meta.get("pushed_at"),
        "default_branch": meta.get("default_branch"),
        "size_kb": meta.get("size"),
        "errors": [],
    }
    try:
        g = gh.graphql(HISTORY_QUERY, record="history", owner=owner, name=meta["name"], n=HISTORY_DEPTH)["repository"]
    except ApiError as e:
        f["errors"].append(str(e))
        return f
    dbr = g.get("defaultBranchRef")
    if not dbr:
        f["empty"] = True
        return f
    branch = dbr["name"]
    save = files_for(meta["name"], "default") if files_for else (lambda path, text: None)
    f["history"] = [{
        "oid": c["oid"],
        "committed_utc": c["committedDate"],
        "author_date": c["author"]["date"],
        "committer_date": c["committer"]["date"],
        "author_email": c["author"]["email"],
        "author_login": (c["author"].get("user") or {}).get("login"),
        "committer_email": c["committer"]["email"],
        "committer_login": (c["committer"].get("user") or {}).get("login"),
        "signature": (c.get("signature") or {}).get("state", "UNSIGNED"),
        "signature_valid": (c.get("signature") or {}).get("isValid", False),
    } for c in dbr["target"]["history"]["nodes"]]
    f["branches"] = {"total": g["refs"]["totalCount"],
                     "items": [{"name": r["name"], "committed": (r["target"] or {}).get("committedDate")}
                               for r in g["refs"]["nodes"]]}

    # read every file at the head commit, so all facts (and zizmor) describe the same snapshot
    head = f["history"][0]["oid"] if f["history"] else branch
    f["head_sha"] = head if f["history"] else None
    tree, err = gh.try_get(f"repos/{full}/git/trees/{quote(head, safe='')}?recursive=1")
    paths = {t["path"] for t in (tree or {}).get("tree", [])}
    f["tree_truncated"] = (tree or {}).get("truncated", False)
    if err:
        f["errors"].append(f"tree: {err}")
    f["dockerfiles"] = sorted(p for p in paths if re.search(r"(^|/)(Dockerfile|Containerfile)[^/]*$", p))
    ioc_names = set(ioc_file_names())
    f["ioc_paths"] = sorted(p for p in paths if p.rsplit("/", 1)[-1] in ioc_names)  # see iocs.yml

    for key, fn in (("activity", lambda: _activity(gh, full, branch)),
                    ("actions", lambda: _workflows(gh, full, head, paths, save, meta.get("visibility"))),
                    ("workflow_history", lambda: _workflow_history(gh, full, head)),
                    ("protection", lambda: _protection(gh, full, branch)),
                    ("codeowners", lambda: _codeowners(gh, full, head, paths)),
                    ("runners", lambda: _runners(gh, full)),
                    ("autorun", lambda: _autorun(gh, full, head, paths))):
        try:
            f[key] = fn()
        except ApiError as e:
            f["errors"].append(f"{key}: {e}")
    if f.get("activity"):
        try:
            f["idle_wakeups"] = _idle_wakeups(gh, full, f["activity"], branch)
        except ApiError as e:
            f["errors"].append(f"idle_wakeups: {e}")
    if branches and (f.get("actions") or {}).get("items") is not None and not (f.get("actions") or {}).get("error"):
        bsave = files_for(meta["name"], "branches") if files_for else (lambda path, text: None)
        for key, fn in (("branch_workflows", lambda: _branch_workflows(
                            gh, owner, meta["name"], branch,
                            lambda oid, name, text: bsave(f"{oid[:12]}/.github/workflows/{name}", text),
                            max_branches)),
                        ("recent_runs", lambda: _recent_runs(gh, full)),
                        ("secrets", lambda: _secrets_and_environments(gh, full))):
            try:
                f[key] = fn()
            except ApiError as e:
                f["errors"].append(f"{key}: {e}")
        _run_tags(gh, full, f)

    collab, cerr = gh.try_get(f"repos/{full}/collaborators?affiliation=all&per_page=100", paginate=True)
    f["collaborators"] = sorted(c["login"] for c in collab or [])
    if cerr:
        f["errors"].append(f"collaborators: {cerr}")
    return f


def all_uses(f):
    """Every remote `uses:` in a repo's workflows and composite actions, with where it appears."""
    a = f.get("actions") or {}
    for w in a.get("items") or []:
        for u in w.get("uses") or []:
            yield w["path"], u
    for c in a.get("composite_actions") or []:
        for u in c.get("uses") or []:
            yield c["path"], u


def _resolve_tag(gh, slug, tag):
    """Commit a tag points to now (annotated tags are followed). Returns (sha, error)."""
    data, err = gh.try_get(f"repos/{slug}/git/ref/tags/{quote(tag, safe='')}")
    if err:
        return None, err
    obj = data.get("object") or {}
    for _ in range(3):
        if obj.get("type") != "tag":
            break
        t, err = gh.try_get(f"repos/{slug}/git/tags/{obj['sha']}")
        if err:
            return None, err
        obj = t.get("object") or {}
    return obj.get("sha"), None


def action_index(gh, facts, workers=4, pace=None):
    """Once per scan, for every upstream action any repo uses: does it still exist under the same
    owner and id, is it archived, and where do the tags we have a recorded commit for point now."""
    slugs, claims = set(), set()
    used = defaultdict(set)  # slug -> {(sub-path, ref, ref type, kind)}: what the organisation runs of it
    for f in facts:
        for _, u in all_uses(f):
            if u["kind"] in ("action", "reusable") and u.get("slug") and "/" in u["slug"]:
                slugs.add(u["slug"])
                used[u["slug"]].add((u.get("path") or "", u.get("ref") or "", u.get("ref_type") or "", u["kind"]))
                if u["ref_type"] == "sha" and u.get("version_comment"):
                    claims.add((u["slug"], u["version_comment"]))
        for d in ((f.get("actions") or {}).get("lockfile") or {}).get("dependencies", {}).values():
            slugs.add(d["slug"])
            if ref_type(d["ref"]) in ("version", "floating"):
                claims.add((d["slug"], d["ref"]))

    pace = pace or (lambda: None)

    def repo(slug):
        pace()
        data, err = gh.try_get(f"repos/{slug}")
        if data:
            return slug, {"status": "ok", "id": data["id"], "owner_id": (data.get("owner") or {}).get("id"),
                          "full_name": data["full_name"], "archived": data.get("archived", False),
                          "owner_type": (data.get("owner") or {}).get("type"), "pushed_at": data.get("pushed_at")}
        if err and err.startswith("404"):
            _, oerr = gh.try_get(f"users/{slug.split('/')[0]}")
            return slug, {"status": "owner gone" if oerr and oerr.startswith("404") else "repo gone"}
        return slug, {"status": f"unknown ({err})"}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        repos = dict(ex.map(repo, sorted(slugs)))

    def tag(claim):
        pace()
        slug, t = claim
        r = repos.get(slug) or {}
        if r.get("status") != "ok":
            return f"{slug}@{t}", {"error": r.get("status")}
        sha, err = _resolve_tag(gh, r["full_name"], t)
        return f"{slug}@{t}", {"commit": sha, "error": err}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        tags = dict(ex.map(tag, sorted(claims)))

    def health(slug):
        return slug, _action_health(gh, repos[slug]["full_name"], slug, used.get(slug, set()), pace)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        healthy = dict(ex.map(health, sorted(s for s in slugs if (repos.get(s) or {}).get("status") == "ok")))
    return {"repos": repos, "tags": tags, "health": healthy}


def _action_health(gh, full, slug, used, pace):
    """Facts for judging an upstream action (checks/action_health.py does the judging): published
    vulnerabilities, latest release and whether releases are immutable, release dates of the exact
    versions used, and whether the action pins what it uses itself. About 3 to 5 calls per action."""
    out = {"errors": []}
    pace()
    rel, err = gh.try_get(f"repos/{full}/releases/latest")
    out["latest_release"] = ({"tag": rel.get("tag_name"), "published_at": rel.get("published_at"),
                              "immutable": rel.get("immutable")} if rel else None)
    if err and not err.startswith("404"):
        out["errors"].append(f"latest release: {err}")
    adv, err = gh.try_get(f"advisories?ecosystem=actions&affects={slug}&per_page=100")
    out["advisories"] = None if err else [{
        "ghsa": a.get("ghsa_id"), "severity": a.get("severity"), "summary": (a.get("summary") or "")[:150],
        "url": a.get("html_url"),
        "ranges": [{"range": v.get("vulnerable_version_range"), "fixed": v.get("first_patched_version")}
                   for v in a.get("vulnerabilities") or [] if ((v.get("package") or {}).get("name") or "").lower() == slug],
    } for a in adv or [] if a.get("withdrawn_at") is None]
    if err:
        out["errors"].append(f"advisories: {err}")
    out["versions"] = {}
    for sub, ref, rtype, kind in sorted(used):
        if rtype == "version" and ref not in out["versions"]:
            r, rerr = gh.try_get(f"repos/{full}/releases/tags/{quote(ref, safe='')}")
            out["versions"][ref] = (r or {}).get("published_at")
    out["inner"] = {}
    for sub in sorted({sub for sub, _, _, kind in used if kind == "action"}):
        for name in ("action.yml", "action.yaml"):
            path = f"{sub}/{name}" if sub else name
            data, aerr = gh.try_get(f"repos/{full}/contents/{quote(path)}")
            if data and data.get("encoding") == "base64":
                a = parse_action(base64.b64decode(data["content"]).decode("utf-8", "replace"))
                out["inner"][sub or "."] = {
                    "unpinned": sorted({f"{u['target']}@{u['ref']}" for u in a["uses"]
                                        if u["kind"] in ("action", "reusable") and u["ref_type"] != "sha"}),
                    "images_without_digest": sorted({i["image"] for i in a["images"] if not i["digest"]}),
                }
                break
    return out
