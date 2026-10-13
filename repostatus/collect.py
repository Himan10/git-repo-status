"""Collect raw facts per repository. No judgement here; see flags.py."""
import base64
import fnmatch
import re
from urllib.parse import quote

import yaml

from .ghapi import ApiError

HISTORY_DEPTH = 50
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")

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

REGISTRY_PATTERNS = {
    "ghcr.io": r"\bghcr\.io\b",
    "docker.io": r"\b(docker\.io|registry-1\.docker\.io|index\.docker\.io)\b",
    "ecr": r"\b\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\b|aws-actions/amazon-ecr-login",
    "gcr/artifact-registry": r"\b([a-z0-9-]+-docker\.pkg\.dev|(\w+\.)?gcr\.io)\b",
    "acr": r"\b[a-z0-9]+\.azurecr\.io\b",
    "quay.io": r"\bquay\.io\b",
}
PUSH_PATTERN = re.compile(r"docker\s+push|docker/build-push-action|push:\s*true|buildah\s+push|podman\s+push|crane\s+(push|copy)")
SECRET_PATTERN = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)")


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


def _workflows(gh, full, ref):
    wfs, err = gh.try_get(f"repos/{full}/actions/workflows?per_page=100", record="workflows")
    if err:
        return {"error": err, "items": []}
    perms, _ = gh.try_get(f"repos/{full}/actions/permissions")
    items = []
    for w in wfs.get("workflows", []):
        item = {"name": w["name"], "path": w["path"], "state": w["state"]}
        runs, _ = gh.try_get(f"repos/{full}/actions/workflows/{w['id']}/runs?per_page=1")
        last = (runs or {}).get("workflow_runs") or []
        item["last_run"] = last[0]["created_at"] if last else None
        item["last_run_event"] = last[0]["event"] if last else None
        item["last_run_conclusion"] = last[0]["conclusion"] if last else None

        if w["path"].startswith(".github/workflows/"):
            text = _b64file(gh, full, w["path"], ref) or ""
            item.update(_parse_workflow(text))
            if item["triggers"] and "schedule" in item["triggers"]:
                sruns, _ = gh.try_get(f"repos/{full}/actions/workflows/{w['id']}/runs?event=schedule&per_page=1")
                s = (sruns or {}).get("workflow_runs") or []
                item["last_scheduled_run"] = s[0]["created_at"] if s else None
        else:
            item["dynamic"] = True  # e.g. Dependabot, CodeQL default setup
        items.append(item)
    return {"enabled": (perms or {}).get("enabled"), "items": items}


def _parse_workflow(text):
    out = {"triggers": [], "crons": [], "secrets": [], "registries": [], "pushes_image": False,
           "runs_on": [], "parse_error": None}
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        out["parse_error"] = str(e).splitlines()[0]
        doc = {}
    on = doc.get("on", doc.get(True)) if isinstance(doc, dict) else None
    if isinstance(on, str):
        out["triggers"] = [on]
    elif isinstance(on, list):
        out["triggers"] = [str(t) for t in on]
    elif isinstance(on, dict):
        out["triggers"] = [str(t) for t in on]
        for s in on.get("schedule") or []:
            if isinstance(s, dict) and "cron" in s:
                out["crons"].append(s["cron"])
    for job in (doc.get("jobs") or {}).values() if isinstance(doc, dict) else []:
        ro = job.get("runs-on") if isinstance(job, dict) else None
        labels = ro if isinstance(ro, list) else [ro] if ro else []
        out["runs_on"] += [str(l) for l in labels if str(l) not in out["runs_on"]]
    out["secrets"] = sorted({s for s in SECRET_PATTERN.findall(text) if s != "GITHUB_TOKEN"})
    out["registries"] = [name for name, pat in REGISTRY_PATTERNS.items() if re.search(pat, text)]
    if "docker/login-action" in text and not out["registries"]:
        out["registries"].append("docker.io")  # login-action without registry: defaults to Docker Hub
    out["pushes_image"] = bool(PUSH_PATTERN.search(text))
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


def collect_repo(gh, owner, meta, recorder_for):
    full = f"{owner}/{meta['name']}"
    gh = gh.with_recorder(recorder_for(meta["name"]))
    f = {
        "repo": meta["name"],
        "full_name": full,
        "visibility": meta.get("visibility"),
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

    tree, err = gh.try_get(f"repos/{full}/git/trees/{quote(branch, safe='')}?recursive=1")
    paths = {t["path"] for t in (tree or {}).get("tree", [])}
    f["tree_truncated"] = (tree or {}).get("truncated", False)
    if err:
        f["errors"].append(f"tree: {err}")
    f["dockerfiles"] = sorted(p for p in paths if re.search(r"(^|/)(Dockerfile|Containerfile)[^/]*$", p))

    for key, fn in (("activity", lambda: _activity(gh, full, branch)),
                    ("actions", lambda: _workflows(gh, full, branch)),
                    ("protection", lambda: _protection(gh, full, branch)),
                    ("codeowners", lambda: _codeowners(gh, full, branch, paths)),
                    ("autorun", lambda: _autorun(gh, full, branch, paths))):
        try:
            f[key] = fn()
        except ApiError as e:
            f["errors"].append(f"{key}: {e}")

    collab, cerr = gh.try_get(f"repos/{full}/collaborators?affiliation=all&per_page=100", paginate=True)
    f["collaborators"] = sorted(c["login"] for c in collab or [])
    if cerr:
        f["errors"].append(f"collaborators: {cerr}")
    return f
