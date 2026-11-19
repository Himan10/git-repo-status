"""Workflow checks that need history, run state, settings or the whole organisation.

zizmor checks what a workflow file says; these checks look at what happened around it. zizmor's own
findings are not repeated here; they are combined with run state (is the workflow still running,
does it hold secrets?) to decide whether a repo needs a deep investigation.
"""
import re
from collections import defaultdict

from repostatus.collect import zizmor_runner
from repostatus.checks.repository_checks import _days, is_bot, ts
from repostatus.collect.workflow_parser import FULL_VERSION, branch_matches, runs_on_branch

SCRIPT_HYGIENE = {
    "CURL_PIPE_SHELL": "script pipes a download into a shell",
    "UNPINNED_PIP": "pip install without pinned versions",
    "GO_INSTALL_LATEST": "go install @latest",
    "SECRET_ENCODED": "secret passed through an encoder (log masking misses it)",
    "XTRACE_WITH_SECRETS": "shell tracing (set -x) in a step with secrets",
}


def _is_workflow_file(path):
    return path.startswith(".github/workflows/") or path.rsplit("/", 1)[-1] in ("action.yml", "action.yaml")


def _workflows(f):
    return [w for w in (f.get("actions") or {}).get("items") or [] if not w.get("dynamic")]


def _active(f):
    """Enabled workflows GitHub can run: state "active" (GitHub's word for enabled) and a valid file."""
    if f.get("archived"):
        return []
    invalid = set((f.get("zizmor") or {}).get("invalid") or [])
    return [w for w in _workflows(f) if w["state"] == "active" and w["path"] not in invalid and not w.get("parse_error")]


def _uses(f):
    a = f.get("actions") or {}
    for w in a.get("items") or []:
        for u in w.get("uses") or []:
            yield w["path"], u
    for c in a.get("composite_actions") or []:
        for u in c.get("uses") or []:
            yield c["path"], u


def _idle_wakeups(f, cfg):
    out = []
    for w in f.get("idle_wakeups") or []:
        if w["gap_days"] < cfg["dormant_days"] or "files" not in w:
            continue
        files = w["files"]
        wf = [p for p in files if _is_workflow_file(p)]
        if not wf:
            continue
        detail = (f"{w['actor']} pushed {w['ts'][:10]} after {w['gap_days']:.0f} quiet days "
                  f"({(w['before'] or '')[:7]} -> {(w['after'] or '')[:7]}); changed {', '.join(wf[:3])}")
        if all(p.startswith(".github/") for p in files) and not w.get("files_truncated"):
            out.append(("WORKFLOW_ONLY_PUSH_AFTER_IDLE", "high", detail))
        else:
            out.append(("WORKFLOW_CHANGED_AFTER_IDLE", "medium", f"{detail} and {len(files) - len(wf)} other file(s)"))
    return out


def _new_actor(f, now, cfg):
    hist = f.get("history") or []
    changes = [c for c in (f.get("workflow_history") or {}).get("items") or []
               if not is_bot(c.get("author_login") or "")]
    if not changes or not hist:
        return []
    latest = changes[0]
    who = latest.get("author_login") or latest["author_email"]
    wf_oids = {c["oid"] for c in (f.get("workflow_history") or {}).get("items") or []}
    others = [c for c in hist if c["oid"] not in wf_oids]
    if len(others) < cfg["min_author_commits"] or _days(now, ts(latest["date"])) > cfg["dead_days"]:
        return []
    if any((c.get("author_login") or c["author_email"]) == who for c in others):
        return []
    return [("WORKFLOW_BY_NEW_ACTOR", "medium",
             f"{latest['oid'][:7]} \"{latest['headline']}\" by {who}, dated {latest['date'][:10]}; "
             f"no other commits by them among the last {len(hist)}")]


def _exfil(f):
    a = f.get("actions") or {}
    out = []
    for item in _workflows(f) + (a.get("composite_actions") or []):
        for code, where, detail in item.get("script") or []:
            if code == "EXFIL_PATTERN":
                out.append(("WORKFLOW_EXFIL_PATTERN", "high", f"{item['path']} ({where}): {detail}"))
    return out


def _zombies(f, status, now, cfg):
    if status not in ("dormant", "dead"):
        return []
    out = []
    for w in _active(f):
        ran = ts(w.get("last_run"))
        if w.get("secrets") and ran and _days(now, ran) <= cfg["zombie_days"]:
            out.append(("ZOMBIE_WORKFLOW_WITH_SECRETS", "medium",
                        f"{w['path']} last ran {w['last_run'][:10]} ({w.get('last_run_event')}) "
                        f"with secrets {', '.join(w['secrets'])}"))
    return out


def live_workflows(f, now, cfg):
    """Workflows that still run: enabled, and run recently or holding secrets."""
    return {w["path"] for w in _active(f)
            if w.get("secrets") or (ts(w.get("last_run")) and _days(now, ts(w["last_run"])) <= cfg["live_days"])}


def _zizmor(f, now, cfg):
    live = live_workflows(f, now, cfg)
    groups = defaultdict(list)
    for z in (f.get("zizmor") or {}).get("findings") or []:
        if zizmor_runner.escalates(z) and z["file"] in live:
            groups[z["rule"]].append(f"{z['file']}:{z['line']}")
    return [("ZIZMOR_HIGH_IN_LIVE_WORKFLOW", "high", f"zizmor {rule} in a workflow that still runs: {', '.join(locs[:4])}")
            for rule, locs in sorted(groups.items())]


def _ai_agents(f):
    out = []
    for w in _active(f):
        if w.get("ai_agents") and w.get("untrusted_triggers"):
            acts = sorted({a["action"] for a in w["ai_agents"]})
            out.append(("AI_AGENT_UNTRUSTED_TRIGGER", "medium",
                        f"{w['path']}: {', '.join(acts)} runs on {', '.join(w['untrusted_triggers'])}; "
                        f"text from outsiders can steer it (prompt injection)"))
    return out


def _upstream(f, index):
    """Upstream actions that disappeared, changed hands, or whose tags moved."""
    if not index:
        return []
    repos, tags = index.get("repos") or {}, index.get("tags") or {}
    out, seen = [], set()
    for path, u in _uses(f):
        slug = u.get("slug")
        r = repos.get(slug or "")
        if not r or (slug, path) in seen:
            continue
        seen.add((slug, path))
        if r["status"] == "owner gone":
            out.append(("ACTION_OWNER_GONE", "high", f"{slug} in {path}: the owner account no longer exists, "
                                                      f"so anyone can register it and publish code under that name"))
        elif r["status"] == "repo gone":
            out.append(("ACTION_REPO_GONE", "medium", f"{slug} in {path}: repository no longer exists or is not visible"))
        elif r["status"] == "ok" and r["full_name"].lower() != slug:
            owner_changed = r["full_name"].split("/")[0].lower() != slug.split("/")[0]
            out.append(("ACTION_OWNER_RENAMED" if owner_changed else "ACTION_RENAMED",
                        "high" if owner_changed else "info",
                        f"{slug} in {path} now redirects to {r['full_name']}"
                        + ("; the old owner name can be registered by someone else" if owner_changed else "")))
        if u.get("ref_type") == "sha" and u.get("version_comment") and FULL_VERSION.match(u["version_comment"]):
            now_at = (tags.get(f"{slug}@{u['version_comment']}") or {}).get("commit")
            if now_at and now_at.lower() != u["ref"].lower():
                out.append(("TAG_MOVED", "medium",
                            f"{slug}@{u['ref'][:7]} in {path} is commented {u['version_comment']}, but that tag now "
                            f"points to {now_at[:7]}: the comment is wrong, or the tag was moved after you pinned it"))
    lock = (f.get("actions") or {}).get("lockfile") or {}
    for key, d in (lock.get("dependencies") or {}).items():
        r = repos.get(d["slug"]) or {}
        if r.get("status") == "ok" and d.get("repo_id") and (r["id"] != d["repo_id"] or
                                                             (d.get("owner_id") and r["owner_id"] != d["owner_id"])):
            out.append(("ACTION_REPO_REPLACED", "high",
                        f"{key}: actions.lock recorded repo id {d['repo_id']}, GitHub now has {r['id']} under that name "
                        f"(deleted and re-created, possibly by someone else)"))
        now_at = (tags.get(f"{d['slug']}@{d['ref']}") or {}).get("commit")
        if now_at and d.get("commit") and now_at.lower() != d["commit"].lower():
            if FULL_VERSION.match(d["ref"]):
                out.append(("TAG_MOVED", "high", f"{key}: locked at {d['commit'][:7]}, tag {d['ref']} now points to "
                                                  f"{now_at[:7]}. A full version tag should never move"))
            else:
                out.append(("LOCK_BEHIND_TAG", "info", f"{key}: locked at {d['commit'][:7]}, {d['ref']} has moved on "
                                                       f"to {now_at[:7]} (normal for a major-version tag)"))
    return out


def env_allows(env, branch):
    """Can a job on `branch` use this environment? True, False, or None (cannot tell)."""
    if env.get("custom"):
        if env.get("policies") is None:
            return None
        pats = [p["name"] for p in env["policies"] if p.get("type", "branch") == "branch"]
        return bool(pats) and branch_matches(pats, branch)
    if env.get("protected_branches_only"):
        return None  # depends on branch protection of that branch, which is not read for every branch
    return True


PR_MERGE_REF = "refs/pull/0/merge"  # what GitHub checks environment rules against for pull_request runs


def secret_access(f, job, branch):
    """Which of a job's secrets a run on `branch` could read.

    Organisation and repository secrets reach every branch. Environment secrets reach only jobs that
    name the environment, and only on refs its deployment rule allows; on any other ref GitHub refuses
    to start the job at all. Since 8 Dec 2025 GitHub checks that rule against the run's own ref: the
    branch for push and manual runs, refs/pull/<n>/merge for pull_request runs (pass PR_MERGE_REF),
    and the default branch for pull_request_target. Returns {readable, blocked, unknown, id_token}."""
    sec = f.get("secrets") or {}
    envs = sec.get("environments") or {}
    shared = None if sec.get("repo_secrets") is None or sec.get("org_secrets") is None \
        else set(sec["repo_secrets"]) | set(sec["org_secrets"])
    wanted = set(job.get("secrets") or [])
    env_name = job.get("environment")
    env_secrets = set()
    if env_name:
        env = envs.get(env_name)
        if "${{" in env_name or (env is None and "environment" in " ".join(sec.get("errors") or [])):
            return {"readable": sorted(wanted), "blocked": None, "unknown": True, "id_token": job.get("id_token")}
        if env is not None:
            allowed = env_allows(env, branch)
            if allowed is False:
                names = ", ".join(p["name"] for p in env.get("policies") or []) or "protected branches"
                return {"readable": [], "blocked": f"environment {env_name} allows only {names}",
                        "unknown": False, "id_token": False}
            env_secrets = set(env.get("secrets") or [])
            if allowed is None:
                return {"readable": sorted(wanted), "blocked": None, "unknown": True, "id_token": job.get("id_token")}
    if shared is None:
        return {"readable": sorted(wanted - {"*all*"}) or (["all secrets"] if "*all*" in wanted else []),
                "blocked": None, "unknown": True, "id_token": job.get("id_token")}
    reach = shared | env_secrets
    readable = sorted(reach) if "*all*" in wanted else sorted(wanted & reach)
    return {"readable": readable, "blocked": None, "unknown": False, "id_token": job.get("id_token")}


def _refs_for(routes, branch):
    """The refs GitHub checks environment rules against, for the ways a copy can be started on a branch."""
    refs = {PR_MERGE_REF if r.startswith("pull_request") else branch for r in routes}
    return refs or {branch}


def copy_group(row, now, cfg):
    """flagged: a finding on this copy. active: the branch got a commit, or this copy ran or is running,
    within cfg['dormant_days']. stale: neither (still startable, but nobody seems to use it)."""
    if row.get("exfil") or (row.get("serious") and row.get("runs_via") and (row.get("readable") or row.get("id_token"))):
        return "flagged"
    recent = lambda t: bool(t) and _days(now, ts(t)) <= cfg["dormant_days"]
    run = row.get("last_run") or {}
    if run.get("running") or recent(row.get("committed")) or recent(run.get("created_at")):
        return "active"
    if not row.get("runs_checked", True):
        return "active"  # its runs were not read (limit per repo): do not hide it
    return "stale"


def branch_copies(f, now=None, cfg=None):
    """One row per workflow file on a non-default branch that differs from the default branch's copy.
    With now and cfg, each row also gets its group: flagged, active or stale (see copy_group)."""
    bw = f.get("branch_workflows") or {}
    default_branch = f.get("default_branch")
    by_dir = defaultdict(list)
    for z in (bw.get("zizmor") or {}).get("findings") or []:
        by_dir[z["file"].split("/", 1)[0]].append(z)
    default_serious = defaultdict(set)
    for z in (f.get("zizmor") or {}).get("findings") or []:
        if zizmor_runner.escalates(z):
            default_serious[z["file"].rsplit("/", 1)[-1]].add(z["rule"])
    rows = []
    for b in bw.get("branches") or []:
        for d in b["files"]:
            blob = (bw.get("blobs") or {}).get(d["oid"]) or {}
            if not blob or blob.get("error"):
                rows.append({"branch": b["name"], "committed": b["committed"], "file": d["name"], "oid": d["oid"],
                             "copy": d["copy"], "error": blob.get("error", "not fetched (limit per repo)"),
                             "group": "active" if now else None})
                continue
            routes = runs_on_branch(blob, b["name"], default_branch)
            access = [secret_access(f, job, ref) for job in blob.get("jobs") or [] for ref in _refs_for(routes, b["name"])]
            serious = sorted({z["rule"] for z in by_dir.get(d["oid"][:12], []) if zizmor_runner.escalates(z)}
                             - default_serious.get(d["name"], set()))
            rows.append({
                "branch": b["name"], "committed": b["committed"], "file": d["name"], "oid": d["oid"], "copy": d["copy"],
                "runs_via": routes,
                "last_run": (b.get("runs") or {}).get(d["name"]),
                "runs_checked": b.get("runs_checked", False),
                "readable": sorted({s for a in access for s in a["readable"]}),
                "blocked": sorted({a["blocked"] for a in access if a["blocked"]}),
                "unknown": any(a["unknown"] for a in access),
                "id_token": any(a["id_token"] for a in access),
                "serious": serious,
                "exfil": [d2 for c, _, d2 in blob.get("script") or [] if c == "EXFIL_PATTERN"],
            })
            if now is not None:
                rows[-1]["group"] = copy_group(rows[-1], now, cfg)
    return rows


def _branches(f):
    out = []
    for r in branch_copies(f):
        if r.get("error"):
            continue
        where = f"{r['file']} on branch {r['branch']} ({r['copy']})"
        if r["exfil"]:
            out.append(("BRANCH_WORKFLOW_EXFIL", "high", f"{where}: {r['exfil'][0]}"))
        if r["serious"] and r["runs_via"] and (r["readable"] or r["id_token"]):
            reach = ", ".join(r["readable"]) + (" + OIDC token" if r["id_token"] else "")
            out.append(("OUTDATED_WORKFLOW_ON_BRANCH", "medium",
                        f"{where}: zizmor {', '.join(r['serious'])}; can run via {', '.join(r['runs_via'])}; "
                        f"can read {reach.strip(', ')}"))
    return out


def _runs(f, now, cfg):
    """Runs of workflow files that are not on the default branch, grouped by file and branch."""
    bw = f.get("branch_workflows")
    if not bw:
        return []
    on_default = {f".github/workflows/{n}" for n in bw.get("default_files") or []}
    names = set(bw.get("names") or []) | set((f.get("recent_runs") or {}).get("tags") or [])
    groups = defaultdict(list)
    for r in (f.get("recent_runs") or {}).get("items") or []:
        if (r["path"] or "").startswith(".github/workflows/") and r["path"] not in on_default \
                and r["head_branch"] != f.get("default_branch") and not r["from_fork"] \
                and ts(r["created_at"]) and _days(now, ts(r["created_at"])) <= cfg["live_days"]:
            groups[(r["path"], r["head_branch"])].append(r)
    out = []
    for (path, branch), runs in sorted(groups.items()):
        last = max(runs, key=lambda r: r["created_at"])
        detail = (f"{path} ran {len(runs)} time(s) on branch {branch}, last {last['created_at'][:10]} "
                  f"({last['event']} by {last['actor']}); the file is not on the default branch")
        if branch not in names and not bw.get("truncated"):
            out.append(("DELETED_BRANCH_WORKFLOW_RAN", "high", detail + " and the branch no longer exists"))
        else:
            out.append(("BRANCH_ONLY_WORKFLOW_RAN", "info", detail))
    return out


# Events outsiders can start on a public repository without any access (issues, comments, fork PRs)
OUTSIDER_EVENTS = {"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment",
                   "issues", "issue_comment", "discussion", "discussion_comment", "fork", "watch"}
SHA7 = re.compile(r"\b[0-9a-f]{7,40}\b")


def runs_worth_a_look(f, status, now, cfg, flags=()):
    """Runs from the last 100 that have something unusual about them, each with its reasons.

    Only runs within cfg['live_days']. Reasons (code, text):
      NOT_ON_DEFAULT      ran a workflow file that is not on the default branch
      BRANCH_DELETED      the branch it ran on no longer exists
      NOT_A_COLLABORATOR  a push or manual run started by someone with no access to the repository now
      RERUN_BY_OTHER      a re-run started by someone other than who started the first attempt
      RAN_FLAGGED_CHANGE  it ran a commit that is part of another finding
      INACTIVE_REPO       it ran in a dormant or dead repository
    """
    bw = f.get("branch_workflows") or {}
    on_default = {f".github/workflows/{n}" for n in bw.get("default_files") or []} if bw else None
    names = set(bw.get("names") or []) | set((f.get("recent_runs") or {}).get("tags") or [])
    collaborators = set(f.get("collaborators") or [])
    flagged = {}
    for code, sev, detail in flags:
        if sev in ("high", "medium"):
            for sha in SHA7.findall(detail or ""):
                flagged.setdefault(sha[:7], code)
    out = []
    for r in (f.get("recent_runs") or {}).get("items") or []:
        when = ts(r.get("created_at"))
        if not when or _days(now, when) > cfg["live_days"] or not (r.get("path") or "").startswith(".github/"):
            continue
        reasons = []
        other_branch = r["head_branch"] and r["head_branch"] != f.get("default_branch") and not r.get("from_fork")
        if on_default is not None and other_branch and r["path"] not in on_default:
            reasons.append(("NOT_ON_DEFAULT", "ran a workflow file that is not on the default branch"))
        # a deleted branch alone is normal (pull request branches are deleted after merging); it matters
        # when the workflow that ran is not on the default branch either
        if bw and other_branch and reasons and r["head_branch"] not in names and not bw.get("truncated"):
            reasons.append(("BRANCH_DELETED", f"branch {r['head_branch']} has since been deleted"))
        actor = r.get("actor") or ""
        if collaborators and actor and not is_bot(actor, r.get("actor_type")) and actor not in collaborators \
                and r.get("actor_type") != "Organization" \
                and not (f.get("visibility") == "public" and r.get("event") in OUTSIDER_EVENTS) and not r.get("from_fork"):
            reasons.append(("NOT_A_COLLABORATOR", f"started by {actor}, who has no access to the repository now"))
        if (r.get("run_attempt") or 1) > 1 and r.get("started_by") and actor and actor != r["started_by"]:
            reasons.append(("RERUN_BY_OTHER", f"attempt {r['run_attempt']} re-run by {actor}; "
                                              f"first started by {r['started_by']}"))
        code = flagged.get((r.get("head_sha") or "")[:7])
        if code:
            reasons.append(("RAN_FLAGGED_CHANGE", f"ran commit {r['head_sha'][:7]}, part of {code}"))
        if status in ("dormant", "dead") and _days(now, when) <= cfg["zombie_days"]:
            reasons.append(("INACTIVE_REPO", f"ran in a {status} repository"))
        if reasons:
            out.append(dict(r, reasons=reasons))
    return out


def _run_flags(f, status, now, cfg):
    """Runs started by someone with no access now (push or manual runs, which need write access)."""
    groups = defaultdict(list)
    for r in runs_worth_a_look(f, status, now, cfg):
        if any(c == "NOT_A_COLLABORATOR" for c, _ in r["reasons"]):
            groups[(r["actor"], r["path"])].append(r)
    return [("RUN_BY_NON_COLLABORATOR", "medium",
             f"{actor} started {path} {len(rs)} time(s), last {max(x['created_at'] for x in rs)[:10]} "
             f"({rs[0]['event']}), but has no access to the repository now")
            for (actor, path), rs in sorted(groups.items())]


def _self_hosted_public(f):
    """Self-hosted runners on a public repository: anyone's fork pull request can run code on your machines."""
    if f.get("visibility") != "public":
        return []
    return [("SELF_HOSTED_ON_PUBLIC_REPO", "high", f"{w['path']} runs on {', '.join(w.get('runs_on') or [])}")
            for w in _active(f) if any("self-hosted" in str(x) for x in w.get("runs_on") or [])]


def workflow_flags(f, status, now, cfg, index=None):
    return (_idle_wakeups(f, cfg) + _new_actor(f, now, cfg) + _exfil(f) + _zombies(f, status, now, cfg)
            + _zizmor(f, now, cfg) + _ai_agents(f) + _upstream(f, index) + _branches(f) + _runs(f, now, cfg)
            + _run_flags(f, status, now, cfg) + _self_hosted_public(f))


# GitHub's default rule blocking pull_request_target in public repositories, enforced from this date
# (changelog 2026-09-17, enforcement date updated 2026-10-21)
PRT_BLOCK_DATE = "2026-12-02"
STATIC_CLOUD_KEY = re.compile(r"^(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)|AZURE_(CREDENTIALS|CLIENT_SECRET)|"
                              r"GCP_(SA_KEY|CREDENTIALS|SERVICE_ACCOUNT_KEY)|GOOGLE_(CREDENTIALS|APPLICATION_CREDENTIALS)|"
                              r".*_SERVICE_ACCOUNT_KEY)$")
FORK_APPROVAL = {
    "first_time_contributors_new_to_github": "only accounts new to GitHub need approval",
    "first_time_contributors": "only first-time contributors need approval",
}


def settings_hygiene(f, now=None):
    """Actions settings worth changing: allowed actions, pinning, fork pull requests, environments, cloud keys,
    and pull_request_target against GitHub's default block in public repositories."""
    a = f.get("actions") or {}
    out = []
    if a.get("allowed_actions") == "all":
        out.append("any action from any author may be used (allowed-actions policy is 'all')")
    remote = [u for w in _workflows(f) for u in w.get("uses") or [] if u["kind"] in ("action", "reusable")]
    if a.get("sha_pinning_required") and any(u["ref_type"] != "sha" for u in remote):
        out.append("pinning to a commit is required, so workflows with unpinned actions fail")
    fork = a.get("fork_prs") or {}
    if f.get("visibility") == "public" and fork.get("approval_policy") in FORK_APPROVAL:
        out.append(f"fork pull request workflows run without approval for most outside contributors "
                   f"({FORK_APPROVAL[fork['approval_policy']]})")
    elif f.get("visibility") != "public" and fork.get("run_workflows_from_fork_pull_requests"):
        if fork.get("send_secrets_and_variables"):
            out.append("fork pull request workflows receive the repository's secrets")
        if fork.get("send_write_tokens_to_workflows"):
            out.append("fork pull request workflows get a token that can write")
        if not fork.get("require_approval_for_fork_pr_workflows"):
            out.append("fork pull request workflows run without approval")
    sec = f.get("secrets") or {}
    unreviewed = sorted(env for env, e in (sec.get("environments") or {}).items()
                        if e.get("secrets") and "required_reviewers" not in (e.get("rules") or []))
    if unreviewed:
        plan = (" (below GitHub Enterprise, only public repositories can have required reviewers)"
                if f.get("visibility") != "public" else "")
        out.append(f"environments hold secrets without required reviewers{plan}: {', '.join(unreviewed)}")
    keys = sorted({s for s in (sec.get("repo_secrets") or []) + (sec.get("org_secrets") or [])
                   + [x for e in (sec.get("environments") or {}).values() for x in e.get("secrets") or []]
                   if STATIC_CLOUD_KEY.match(s)})
    if keys:
        out.append(f"static cloud keys stored as secrets (an OIDC login stores none): {', '.join(keys[:4])}")
    prt = [w for w in _active(f) if "pull_request_target" in (w.get("triggers") or [])]
    if prt and f.get("visibility") == "public":
        pols = (a.get("policies") or {}).get("items") or []
        allowed = [p["name"] for p in pols if p.get("enforcement") in ("active", "evaluate")
                   and p.get("restricts_events") and "pull_request_target" in p.get("allowed_events")]
        if not allowed:
            when = "is blocked" if now is not None and f"{now:%Y-%m-%d}" >= PRT_BLOCK_DATE else \
                f"will be blocked from {PRT_BLOCK_DATE}"
            unread = " (the token cannot read policies: GitHub requires Administration write for that)" \
                if (a.get("policies") or {}).get("error") else ""
            out.append(f"pull_request_target {when} by GitHub's default rule for public repositories unless a "
                       f"policy allows it{unread}: {', '.join(w['path'].rsplit('/', 1)[-1] for w in prt)}")
    for w in prt:
        envs = sorted({j["environment"] for j in w.get("jobs") or [] if j.get("environment")})
        if envs:
            out.append(f"environments do not protect pull_request_target workflows, which run as the default "
                       f"branch: {w['path'].rsplit('/', 1)[-1]} uses {', '.join(envs)}")
    return out


def workflow_hygiene(f, now=None, cfg=None, index=None):
    a = f.get("actions") or {}
    out = settings_hygiene(f, now)
    token = a.get("token") or {}
    if token.get("default") == "write":
        out.append("workflow token can write by default (repo setting)")
    if token.get("can_approve_prs"):
        out.append("workflows can approve pull requests (repo setting)")
    remote = defaultdict(set)
    for path, u in _uses(f):
        if u["kind"] == "action":
            remote[path].add(u["slug"])
    wf_remote = [p for p in remote if p.startswith(".github/workflows/")]
    lock = a.get("lockfile")
    if wf_remote and not lock:
        out.append("no actions.lock")
    elif lock and lock.get("error"):
        out.append(f"actions.lock could not be read ({lock['error'][:60]})")
    elif lock:
        missing = [p for p in wf_remote if p not in lock.get("workflows", {})]
        if missing:
            out.append(f"workflows not in actions.lock: {', '.join(sorted(missing)[:3])}")
    for path in (f.get("zizmor") or {}).get("invalid") or []:
        out.append(f"invalid workflow file (GitHub cannot run it): {path}")
    sec = f.get("secrets") or {}
    if sec.get("repo_secrets") is not None:
        shared = set(sec.get("repo_secrets") or []) | set(sec.get("org_secrets") or [])
        used = {s for w in _active(f) for s in w.get("secrets") or []}
        everywhere = sorted(used & shared)
        if everywhere:
            out.append(f"secrets any branch can read (repository or organisation secret, not in an environment): "
                       f"{', '.join(everywhere[:5])}")
    if index and now is not None:
        from repostatus.checks import action_health
        problem = [slug for slug, a, _ in action_health.org_actions(index, [{"f": f}], now)
                   if a["level"] in ("Fix", "Review")]
        if problem:
            out.append(f"uses actions with known problems (see Actions used): {', '.join(problem[:4])}")
    copies = [r for r in branch_copies(f, now, cfg) if not r.get("error")]
    for kind, label in (("older copy", "older workflow copies on other branches"),
                        ("only on this branch", "workflow files only on other branches")):
        mine = [r for r in copies if (r["copy"] == "older copy") == (kind == "older copy")]
        if not mine:
            continue
        branches = sorted({r["branch"] for r in mine})
        stale = sorted({r["branch"] for r in mine if r.get("group") == "stale"} -
                       {r["branch"] for r in mine if r.get("group") != "stale"})
        split = f" ({len(branches) - len(stale)} active, {len(stale)} stale)" if now is not None else ""
        out.append(f"{label}: {len(branches)} branch(es){split}, e.g. {', '.join(branches[:3])}")
    seen = set()
    for item in _workflows(f) + (a.get("composite_actions") or []):
        for code, where, _ in item.get("script") or []:
            if code in SCRIPT_HYGIENE and (code, item["path"]) not in seen:
                seen.add((code, item["path"]))
                out.append(f"{SCRIPT_HYGIENE[code]}: {item['path']}")
    return out
