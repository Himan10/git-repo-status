"""Workflow checks that need history, run state, settings or the whole organisation.

zizmor checks what a workflow file says; these checks look at what happened around it. zizmor's own
findings are not repeated here; they are combined with run state (is the workflow still running,
does it hold secrets?) to decide whether a repo needs a deep investigation.
"""
from collections import defaultdict

from . import zizmor
from .flags import _days, is_bot, ts
from .workflows import FULL_VERSION

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
    return [] if f.get("archived") else [w for w in _workflows(f) if w["state"] == "active"]


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
        if zizmor.escalates(z) and z["file"] in live:
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


def workflow_flags(f, status, now, cfg, index=None):
    return (_idle_wakeups(f, cfg) + _new_actor(f, now, cfg) + _exfil(f) + _zombies(f, status, now, cfg)
            + _zizmor(f, now, cfg) + _ai_agents(f) + _upstream(f, index))


def workflow_hygiene(f):
    a = f.get("actions") or {}
    out = []
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
    seen = set()
    for item in _workflows(f) + (a.get("composite_actions") or []):
        for code, where, _ in item.get("script") or []:
            if code in SCRIPT_HYGIENE and (code, item["path"]) not in seen:
                seen.add((code, item["path"]))
                out.append(f"{SCRIPT_HYGIENE[code]}: {item['path']}")
    return out
