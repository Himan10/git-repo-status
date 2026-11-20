import csv
from collections import Counter, defaultdict
from datetime import datetime, timezone

from repostatus.platform_support import scan_cmd
from repostatus.checks import action_health
from repostatus.checks.workflow_checks import branch_copies, runs_worth_a_look

# Why a repo is on the deep-investigation list: (source, what it means, how to check it).
# Source names the tool that raised it, so zizmor-based reasons can sit in the same table later.
REASONS = {
    "FORCE_PUSH_DEFAULT": ("repo-status", "Default branch history was overwritten",
                           "Run the deep dive: it compares the history before and after"),
    "DATE_MISMATCH": ("repo-status", "A commit reached GitHub long after the date it claims",
                      "See who pushed it: an old local commit pushed late is common, a backdated one is not"),
    "FUTURE_DATED_COMMIT": ("repo-status", "A commit claims a date after it was pushed",
                            "The date was set by hand: review the commit"),
    "COMMITTED_BEFORE_AUTHORED": ("repo-status", "Committer date is earlier than author date",
                                  "Normal git never does this: review the commit"),
    "NEW_TIMEZONE": ("repo-status", "Latest commit is in a time zone its author never used before",
                     "Confirm with the author that they made it"),
    "SIGNING_BREAK": ("repo-status", "The author signs their commits, but the latest one is unsigned",
                      "Confirm with the author that they made it"),
    "BAD_SIGNATURE": ("repo-status", "A commit signature does not verify",
                      "Review the commit and the key that signed it"),
    "MULTI_BRANCH_PUSH": ("repo-status", "Same commit pushed to several branches within seconds",
                          "Looks scripted: review the commit on each branch"),
    "VSCODE_AUTORUN": ("repo-status", ".vscode/tasks.json runs a command when the folder is opened",
                       "Read the task before opening the repo in VS Code"),
    "PUBLISHED_AFTER_INACTIVITY": ("repo-status", "A package or image was published after the repo went quiet",
                                   "Check who published it and from which workflow run"),
    # workflows: what happened around them (repo-status) and what they say (zizmor)
    "WORKFLOW_ONLY_PUSH_AFTER_IDLE": ("repo-status", "A quiet repo woke up with a push that changed only workflow files "
                                      "(the GhostAction / Shai-Hulud pattern)",
                                      "Run the deep dive: who pushed, what changed, what ran afterwards"),
    "WORKFLOW_CHANGED_AFTER_IDLE": ("repo-status", "The first push after a long quiet period changed a workflow",
                                    "Run the deep dive and review the workflow change"),
    "WORKFLOW_BY_NEW_ACTOR": ("repo-status", "The latest workflow change was made by someone with no other recent commits",
                              "Run the deep dive; confirm with that person"),
    "WORKFLOW_EXFIL_PATTERN": ("repo-status", "A workflow step sends secrets or the environment to an outside address",
                               "Read the step now; if unexpected, disable the workflow and rotate its secrets"),
    "ZOMBIE_WORKFLOW_WITH_SECRETS": ("repo-status", "A dormant or dead repo still runs a workflow that holds secrets",
                                     "Disable the workflow or delete the secrets if nobody needs them"),
    "ZIZMOR_HIGH_IN_LIVE_WORKFLOW": ("zizmor + repo-status", "zizmor found a serious flaw in a workflow that still "
                                     "runs or holds secrets", "Run the deep dive (zizmor online, every finding)"),
    "AI_AGENT_UNTRUSTED_TRIGGER": ("repo-status", "An AI agent action runs on issues, comments or outside PRs",
                                   "Limit who can trigger it and what its token can do"),
    "ACTION_OWNER_GONE": ("repo-status", "A used action's owner account no longer exists; anyone can claim the name",
                          "Replace or vendor the action before someone registers the name"),
    "ACTION_OWNER_RENAMED": ("repo-status", "A used action's owner was renamed; the old name can be claimed",
                             "Update uses: to the new name"),
    "ACTION_REPO_REPLACED": ("repo-status", "actions.lock recorded a different repository id than GitHub has now",
                             "Do not relock; find out who owns the new repository"),
    "ACTION_REPO_GONE": ("repo-status", "A used action's repository no longer exists or is not visible",
                         "Workflows using it fail; replace it"),
    "TAG_MOVED": ("repo-status", "A version tag of a used action points to a different commit than you pinned or locked",
                  "Run the deep dive; compare the two commits upstream before running the workflow again"),
    # workflows on other branches
    "BRANCH_WORKFLOW_EXFIL": ("repo-status", "A workflow copy on a non-default branch sends secrets or the environment "
                              "to an outside address (the Shai-Hulud pattern)",
                              "Run the deep dive; delete the branch and rotate the secrets it could read"),
    "DELETED_BRANCH_WORKFLOW_RAN": ("repo-status", "A workflow that is not on the default branch ran recently on a "
                                    "branch that has since been deleted", "Run the deep dive; open the runs and read "
                                                                          "their logs while GitHub still keeps them"),
    "RUN_BY_NON_COLLABORATOR": ("repo-status", "A push or manual run was started by someone with no access to the "
                                "repository now", "Check who it is; revoke any token or app still acting for them"),
    "IOC_MATCH": ("repo-status", "Matches an indicator of a known GitHub Actions supply-chain campaign (iocs.yml)",
                  "Treat as compromised: read the match, disable affected workflows, rotate their secrets"),
    "SELF_HOSTED_ON_PUBLIC_REPO": ("repo-status", "A public repository runs workflows on self-hosted runners: "
                                   "outsiders' pull requests can run code on your machines",
                                   "Move the workflow to GitHub-hosted runners"),
    "OUTDATED_WORKFLOW_ON_BRANCH": ("zizmor + repo-status", "An older workflow copy on another branch has a serious "
                                    "flaw the default branch fixed, can still be started there, and can read secrets",
                                    "Delete or update the branch; restrict the secrets to an environment"),
}
# reasons deep_dive.py investigates; the others have a "How to check" that needs no tool
DEEP_DIVE_COVERS = {"FORCE_PUSH_DEFAULT", "WORKFLOW_ONLY_PUSH_AFTER_IDLE", "WORKFLOW_CHANGED_AFTER_IDLE",
                    "WORKFLOW_BY_NEW_ACTOR", "ZIZMOR_HIGH_IN_LIVE_WORKFLOW", "TAG_MOVED", "WORKFLOW_EXFIL_PATTERN",
                    "BRANCH_WORKFLOW_EXFIL", "DELETED_BRANCH_WORKFLOW_RAN", "OUTDATED_WORKFLOW_ON_BRANCH",
                    "RUN_BY_NON_COLLABORATOR"}
SEVERITY_ORDER = {"high": 0, "medium": 1}  # only these put a repo on the list


def deep_reasons(r):
    """Flags that put a repo on the deep-investigation list."""
    return [x for x in r["flags"] if x[1] in SEVERITY_ORDER]


def priority(r):
    """A repo's most severe reason: 'high', 'medium', or '' when it is not on the list."""
    return min((s for _, s, _ in deep_reasons(r)), key=SEVERITY_ORDER.get, default="")


def _cell(text):
    return str(text).replace("|", "\\|")


COLUMNS = [
    "repo", "visibility", "archived", "fork", "status",
    "last_human_push", "last_push_source", "days_since_human_push", "pushed_at",
    "head_commit_date", "head_author", "head_signed", "last_default_pusher",
    "default_branch", "branch_count", "branch_strategy", "branch_prefixes", "stale_branches",
    "protection_source", "force_push_blocked", "pr_required", "approvals", "code_owner_review", "signatures_required",
    "codeowners_path", "codeowners_errors", "codeowners_catch_all", "workflows_owner",
    "actions_enabled", "workflows", "enabled_workflows", "workflows_run_last_90_days", "scheduled_workflows",
    "last_scheduled_run",
    "workflow_secrets", "self_hosted", "registries_in_workflows", "workflow_pushes_image", "dockerfiles",
    "packages", "latest_package_published", "latest_image_tags",
    "vscode_autorun", "force_pushes_default", "force_pushes_other",
    "lockfile", "unpinned_actions", "default_token_permission", "workflow_last_changed", "workflow_last_changed_by",
    "zizmor_status", "zizmor_high", "zizmor_medium", "zizmor_low", "zizmor_top_rules",
    "branches_with_older_workflows", "branches_stale", "branch_only_workflows", "secret_scopes", "runs_worth_a_look",
    "deep_dive", "deep_dive_priority", "deep_dive_reason_codes", "deep_dive_reasons", "hygiene",
    "collection_errors",
]


def _yn(v):
    return "" if v is None else ("yes" if v else "no")


def _rule(v, prot):
    """A branch-rule value; marked when the plan makes the rule impossible, not merely unset."""
    v = _yn(v) if isinstance(v, bool) or v is None else v
    return f"{v} (plan)" if prot.get("plan_limited") and v != "" else v


def row_for(r, now, cfg=None):
    f, prot, br = r["f"], r["prot"] or {}, r["branches"] or {}
    hist = f.get("history") or []
    head = hist[0] if hist else {}
    act = f.get("activity") or {}
    wfs = [w for w in (f.get("actions") or {}).get("items") or [] if not w.get("dynamic")]
    # "active" is GitHub's word for enabled (not disabled); it says nothing about running. An invalid file
    # stays "active" in GitHub's API although GitHub can never run it, so it is not counted as enabled.
    invalid = set((f.get("zizmor") or {}).get("invalid") or [])
    active = [w for w in wfs if w["state"] == "active" and w["path"] not in invalid and not w.get("parse_error")]
    live_days = {**_defaults(), **(cfg or {})}["live_days"]
    ran = [w for w in wfs if w.get("last_run") and (now - datetime.fromisoformat(w["last_run"].replace("Z", "+00:00"))).days
           <= live_days]
    sched = [w for w in active if "schedule" in (w.get("triggers") or [])]
    co = f.get("codeowners") or {}
    fps = act.get("force_pushes") or []
    on_default = [e for e in fps if e["ref"] == f"refs/heads/{f.get('default_branch')}"]
    dpush = [e for e in act.get("default_branch") or [] if e["type"] != "branch_deletion"]
    latest_pkg = max(r["pkgs"], key=lambda p: p["latest_published"] or "", default=None)
    last = r["last"]
    deep = deep_reasons(r)
    return {
        "repo": f["repo"],
        "visibility": f.get("visibility"),
        "archived": _yn(f.get("archived")),
        "fork": _yn(f.get("fork")),
        "status": r["status"],
        "last_human_push": (("before " if r["bound"] else "") + last.strftime("%Y-%m-%d")) if last else "",
        "last_push_source": r["source"],
        "days_since_human_push": int((now - last).days) if last else "",
        "pushed_at": (f.get("pushed_at") or "")[:10],
        "head_commit_date": (head.get("committed_utc") or "")[:10],
        "head_author": head.get("author_login") or head.get("author_email", ""),
        "head_signed": head.get("signature", ""),
        "last_default_pusher": dpush[0]["actor"] if dpush else "",
        "default_branch": f.get("default_branch"),
        "branch_count": br.get("count", ""),
        "branch_strategy": br.get("strategy", ""),
        "branch_prefixes": br.get("prefixes", ""),
        "stale_branches": br.get("stale", ""),
        "protection_source": prot.get("source", ""),
        "force_push_blocked": _rule(prot.get("force_push_blocked"), prot),
        "pr_required": _rule(prot.get("pr_required"), prot),
        "approvals": _rule(prot.get("approvals", ""), prot),
        "code_owner_review": _rule(prot.get("code_owner_review"), prot),
        "signatures_required": _rule(prot.get("signatures"), prot),
        "codeowners_path": co.get("path") or ("none" if "codeowners" in f else ""),
        "codeowners_errors": len(co.get("errors") or []) if co.get("path") else "",
        "codeowners_catch_all": _yn(co.get("catch_all")) if co.get("path") else "",
        "workflows_owner": " ".join(co.get("workflows_owner") or []) if co.get("path") else "",
        "actions_enabled": _yn((f.get("actions") or {}).get("enabled")),
        "workflows": len(wfs),
        "enabled_workflows": len(active),
        "workflows_run_last_90_days": len(ran),
        "scheduled_workflows": "; ".join(f"{w['path'].split('/')[-1]} [{' | '.join(w['crons'])}]" for w in sched),
        "last_scheduled_run": max((w.get("last_scheduled_run") or "" for w in sched), default="")[:10],
        "workflow_secrets": ", ".join(sorted({s for w in active for s in w.get("secrets") or []})),
        "self_hosted": _yn(any("self-hosted" in x for w in active for x in w.get("runs_on") or [])) if wfs else "",
        "registries_in_workflows": ", ".join(sorted({x for w in wfs for x in w.get("registries") or []})),
        "workflow_pushes_image": _yn(any(w.get("pushes_image") for w in wfs)) if wfs else "",
        "dockerfiles": len(f.get("dockerfiles") or []),
        "packages": "; ".join(f"{p['type']}:{p['name']} ({p['versions']} versions)" for p in r["pkgs"]),
        "latest_package_published": (latest_pkg or {}).get("latest_published", "") and latest_pkg["latest_published"][:10],
        "latest_image_tags": ", ".join(((latest_pkg or {}).get("latest_tags") or [])[:3]),
        "vscode_autorun": _yn((f.get("autorun") or {}).get("run_on_folder_open")) if f.get("autorun") else "",
        "force_pushes_default": len(on_default) if act else "",
        "force_pushes_other": len(fps) - len(on_default) if act else "",
        **_workflow_columns(f, now, cfg),
        "runs_worth_a_look": len(runs_worth_a_look(f, r["status"], now, cfg or _defaults(), r["flags"]))
        if f.get("recent_runs") else "",
        "deep_dive": "yes" if deep else "no",
        "deep_dive_priority": priority(r),
        "deep_dive_reason_codes": ", ".join(sorted({c for c, _, _ in deep})),
        "deep_dive_reasons": " | ".join(f"{c}: {d}" for c, s, d in deep),
        "hygiene": " | ".join(r["hygiene"]),
        "collection_errors": " | ".join(f.get("errors") or []),
    }


def _remote_uses(f):
    a = f.get("actions") or {}
    for item in (a.get("items") or []) + (a.get("composite_actions") or []):
        for u in item.get("uses") or []:
            if u["kind"] in ("action", "reusable"):
                yield item["path"], u


def secret_scopes(f):
    """Where each secret the default-branch workflows use is stored, and which branches can read it."""
    sec = f.get("secrets")
    if not sec:
        return ""
    used = sorted({s for w in (f.get("actions") or {}).get("items") or [] for s in w.get("secrets") or []})
    out = []
    for name in used:
        where = []
        if name in (sec.get("org_secrets") or []):
            where.append("organisation (all branches)")
        if name in (sec.get("repo_secrets") or []):
            where.append("repository (all branches)")
        for env, e in (sec.get("environments") or {}).items():
            if name in (e.get("secrets") or []):
                rule = (", ".join(p["name"] for p in e.get("policies") or []) if e.get("custom")
                        else "protected branches" if e.get("protected_branches_only") else "all branches")
                where.append(f"environment {env} ({rule})")
        if not where:
            where.append("unverified" if sec.get("errors") else "not found")
        out.append(f"{name}: {'; '.join(where)}")
    return " | ".join(out)


def _workflow_columns(f, now=None, cfg=None):
    a = f.get("actions") or {}
    lock = a.get("lockfile")
    remote = list(_remote_uses(f))
    wh = ((f.get("workflow_history") or {}).get("items") or [{}])[0]
    z = f.get("zizmor") or {}
    zf = [x for x in z.get("findings") or [] if not x.get("ignored")]
    sev = Counter(x["severity"] for x in zf)
    return {
        "lockfile": ("error" if lock.get("error") else "yes") if lock else ("no" if remote else ""),
        "unpinned_actions": sum(1 for _, u in remote if u["ref_type"] != "sha") if remote else "",
        "default_token_permission": (a.get("token") or {}).get("default") or "",
        "workflow_last_changed": (wh.get("date") or "")[:10],
        "workflow_last_changed_by": wh.get("author_login") or wh.get("author_email") or "",
        "zizmor_status": z.get("status", ""),
        "zizmor_high": sev["high"] if z.get("status") == "ok" else "",
        "zizmor_medium": sev["medium"] if z.get("status") == "ok" else "",
        "zizmor_low": sev["low"] if z.get("status") == "ok" else "",
        "zizmor_top_rules": ", ".join(f"{k}({v})" for k, v in Counter(x["rule"] for x in zf).most_common(3)),
        **_branch_columns(f, now, cfg),
    }


def _defaults():
    from repostatus.checks.repository_checks import DEFAULTS
    return DEFAULTS


def _branch_columns(f, now=None, cfg=None):
    if now is not None and cfg is None:
        from repostatus.checks.repository_checks import DEFAULTS
        cfg = DEFAULTS
    if not f.get("branch_workflows"):
        return {"branches_with_older_workflows": "", "branches_stale": "", "branch_only_workflows": "",
                "secret_scopes": secret_scopes(f)}
    copies = [r for r in branch_copies(f, now, cfg) if not r.get("error")]
    branches = {r["branch"] for r in copies}
    return {
        "branches_with_older_workflows": len({r["branch"] for r in copies if r["copy"] == "older copy"}),
        "branches_stale": len(branches - {r["branch"] for r in copies if r.get("group") != "stale"}),
        "branch_only_workflows": len({(r["branch"], r["file"]) for r in copies if r["copy"] != "older copy"}),
        "secret_scopes": secret_scopes(f),
    }


def write_inventory(path, rows, ctx, now=None):
    """One line per action and ref: where it is used, whether it is pinned or locked, upstream state, health."""
    index = (ctx.get("action_index") or {}).get("repos") or {}
    health = {slug: a for slug, a, _ in action_health.org_actions(ctx.get("action_index"), rows, now)} if now else {}
    agg = defaultdict(lambda: {"repos": set(), "files": set(), "locked": set()})
    for r in rows:
        f = r["f"]
        lock = (f.get("actions") or {}).get("lockfile") or {}
        locked = {k.split("@")[0].lower() for k in (lock.get("dependencies") or {})}
        for p, u in _remote_uses(f):
            e = agg[(u["target"].lower(), u["ref"], u["ref_type"])]
            e["repos"].add(f["repo"])
            e["files"].add(f"{f['repo']}:{p}")
            if u["target"].lower() in locked or u.get("slug") in locked:
                e["locked"].add(f["repo"])
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["action", "ref", "ref_type", "repos", "repos_with_lockfile_entry", "upstream", "health",
                    "problems", "maintainer_and_releases", "used_in"])
        for (target, ref, rtype), e in sorted(agg.items(), key=lambda kv: (-len(kv[1]["repos"]), kv[0])):
            up = index.get("/".join(target.split("/")[:2]))
            upstream = "" if not up else (up["status"] if up["status"] != "ok" else
                                          ("archived" if up.get("archived") else "ok"))
            h = health.get("/".join(target.split("/")[:2])) or {}
            w.writerow([target, ref, rtype, len(e["repos"]), len(e["locked"]), upstream, h.get("level", ""),
                        "; ".join(t for _, t in h.get("problems") or []), "; ".join(h.get("notes") or []),
                        "; ".join(sorted(e["files"])[:20])])


RUN_COLUMNS = ["repo", "started", "workflow", "branch", "event", "started_by", "attempt", "result", "reasons",
               "reason_codes", "link"]
RUN_STRENGTH = {"BRANCH_DELETED": 3, "NOT_A_COLLABORATOR": 3, "RAN_FLAGGED_CHANGE": 2, "NOT_ON_DEFAULT": 1,
                "RERUN_BY_OTHER": 1, "INACTIVE_REPO": 1}


def _worth_a_look(rows, now, cfg):
    """[(row, run)] for every run worth a look, strongest reasons first."""
    out = [(r, x) for r in rows if r["f"].get("recent_runs")
           for x in runs_worth_a_look(r["f"], r["status"], now, cfg, r["flags"])]
    return sorted(out, key=lambda rx: (-sum(RUN_STRENGTH.get(c, 1) for c, _ in rx[1]["reasons"]),
                                       rx[1]["created_at"]), reverse=False)


def write_runs_csv(path, rows, now, cfg):
    """runs-worth-a-look.csv: every run from the last scan's run history that has a reason to look at it."""
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=RUN_COLUMNS)
        w.writeheader()
        for r, x in _worth_a_look(rows, now, cfg):
            w.writerow({"repo": r["f"]["repo"], "started": x["created_at"], "workflow": x["path"],
                        "branch": x["head_branch"], "event": x["event"], "started_by": x["actor"],
                        "attempt": x.get("run_attempt") or 1, "result": x.get("conclusion") or x.get("status") or "",
                        "reasons": "; ".join(t for _, t in x["reasons"]),
                        "reason_codes": ", ".join(c for c, _ in x["reasons"]), "link": x["url"]})


def _runs_section(rows, cfg, now):
    cfg = {**_defaults(), **cfg}
    found = _worth_a_look(rows, now, cfg)
    checked = [r for r in rows if r["f"].get("recent_runs")]
    L = [f"\n## Runs worth a look ({len(found)})\n",
         f"From the last 100 runs of each of {len(checked)} repositories, within {cfg['live_days']} days: only runs "
         f"with something unusual about them, each with its reason. Every one is in `runs-worth-a-look.csv`.\n"]
    if not found:
        L.append("None.")
        return L
    L.append("| Repo | Started | Workflow | Branch | Event | By | Why | Run |\n|---|---|---|---|---|---|---|---|")
    for r, x in found[:30]:
        L.append(f"| {r['f']['repo']} | {x['created_at'][:16].replace('T', ' ')} | {x['path'].rsplit('/', 1)[-1]} | "
                 f"{_cell(x['head_branch'])} | {x['event']} | {x['actor']} | "
                 f"{_cell('; '.join(t for _, t in x['reasons']))} | [run]({x['url']}) |")
    if len(found) > 30:
        L.append(f"\n{len(found) - 30} more in `runs-worth-a-look.csv`.")
    return L


BRANCH_COLUMNS = ["repo", "branch", "group", "workflow", "copy", "last_commit", "last_run", "last_run_event",
                  "running_now", "can_be_started_by", "secrets_it_can_read", "oidc_login", "serious_zizmor_findings",
                  "link"]


def write_branch_csv(path, rows, now, cfg):
    """branch-workflows.csv: every workflow copy on a non-default branch, including stale ones."""
    from repostatus.reports.github_links import file_url
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=BRANCH_COLUMNS)
        w.writeheader()
        for r in rows:
            f = r["f"]
            if not f.get("branch_workflows"):
                continue
            for c in branch_copies(f, now, cfg):
                run = c.get("last_run") or {}
                w.writerow({
                    "repo": f["repo"], "branch": c["branch"], "group": c.get("group") or "", "workflow": c["file"],
                    "copy": c["copy"], "last_commit": (c.get("committed") or "")[:10],
                    "last_run": (run.get("created_at") or "")[:10], "last_run_event": run.get("event") or "",
                    "running_now": "yes" if run.get("running") else "no",
                    "can_be_started_by": ", ".join(c.get("runs_via") or []),
                    "secrets_it_can_read": "" if c.get("error") else _reach(c),
                    "oidc_login": "yes" if c.get("id_token") else "no",
                    "serious_zizmor_findings": ", ".join(c.get("serious") or []),
                    "link": file_url(f["full_name"], c["branch"], ".github/workflows/" + c["file"]),
                })


def write_csv(path, rows, now, cfg=None):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:  # BOM: Excel on Windows reads UTF-8
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for r in sorted(rows, key=lambda r: (r["status"] != "dead", r["status"] != "dormant", r["f"]["repo"])):
            w.writerow(row_for(r, now, cfg))


def _deep_section(deep, owner):
    """Counts by reason, then one line per repo, then every warning in full."""
    by_code = {}
    for r in deep:
        for code, sev, _ in deep_reasons(r):
            e = by_code.setdefault(code, {"sev": sev, "repos": set()})
            e["repos"].add(r["f"]["repo"])
            if SEVERITY_ORDER[sev] < SEVERITY_ORDER[e["sev"]]:
                e["sev"] = sev
    L = ["Each repository is counted once, however many reasons it has. Its priority is its most severe reason.\n",
         "| Reason | Source | Severity | Repos | What it means | How to check |",
         "|---|---|---|---|---|---|"]
    for code, e in sorted(by_code.items(), key=lambda kv: (SEVERITY_ORDER[kv[1]["sev"]], -len(kv[1]["repos"]), kv[0])):
        source, meaning, check = REASONS.get(code, ("repo-status", "", ""))
        L.append(f"| {code} | {source} | {e['sev']} | {len(e['repos'])} | {meaning} | {check} |")

    cmd = scan_cmd()
    L += ["", "| Repo | Status | Priority | Reasons | Deep dive |", "|---|---|---|---|---|"]
    for r in sorted(deep, key=lambda r: (SEVERITY_ORDER[priority(r)], r["f"]["repo"].lower())):
        codes = sorted({c for c, _, _ in deep_reasons(r)})
        dd = f"`{cmd} {owner} deep {r['f']['repo']}`" if DEEP_DIVE_COVERS & set(codes) else "-"
        L.append(f"| {r['f']['repo']} | {r['status']} | {priority(r)} | {', '.join(codes)} | {dd} |")
    L.append("\nA deep dive command is shown when `deep` can investigate one of the repo's reasons. "
             "For the other reasons, follow \"How to check\" above.")

    L += ["\n### Details\n", "| Repo | Status | Signal | Detail |", "|---|---|---|---|"]
    for r in deep:
        for code, sev, detail in deep_reasons(r):
            L.append(f"| {r['f']['repo']} | {r['status']} | {code} ({sev}) | {_cell(detail)} |")
    return L


def _zizmor_section(ctx, rows):
    z = ctx.get("zizmor") or {}
    L = ["\n## Workflow security (zizmor)\n"]
    if z.get("status") != "ok":
        L.append(f"zizmor {z.get('status', 'did not run')}. The checks below rely on it, so they are missing "
                 "from this report.")
        return L
    ran = [r for r in rows if (r["f"].get("zizmor") or {}).get("status") == "ok"]
    failed = [r["f"]["repo"] for r in rows if (r["f"].get("zizmor") or {}).get("status", "ok") != "ok"]
    by_rule = defaultdict(lambda: {"sev": Counter(), "repos": set()})
    for r in ran:
        for x in r["f"]["zizmor"]["findings"]:
            if not x.get("ignored"):
                e = by_rule[x["rule"]]
                e["sev"][x["severity"]] += 1
                e["repos"].add(r["f"]["repo"])
    online = z.get("online") or {}
    L.append(f"zizmor {z.get('version')} audited the workflow files of {len(ran)} repositories. "
             + (f"Online audits (known-vulnerable actions, impostor commits, ref confusion) ran once for the whole "
                f"organisation: {online.get('findings', 0)} finding(s), about {online.get('api_calls', 0)} API calls. "
                if online.get("status") == "ok" else f"Online audits: {online.get('status', 'not run')}. ")
             + (f"zizmor could not process {len(online['skipped'])} file(s), so the online audits skipped them "
                f"(every other file was audited): {', '.join(online['skipped'][:10])}. " if online.get("skipped") else "")
             + "A deep dive on a repository also shows findings hidden by `# zizmor: ignore` comments.\n")
    if failed:
        L.append(f"zizmor could not audit {len(failed)} repo(s): {', '.join(failed[:10])} (see Collection errors).\n")
    if not by_rule:
        L.append("No findings.")
        return L
    L.append("| Rule | High | Medium | Low | Repos |\n|---|---|---|---|---|")
    order = sorted(by_rule.items(), key=lambda kv: (-kv[1]["sev"]["high"], -len(kv[1]["repos"]), kv[0]))
    for rule, e in order:
        L.append(f"| [{rule}](https://docs.zizmor.sh/audits/#{rule}) | {e['sev']['high']} | {e['sev']['medium']} | "
                 f"{e['sev']['low']} | {len(e['repos'])} |")
    return L


def _reach(r):
    if r.get("error"):
        return r["error"]
    if r["blocked"] and not r["readable"]:
        return "none: " + "; ".join(r["blocked"])
    text = ", ".join(r["readable"]) or "none"
    if r["id_token"]:
        text += " + OIDC token"
    return text + (" (unverified)" if r["unknown"] else "")


def _last_activity(c):
    """Latest of the branch's last commit and this copy's last run, as YYYY-MM-DD."""
    return max((c.get("committed") or "")[:10], ((c.get("last_run") or {}).get("created_at") or "")[:10])


def _last_run_text(c):
    run = c.get("last_run")
    if not c.get("runs_checked"):
        return "not checked"
    if not run:
        return "never (in its latest runs)"
    return ("RUNNING NOW; " if run.get("running") else "") + f"{run['created_at'][:10]} ({run['event']})"


def _branches_section(rows, cfg, now):
    cfg = {**_defaults(), **cfg}
    scanned = [r for r in rows if r["f"].get("branch_workflows")]
    if not scanned:
        return ["\n## Workflows on other branches\n", "Not checked (--skip-branches)."]
    copies = [(r, c) for r in scanned for c in branch_copies(r["f"], now, cfg)]
    L = ["\n## Workflows on other branches\n",
         "`push`, `pull_request` and manual (`workflow_dispatch`) runs use the copy of a workflow on the branch they "
         "run on, and organisation and repository secrets reach every branch. A workflow fixed on the default branch "
         "can therefore still run in its old form on another branch.\n",
         f"Copies are grouped: **flagged** (a finding on the copy), **active** (the branch got a commit, or the copy "
         f"ran, in the last {cfg['dormant_days']} days, or it is running now) and **stale** (neither). Stale copies "
         f"can still be started by anyone with write access, so deleting those branches is the fix. Every copy is in "
         f"`branch-workflows.csv`.\n"]
    total = sum(r["f"]["branch_workflows"]["total"] for r in scanned)
    checked = sum(r["f"]["branch_workflows"]["scanned"] for r in scanned)
    L.append(f"{checked} of {total} branches checked in {len(scanned)} repositories.\n")
    if not copies:
        L.append("Every branch has the same workflow files as its default branch.")
    else:
        per_repo = defaultdict(lambda: {"flagged": set(), "active": set(), "stale": set(), "running": 0, "secrets": 0})
        for r, c in copies:
            e = per_repo[r["f"]["repo"]]
            e[c.get("group") or "active"].add(c["branch"])
            e["running"] += bool((c.get("last_run") or {}).get("running"))
            e["secrets"] += bool(c.get("readable") or c.get("id_token"))
        L.append("| Repo | Flagged | Active | Stale | Running now | Copies that can read secrets |\n|---|---|---|---|---|---|")
        for repo, e in sorted(per_repo.items(), key=lambda kv: (-len(kv[1]["flagged"]), -len(kv[1]["active"]), kv[0])):
            L.append(f"| {repo} | {len(e['flagged'])} | {len(e['active'])} | {len(e['stale'])} | {e['running']} | "
                     f"{e['secrets']} |")
        shown = [(r, c) for r, c in copies if c.get("group") in ("flagged", "active")]
        if shown:
            L.append("\n**Flagged and active copies**\n")
            L.append("| Repo | Branch | Group | Workflow | Copy | Last commit | Last run | Can be started by | "
                     "Secrets it can read | Serious zizmor findings |\n|---|---|---|---|---|---|---|---|---|---|")
            order = sorted(shown, key=lambda rc: (rc[1]["group"] != "flagged", rc[0]["f"]["repo"].lower(), rc[1]["branch"]))
            for r, c in order[:40]:
                L.append(f"| {r['f']['repo']} | {_cell(c['branch'])} | {c['group']} | {c['file']} | {c['copy']} | "
                         f"{(c['committed'] or '')[:10]} | {_last_run_text(c)} | "
                         f"{', '.join(c.get('runs_via') or []) or 'no (only default-branch triggers)'} | "
                         f"{_cell(_reach(c))} | {', '.join(c.get('serious') or []) or '-'} |")
            if len(shown) > 40:
                L.append(f"\n{len(shown) - 40} more in `branch-workflows.csv`.")
        stale = defaultdict(list)
        for r, c in copies:
            if c.get("group") == "stale":
                stale[r["f"]["repo"]].append(c)
        if stale:
            L.append("\n**Stale copies** (one line per repository)\n")
            for repo, cs in sorted(stale.items()):
                n = len({c["branch"] for c in cs})
                reach = sum(1 for c in cs if c.get("readable") or c.get("id_token"))
                L.append(f"- {repo}: {n} stale branch(es) carry old workflow copies; last activity "
                         f"{max(_last_activity(c) for c in cs)}; "
                         + (f"{reach} copy(ies) can read secrets" if reach else "none can read secrets")
                         + ". Delete the branches if nobody needs them.")
    ran = [(r["f"]["repo"], d) for r in scanned for code, _, d in r["flags"]
           if code in ("BRANCH_ONLY_WORKFLOW_RAN", "DELETED_BRANCH_WORKFLOW_RAN")]
    if ran:
        L.append(f"\n**Runs of workflows that are not on the default branch** (last {cfg['live_days']} days, "
                 "not counting pull requests from forks)\n")
        L += [f"- {repo}: {d}" for repo, d in ran]
    bypass = sorted({f"{r['f']['repo']}/{env}" for r in scanned
                     for env, e in ((r["f"].get("secrets") or {}).get("environments") or {}).items()
                     if e.get("admins_bypass") and (e.get("custom") or e.get("protected_branches_only"))})
    unverified = sorted(r["f"]["repo"] for r in scanned if (r["f"].get("secrets") or {}).get("errors"))
    L += ["\n**What this cannot see**\n",
          "- **Cloud logins (OIDC).** \"+ OIDC token\" means the copy can ask GitHub for a login token for AWS, Azure "
          "or Google Cloud. Whether the cloud accepts a token from that branch is decided by the cloud's trust policy "
          "(the `sub` condition), which Repo Status cannot read. Check that it requires the environment or the default "
          "branch, not the whole repository.",
          "- **Admin bypass.** " + (f"These environments let repository admins deploy from any branch: "
                                    f"{', '.join(bypass)}." if bypass else "No environment with a branch rule lets "
                                                                          "admins bypass it."),
          "- **`GITHUB_TOKEN`** is available on every branch, with the permissions that copy asks for.",
          "- **Secret locations.** " + (f"Secret names could not be read for {', '.join(unverified[:10])} (the token "
                                        "needs read access to Secrets and Environments), so every secret is assumed "
                                        "readable there, marked (unverified)." if unverified else
                                        "Secret names were read for every repository."),
          "- **Branch filters** with `+` or `[ ]` are not evaluated; such copies count as able to run. Tags are not "
          "checked."]
    capped = sorted(f"{r['f']['repo']} ({r['f']['branch_workflows']['scanned']} of "
                    f"{r['f']['branch_workflows']['total']})" for r in scanned if r["f"]["branch_workflows"]["truncated"])
    L.append("- **Branches checked.** " + (
        f"These repositories have more branches than the limit (--max-branches); their oldest branches were not "
        f"checked: {', '.join(capped)}." if capped else "Every branch of every repository was checked."))
    return L


def _ioc_section(rows):
    from repostatus.checks.ioc_matching import load_iocs
    iocs = load_iocs()
    hits = [(r["f"]["repo"], d) for r in rows for c, _, d in r["flags"] if c == "IOC_MATCH"]
    windows = [(r["f"]["repo"], d) for r in rows for c, _, d in r["flags"] if c == "IOC_EXPOSURE_WINDOW"]
    L = [f"\n## Known attack indicators ({len(hits)} match(es))\n",
         f"Checked against {len(iocs['campaigns'])} published GitHub Actions supply-chain campaigns in `iocs.yml` "
         f"(updated {iocs['updated'] or 'unknown'}): "
         + ", ".join(c["name"] for c in iocs["campaigns"]) + ".\n"]
    L += [f"- **{repo}**: {d}" for repo, d in hits] if hits else ["No match."]
    if windows:
        L.append("\n**Actions that were compromised for a while, used here by tag.** Runs in the window ran the "
                 "attackers' code; check them with the `uses` command.\n")
        L += [f"- {repo}: {d}" for repo, d in windows]
    return L


def _actions_section(ctx, rows, now):
    index = ctx.get("action_index") or {}
    remote = [(r["f"]["repo"], p, u) for r in rows for p, u in _remote_uses(r["f"])]
    if not remote:
        return []
    with_wf = {repo for repo, _, _ in remote}
    locked = [r["f"]["repo"] for r in rows if (r["f"].get("actions") or {}).get("lockfile")]
    unpinned = sum(1 for _, _, u in remote if u["ref_type"] != "sha")
    L = ["\n## Actions used\n",
         f"{len(remote)} `uses:` of {len({u['target'].lower() for _, _, u in remote})} different actions in "
         f"{len(with_wf)} repositories. {unpinned} ({100 * unpinned // len(remote)}%) are not pinned to a commit. "
         f"{len(locked)} of {len(with_wf)} repositories have an actions.lock.\n"]
    if not index:
        L.append("Upstream actions were not checked (--skip-action-check).")
    else:
        assessed = action_health.org_actions(index, rows, now)
        bad = [x for x in assessed if x[1]["level"] in ("Fix", "Review")]
        L.append(f"**Action health.** {len(assessed) - len(bad)} of {len(assessed)} actions have no known problems: "
                 f"no published vulnerability in the versions used, maintained, released over "
                 f"{action_health.COOLDOWN_DAYS} days ago, and pinning what they use themselves. That does not prove "
                 f"an action safe; it means these checks found nothing.\n")
        if bad:
            L.append("| Action | Result | Problems | Used in |\n|---|---|---|---|")
            for slug, a, users in bad:
                L.append(f"| {slug} | {a['level']} | {_cell('; '.join(t for _, t in a['problems']))} | "
                         f"{', '.join(users[:5])}{' and more' if len(users) > 5 else ''} |")
            L.append("")
    top = Counter(u["target"].lower() for _, _, u in remote).most_common(5)
    L.append("\nMost used: " + ", ".join(f"{t} ({n})" for t, n in top) +
             ". Every action, with where it is used: `actions-inventory.csv` (a list to keep for incident response; no need to read it after every scan). "
             f"After an upstream compromise: `{scan_cmd()} {ctx['owner']} uses <owner/action> --since YYYY-MM-DD`.")
    return L


WHERE_TO_FIX = [  # (start of hygiene note, where)
    ("force-push allowed", "Settings > Rules (or Branches)"), ("no PR required", "Settings > Rules (or Branches)"),
    ("CODEOWNERS not enforced", "Settings > Rules (or Branches): require review from code owners"),
    ("branch rules could not be read", "Your token: needs admin access to the repository"),
    ("no CODEOWNERS", "File `.github/CODEOWNERS`"), ("CODEOWNERS errors", "File `.github/CODEOWNERS`"),
    ("workflows have no code owner", "File `.github/CODEOWNERS`: add a rule for `.github/workflows/`"),
    ("workflow token can write by default", "Settings > Actions > General > Workflow permissions"),
    ("workflows can approve pull requests", "Settings > Actions > General > Workflow permissions"),
    ("last pusher has no access now", "Settings > Collaborators and teams"),
    ("scheduled workflow still running", "Actions tab > the workflow > Disable workflow"),
    ("self-hosted runner used by", "Settings > Actions > Runners"),
    ("secrets any branch can read", "Settings > Secrets and variables > Actions, and Settings > Environments"),
    ("older workflow copies on other branches", "Code > Branches: delete or update the branches"),
    ("workflow files only on other branches", "Code > Branches: review the branches"),
    ("no actions.lock", "Run `gh actions-lock` in the repository"),
    ("approvals stay valid after new commits", "Settings > Rules: pull request rule, dismiss stale approvals"),
    ("whoever pushed last can approve", "Settings > Rules: pull request rule, require approval of the most recent push"),
    ("any action from any author", "Settings > Actions > General > Actions permissions (or the organisation's)"),
    ("pinning to a commit is required", "Pin the workflows' actions (`gh actions-lock`), or relax the setting"),
    ("fork pull request workflows", "Settings > Actions > General > Fork pull request workflows"),
    ("environments hold secrets without required reviewers", "Settings > Environments > the environment > Required reviewers"),
    ("environments do not protect pull_request_target", "Move secrets out of pull_request_target workflows, or use pull_request"),
    ("static cloud keys", "Your cloud provider: set up an OIDC login, then delete the keys from Settings > Secrets"),
    ("pull_request_target", "Settings > Actions > Policies (allow the event), or move to pull_request"),
    ("uses actions with known problems", "The Actions used section of summary.md, or the Actions tab of report.html"),
    ("workflows not in actions.lock", "Run `gh actions-lock` in the repository"),
]


def where_to_fix(note):
    return next((w for prefix, w in WHERE_TO_FIX if note.startswith(prefix)), "The workflow file named in the CSV")


def write_summary(path, ctx, rows, cfg, now, api_calls, generated=None):
    status = Counter(r["status"] for r in rows)
    deep = [r for r in rows if deep_reasons(r)]
    inactive = [r for r in rows if r["status"] in ("dormant", "dead", "archived")]
    L = []
    L.append(f"# Repository status: {ctx['owner']}\n")
    L.append(f"**Data collected {now:%Y-%m-%d %H:%M} UTC.** {len(rows)} repositories. {api_calls} API calls (read-only).\n")
    pauses = ctx.get("pauses") or {}
    if (pauses.get("count") or ctx.get("resumed")) and ctx.get("collection_started"):
        started = datetime.fromisoformat(ctx["collection_started"]).astimezone(timezone.utc)
        how = (f"paused {pauses['count']} time(s) ({pauses.get('minutes', 0)} minutes) for GitHub's hourly limit"
               if pauses.get("count") else "was stopped and resumed")
        L.append(f"Collection started {started:%Y-%m-%d %H:%M} UTC and {how}; repositories were collected at "
                 f"different times within that span.\n")
    age = (generated - now).days if generated else 0
    if age >= 1:
        L.append(f"> This report was generated {generated:%Y-%m-%d} from data that was then {age} day(s) old. "
                 f"Repositories may have changed since (visibility, workflows, settings). "
                 f"Run `{scan_cmd()} {ctx['owner']}` for current data.\n")
    L.append("| Status | Repos | Rule |\n|---|---|---|")
    L.append(f"| active | {status['active']} | human push in last {cfg['dormant_days']} days |")
    L.append(f"| dormant | {status['dormant']} | last human push {cfg['dormant_days']} to {cfg['dead_days']} days ago |")
    L.append(f"| dead | {status['dead']} | no human push for over {cfg['dead_days']} days |")
    L.append(f"| archived | {status['archived']} | archived on GitHub |")
    if status["empty"] or status["unknown"]:
        L.append(f"| empty / unknown | {status['empty'] + status['unknown']} | no default branch or no data |")
    L.append("\nPush times are server-side (GitHub activity API). Commit dates are not used for status.\n")
    L.append(f"Org audit log: {ctx.get('audit_log')}.")
    plan = [r["f"]["repo"] for r in rows if (r["prot"] or {}).get("plan_limited")]
    if plan:
        L.append(f"\nBranch rules not available on this plan for {len(plan)} private repo(s): {', '.join(plan)}. "
                 "GitHub Free does not offer branch protection or rulesets for private repositories, "
                 "so force-push cannot be blocked there.")
    unknown = [r["f"]["repo"] for r in rows if (r["prot"] or {}).get("source") == "unknown"]
    if unknown:
        L.append(f"\nBranch rules could not be read for {len(unknown)} repo(s): {', '.join(unknown)}. "
                 "Their rule columns are left blank rather than guessed.")
    if ctx.get("package_errors"):
        L.append(f"Package listing errors: {'; '.join(ctx['package_errors'])}.")

    L.append(f"\n## Deep investigation needed: {len(deep)} of {len(rows)} repositories\n")
    if deep:
        L += _deep_section(deep, ctx["owner"])
    else:
        L.append("None. No repository has a high or medium warning.")

    L.append(f"\n## Dormant, dead and archived repos ({len(inactive)})\n")
    if inactive:
        L.append("| Repo | Status | Last human push | Workflows enabled / ran in 90 days | Scheduled | Packages | "
                 "Force-push blocked | CODEOWNERS |")
        L.append("|---|---|---|---|---|---|---|---|")
        for r in sorted(inactive, key=lambda r: r["last"] or now):
            x = row_for(r, now, cfg)
            L.append(f"| {x['repo']} | {x['status']} | {x['last_human_push']} | "
                     f"{x['enabled_workflows']} / {x['workflows_run_last_90_days']} | "
                     f"{x['scheduled_workflows'] or '-'} | {x['packages'] or '-'} | {x['force_push_blocked']} | "
                     f"{x['codeowners_path']} |")
    else:
        L.append("None.")

    L += (_ioc_section(rows) + _zizmor_section(ctx, rows) + _branches_section(rows, cfg, now) + _runs_section(rows, cfg, now)
          + _actions_section(ctx, rows, now))

    hy = Counter(h.split(":")[0].split(" (")[0] for r in rows for h in r["hygiene"])
    if hy:
        L.append("\n## Hygiene (all repos)\n\nWhere to fix: the page in each repository's settings on GitHub, or the "
                 "file to change. A deep dive on a repository gives the direct links.\n")
        L.append("| Finding | Repos | Where to fix |\n|---|---|---|")
        for k, v in hy.most_common():
            L.append(f"| {k} | {v} | {where_to_fix(k)} |")

    info = [(r["f"]["repo"], c, d) for r in rows for c, s, d in r["flags"] if s == "info"]
    if info:
        L.append("\n## Informational\n")
        for repo, c, d in info:
            L.append(f"- {repo}: {c}: {d}")
    errs = [(r["f"]["repo"], e) for r in rows for e in r["f"].get("errors") or []]
    if errs:
        L.append("\n## Collection errors\n")
        for repo, e in errs:
            L.append(f"- {repo}: {e}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
