import csv
from collections import Counter, defaultdict

from .oscompat import scan_cmd

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
}
# reasons deep_dive.py investigates; the others have a "How to check" that needs no tool
DEEP_DIVE_COVERS = {"FORCE_PUSH_DEFAULT", "WORKFLOW_ONLY_PUSH_AFTER_IDLE", "WORKFLOW_CHANGED_AFTER_IDLE",
                    "WORKFLOW_BY_NEW_ACTOR", "ZIZMOR_HIGH_IN_LIVE_WORKFLOW", "TAG_MOVED", "WORKFLOW_EXFIL_PATTERN"}
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
    "actions_enabled", "workflows", "active_workflows", "scheduled_workflows", "last_scheduled_run",
    "workflow_secrets", "self_hosted", "registries_in_workflows", "workflow_pushes_image", "dockerfiles",
    "packages", "latest_package_published", "latest_image_tags",
    "vscode_autorun", "force_pushes_default", "force_pushes_other",
    "lockfile", "unpinned_actions", "default_token_permission", "workflow_last_changed", "workflow_last_changed_by",
    "zizmor_status", "zizmor_high", "zizmor_medium", "zizmor_low", "zizmor_top_rules",
    "deep_dive", "deep_dive_priority", "deep_dive_reason_codes", "deep_dive_reasons", "hygiene",
    "collection_errors",
]


def _yn(v):
    return "" if v is None else ("yes" if v else "no")


def _rule(v, prot):
    """A branch-rule value; marked when the plan makes the rule impossible, not merely unset."""
    v = _yn(v) if isinstance(v, bool) or v is None else v
    return f"{v} (plan)" if prot.get("plan_limited") and v != "" else v


def row_for(r, now):
    f, prot, br = r["f"], r["prot"] or {}, r["branches"] or {}
    hist = f.get("history") or []
    head = hist[0] if hist else {}
    act = f.get("activity") or {}
    wfs = [w for w in (f.get("actions") or {}).get("items") or [] if not w.get("dynamic")]
    active = [w for w in wfs if w["state"] == "active"]
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
        "active_workflows": len(active),
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
        **_workflow_columns(f),
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


def _workflow_columns(f):
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
    }


def write_inventory(path, rows, ctx):
    """One line per action and ref: where it is used, whether it is pinned or locked, upstream state."""
    index = (ctx.get("action_index") or {}).get("repos") or {}
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
        w.writerow(["action", "ref", "ref_type", "repos", "repos_with_lockfile_entry", "upstream", "used_in"])
        for (target, ref, rtype), e in sorted(agg.items(), key=lambda kv: (-len(kv[1]["repos"]), kv[0])):
            up = index.get("/".join(target.split("/")[:2]))
            upstream = "" if not up else (up["status"] if up["status"] != "ok" else
                                          ("archived" if up.get("archived") else "ok"))
            w.writerow([target, ref, rtype, len(e["repos"]), len(e["locked"]), upstream,
                        "; ".join(sorted(e["files"])[:20])])


def write_csv(path, rows, now):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:  # BOM: Excel on Windows reads UTF-8
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for r in sorted(rows, key=lambda r: (r["status"] != "dead", r["status"] != "dormant", r["f"]["repo"])):
            w.writerow(row_for(r, now))


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
    L.append(f"zizmor {z.get('version')} audited the workflow files of {len(ran)} repositories, offline. "
             "Run the deep dive on a repo for the online audits (impostor commits, known-vulnerable actions) "
             "and for findings hidden by `# zizmor: ignore` comments.\n")
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


def _actions_section(ctx, rows):
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
    bad = {k: v for k, v in (index.get("repos") or {}).items() if v["status"] != "ok" or v.get("archived")}
    if bad:
        L.append("| Upstream action | State |\n|---|---|")
        L += [f"| {k} | {'archived' if v['status'] == 'ok' else v['status']} |" for k, v in sorted(bad.items())]
    elif not index:
        L.append("Upstream actions were not checked (--skip-action-check).")
    top = Counter(u["target"].lower() for _, _, u in remote).most_common(5)
    L.append("\nMost used: " + ", ".join(f"{t} ({n})" for t, n in top) +
             ". Every action, with where it is used: `actions-inventory.csv`. "
             f"After an upstream compromise: `{scan_cmd()} {ctx['owner']} uses <owner/action> --since YYYY-MM-DD`.")
    return L


def write_summary(path, ctx, rows, cfg, now, api_calls, generated=None):
    status = Counter(r["status"] for r in rows)
    deep = [r for r in rows if deep_reasons(r)]
    inactive = [r for r in rows if r["status"] in ("dormant", "dead", "archived")]
    L = []
    L.append(f"# Repository status: {ctx['owner']}\n")
    L.append(f"**Data collected {now:%Y-%m-%d %H:%M} UTC.** {len(rows)} repositories. {api_calls} API calls (read-only).\n")
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
        L.append("| Repo | Status | Last human push | Active workflows | Scheduled | Packages | Force-push blocked | CODEOWNERS |")
        L.append("|---|---|---|---|---|---|---|---|")
        for r in sorted(inactive, key=lambda r: r["last"] or now):
            x = row_for(r, now)
            L.append(f"| {x['repo']} | {x['status']} | {x['last_human_push']} | {x['active_workflows']} | "
                     f"{x['scheduled_workflows'] or '-'} | {x['packages'] or '-'} | {x['force_push_blocked']} | "
                     f"{x['codeowners_path']} |")
    else:
        L.append("None.")

    L += _zizmor_section(ctx, rows) + _actions_section(ctx, rows)

    hy = Counter(h.split(":")[0].split(" (")[0] for r in rows for h in r["hygiene"])
    if hy:
        L.append("\n## Hygiene (all repos)\n\n| Finding | Repos |\n|---|---|")
        for k, v in hy.most_common():
            L.append(f"| {k} | {v} |")

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
