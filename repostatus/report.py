import csv
from collections import Counter

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
    "deep_dive", "deep_dive_reasons", "hygiene", "collection_errors",
]


def _yn(v):
    return "" if v is None else ("yes" if v else "no")


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
    high = [x for x in r["flags"] if x[1] in ("high", "medium")]
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
        "force_push_blocked": _yn(prot.get("force_push_blocked")),
        "pr_required": _yn(prot.get("pr_required")),
        "approvals": prot.get("approvals", ""),
        "code_owner_review": _yn(prot.get("code_owner_review")),
        "signatures_required": _yn(prot.get("signatures")),
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
        "deep_dive": "yes" if high else "no",
        "deep_dive_reasons": " | ".join(f"{c}: {d}" for c, s, d in high),
        "hygiene": " | ".join(r["hygiene"]),
        "collection_errors": " | ".join(f.get("errors") or []),
    }


def write_csv(path, rows, now):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:  # BOM so Excel reads UTF-8
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for r in sorted(rows, key=lambda r: (r["status"] != "dead", r["status"] != "dormant", r["f"]["repo"])):
            w.writerow(row_for(r, now))


def write_summary(path, ctx, rows, cfg, now, api_calls):
    status = Counter(r["status"] for r in rows)
    deep = [r for r in rows if any(s in ("high", "medium") for _, s, _ in r["flags"])]
    inactive = [r for r in rows if r["status"] in ("dormant", "dead", "archived")]
    L = []
    L.append(f"# Repository status: {ctx['owner']}\n")
    L.append(f"Collected {now:%Y-%m-%d %H:%M} UTC. {len(rows)} repositories. {api_calls} API calls (read-only).\n")
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

    L.append(f"\n## Needs a closer look ({len(deep)})\n")
    if deep:
        L.append("| Repo | Status | Signal | Detail |\n|---|---|---|---|")
        for r in deep:
            for code, sev, detail in r["flags"]:
                if sev in ("high", "medium"):
                    L.append(f"| {r['f']['repo']} | {r['status']} | {code} ({sev}) | {detail} |")
    else:
        L.append("None.")

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
