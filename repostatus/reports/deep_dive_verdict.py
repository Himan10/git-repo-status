"""The deep-dive verdict: eight fixed areas, each OK / Review / Fix, and what to do, in plain words.

Pure: facts, the evaluated flags and the deep-dive results in, a structure out. deep_dive.py renders it.
Result words only (no icons): Fix = act now; Review = look at it and decide; OK = checked, nothing found.
"""
import os
import re
from collections import defaultdict

from repostatus.reports import finding_explanations
from repostatus.collect import zizmor_runner
from repostatus.checks.workflow_checks import branch_copies, live_workflows, secret_access

AREAS = ["History", "Workflow changes", "Workflow flaws", "Old copies on branches", "Secrets",
         "Upstream actions", "Repository settings", "Workflow hygiene"]
AREA_OF = {
    "FORCE_PUSH_DEFAULT": "History", "DATE_MISMATCH": "History", "FUTURE_DATED_COMMIT": "History",
    "SIGNING_BREAK": "History", "BAD_SIGNATURE": "History", "COMMITTED_BEFORE_AUTHORED": "History",
    "NEW_TIMEZONE": "History", "MULTI_BRANCH_PUSH": "History", "PUBLISHED_AFTER_INACTIVITY": "History",
    "WORKFLOW_ONLY_PUSH_AFTER_IDLE": "Workflow changes", "WORKFLOW_CHANGED_AFTER_IDLE": "Workflow changes",
    "WORKFLOW_BY_NEW_ACTOR": "Workflow changes", "WORKFLOW_EXFIL_PATTERN": "Workflow changes",
    "ZOMBIE_WORKFLOW_WITH_SECRETS": "Workflow changes", "RUN_BY_NON_COLLABORATOR": "Workflow changes",
    "IOC_MATCH": "Workflow changes", "SECRET_IN_RUN_LOG": "Secrets",
    "VSCODE_AUTORUN": "Workflow flaws", "AI_AGENT_UNTRUSTED_TRIGGER": "Workflow flaws",
    "SELF_HOSTED_ON_PUBLIC_REPO": "Workflow flaws",
    "BRANCH_WORKFLOW_EXFIL": "Old copies on branches", "DELETED_BRANCH_WORKFLOW_RAN": "Old copies on branches",
    "OUTDATED_WORKFLOW_ON_BRANCH": "Old copies on branches",
    "ACTION_OWNER_GONE": "Upstream actions", "ACTION_OWNER_RENAMED": "Upstream actions",
    "ACTION_REPO_REPLACED": "Upstream actions", "ACTION_REPO_GONE": "Upstream actions", "TAG_MOVED": "Upstream actions",
}
TAMPERING_AREAS = {"History", "Workflow changes", "Old copies on branches"}
EVIDENCE = {  # anchors of the evidence file's sections
    "History": "force-pushes", "Workflow changes": "workflow-changes", "Workflow flaws": "zizmor-every-finding",
    "Old copies on branches": "workflows-on-other-branches", "Upstream actions": "upstream-actions",
}
EVIDENCE_BY_CODE = {"RUN_BY_NON_COLLABORATOR": "runs-worth-a-look", "DELETED_BRANCH_WORKFLOW_RAN": "runs-worth-a-look",
                    "SECRET_IN_RUN_LOG": "run-logs"}
SETTINGS_NOTES = [  # (start of hygiene note, settings page)
    ("force-push allowed", "rules"), ("no PR required", "rules"), ("branch rules could not be read", None),
    ("no CODEOWNERS", None), ("CODEOWNERS errors", None), ("CODEOWNERS not enforced", "rules"),
    ("workflows have no code owner", None), ("workflow token can write by default", "actions"),
    ("workflows can approve pull requests", "actions"), ("last pusher has no access now", "access"),
    ("self-hosted runner used by", "actions"), ("scheduled workflow still running", "workflows"),
    ("approvals stay valid after new commits", "rules"), ("whoever pushed last can approve", "rules"),
    ("any action from any author", "actions"), ("fork pull request workflows", "actions"),
    ("pull_request_target is blocked", "actions"), ("pull_request_target will be blocked", "actions"),
    ("uses actions with known problems", None),
]
SECRETS_NOTES = [("environments hold secrets without required reviewers", "environments"),
                 ("environments do not protect pull_request_target", "environments"), ("static cloud keys", "secrets")]
HYGIENE_NOTES = ["pinning to a commit is required", "no actions.lock", "workflows not in actions.lock", "actions.lock could not be read",
                 "invalid workflow file", "script pipes a download into a shell", "pip install without pinned versions",
                 "go install @latest", "secret passed through an encoder", "shell tracing (set -x)"]
LEVEL = {"high": "Fix", "medium": "Review"}
EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def _line(owner_dir, repo, path, n):
    p = os.path.join(owner_dir, "workflows", repo, *path.split("/"))
    try:
        with open(p, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        return lines[n - 1].strip() if 0 < n <= len(lines) else None
    except OSError:
        return None


def _workflow(f, path):
    return next((w for w in (f.get("actions") or {}).get("items") or [] if w["path"] == path), {})


def _reach(f, w):
    """What a run of this default-branch workflow can read: its secrets, and an OIDC login if requested."""
    branch = f.get("default_branch")
    acc = [secret_access(f, j, branch) for j in w.get("jobs") or []]
    secrets = sorted({s for a in acc for s in a["readable"]}) or w.get("secrets") or []
    oidc = any(a["id_token"] for a in acc)
    return ", ".join(secrets) + (" and an OIDC cloud login" if oidc else "") if (secrets or oidc) else "no secrets"


def assess(f, row, full, owner_dir, results=(), wf=None, zz=None, up=None):
    """Build the verdict for one repository. results: force-push investigations; wf: workflow changes;
    zz: zizmor online; up: upstream actions (all from deep_dive.py)."""
    flags = [x for x in row["flags"] if x[1] in LEVEL]
    actions, notes = [], defaultdict(list)  # notes: area -> short findings for the table
    repo = f["repo"]

    # 1. Flags raised by the scan, one action per code
    by_code = defaultdict(list)
    for code, sev, detail in flags:
        by_code[code].append((sev, detail))
    for code, items in by_code.items():
        if code == "ZIZMOR_HIGH_IN_LIVE_WORKFLOW":
            continue  # replaced by the per-file zizmor actions below, which quote the lines
        area = AREA_OF.get(code, "Workflow flaws")
        text = finding_explanations.FLAGS.get(code, {"title": code, "why": "", "fix": "", "settings": None})
        level = "Fix" if any(s == "high" for s, _ in items) else "Review"
        actions.append({"level": level, "area": area, "title": text["title"], "code": code,
                        "where": [d for _, d in items], "why": text["why"], "fix": text["fix"],
                        "settings": finding_explanations.settings_link(text.get("settings"), full),
                        "evidence": EVIDENCE_BY_CODE.get(code) or EVIDENCE.get(area)})
        notes[area].append(text["title"])

    # 2. zizmor (online in the deep dive, ignore comments disregarded): serious rules, quoted from the file
    findings = (zz or {}).get("findings") if (zz or {}).get("status") == "ok" else (f.get("zizmor") or {}).get("findings")
    live = live_workflows(f, *_now_cfg(row))
    groups = defaultdict(list)
    for z in findings or []:
        if z["rule"] in zizmor_runner.ESCALATE and zizmor_runner.LEVELS.get(z["severity"], 0) >= 3 \
                and zizmor_runner.LEVELS.get(z["confidence"], 0) >= 2 and z["file"].startswith(".github/workflows/"):
            groups[(z["rule"], z["file"])].append(z)
    for (rule, path), zs in sorted(groups.items()):
        text = finding_explanations.ZIZMOR.get(rule, {"title": rule, "why": "", "fix": ""})
        w = _workflow(f, path)
        lines, harmless = [], 0
        for z in sorted(zs, key=lambda z: z["line"] or 0):
            src = _line(owner_dir, repo, path, z["line"]) if z["line"] else None
            exprs = EXPR.findall(src or "")
            safe = rule == "template-injection" and exprs and all(finding_explanations.harmless_expression(e) for e in exprs)
            harmless += bool(safe)
            lines.append({"line": z["line"], "text": src, "harmless": bool(safe)})
        step = next((z["step"] for z in zs if z.get("step")), None)
        level = "Fix" if path in live and harmless < len(zs) else "Review"
        actions.append({
            "level": level, "area": "Workflow flaws", "title": f"{text['title']} ({path.rsplit('/', 1)[-1]})",
            "code": rule, "file": path, "step": step, "lines": lines,
            "who": finding_explanations.who_can_trigger(w.get("triggers"), f.get("visibility")),
            "reach": _reach(f, w), "why": text["why"], "fix": text["fix"],
            "where": [f"{path}" + (f", step \"{step}\"" if step else "")],
            "live": path in live, "settings": None, "evidence": "zizmor-every-finding"})
        notes["Workflow flaws"].append(f"{text['title']} in {path.rsplit('/', 1)[-1]}"
                                       + ("" if path in live else " (workflow no longer runs)"))

    # 3. Secrets: where they live and who can reach them
    sec = f.get("secrets") or {}
    for h in row["hygiene"]:
        if h.startswith("secrets any branch can read"):
            names = h.split(": ", 1)[-1]
            actions.append({
                "level": "Review", "area": "Secrets", "title": "Secrets that any branch can read", "code": "secrets",
                "where": [names],
                "why": "They are repository or organisation secrets, so a workflow on any branch can read them: one "
                       "pushed by anyone with write access, or with a stolen token, included.",
                "fix": "Create an environment that allows only the default branch, move these secrets into it, add "
                       "`environment: <name>` to the jobs that need them, and delete the repository copies. For "
                       "cloud keys, switch to an OIDC login so no key is stored at all.",
                "settings": finding_explanations.settings_link("secrets", full),
                "settings2": finding_explanations.settings_link("environments", full)})
            notes["Secrets"].append(f"{names} readable from every branch")
    for env, e in sorted((sec.get("environments") or {}).items()):
        if e.get("admins_bypass") and (e.get("custom") or e.get("protected_branches_only")) and e.get("secrets"):
            actions.append({
                "level": "Review", "area": "Secrets", "title": f"Admins can bypass the branch rule of environment {env}",
                "code": "admin-bypass", "where": [f"environment {env} (secrets: {', '.join(e['secrets'])})"],
                "why": "A repository admin, or a stolen admin token, can use the environment's secrets from any branch.",
                "fix": f"Open environment {env} and untick \"Allow administrators to bypass configured protection "
                       f"rules\", unless admins need it.",
                "settings": finding_explanations.settings_link("environments", full)})
            notes["Secrets"].append(f"{', '.join(e['secrets'])} limited by environment {env}, but admins can bypass it")
    if sec.get("errors"):
        notes["Secrets"].append("secret locations could not all be read")

    # 4. Repository settings and workflow hygiene: one grouped action each
    plan = (row.get("prot") or {}).get("plan_limited")
    plan_notes = ("force-push allowed", "no PR required", "CODEOWNERS not enforced")
    for area, prefixes in (("Secrets", SECRETS_NOTES), ("Repository settings", SETTINGS_NOTES),
                           ("Workflow hygiene", [(p, None) for p in HYGIENE_NOTES])):
        items, short = [], []
        if area == "Repository settings" and plan and any(h.startswith(plan_notes) for h in row["hygiene"]):
            items.append({"text": "Branch rules (block force pushes, require pull requests and code-owner review) "
                                  "are not available for private repositories on GitHub Free", "settings": None})
            short.append("branch rules not available on this plan")
        for h in row["hygiene"]:
            if area == "Repository settings" and plan and h.startswith(plan_notes):
                continue
            for prefix, page in prefixes:
                if h.startswith(prefix):
                    items.append({"text": h, "settings": finding_explanations.settings_link(page, full)})
                    short.append(h.split(" (")[0].split(":")[0])
        fix = ""
        if area == "Repository settings" and plan:
            fix = ("Move to GitHub Team (or make the repository public) to enable branch rules. Until then, keep "
                   "write access to the few people who need it.")
        if area == "Workflow hygiene":
            uses = [u for w in (f.get("actions") or {}).get("items") or [] for u in w.get("uses") or []
                    if u.get("kind") in ("action", "reusable")]
            unpinned = sum(1 for u in uses if u.get("ref_type") != "sha")
            if unpinned:
                items.insert(0, {"text": f"{unpinned} of {len(uses)} actions are not pinned to a commit, so the "
                                         f"code they run can change without any change to this repository",
                                 "settings": None})
                short.insert(0, f"{unpinned} actions not pinned")
            if unpinned or any(i["text"].startswith(("no actions.lock", "workflows not in actions.lock"))
                               for i in items):
                fix = ("Run `gh actions-lock` to create `.github/workflows/actions.lock` (it records the exact commit "
                       "of every action, including the actions they use), or pin each `uses:` to a commit SHA.")
            common = defaultdict(int)
            for z in (f.get("zizmor") or {}).get("findings") or []:
                if not z.get("ignored") and not zizmor_runner.escalates(z) and z["rule"] != "unpinned-uses":
                    common[z["rule"]] += 1
            if common:
                items.append({"text": "Other zizmor findings (details in the evidence file): " + ", ".join(
                    f"{k} ({v})" for k, v in sorted(common.items(), key=lambda kv: -kv[1])), "settings": None})
        if items:
            actions.append({
                "level": "Review", "area": area, "title": "Secrets settings" if area == "Secrets" else area,
                "code": area, "items": items,
                "why": ("Nothing can stop someone with write access, or a stolen token, from force-pushing to the "
                        "default branch or merging without review." if area == "Repository settings" and plan else ""),
                "fix": fix, "settings": finding_explanations.settings_link("access", full) if fix and area == "Repository settings"
                else None, "evidence": "zizmor-every-finding" if area == "Workflow hygiene" else None})
            notes[area].append("; ".join(dict.fromkeys(short)) or _short_hygiene(items))

    # Table rows
    order = {"Fix": 0, "Review": 1}
    actions.sort(key=lambda a: (order[a["level"]], AREAS.index(a["area"])))
    areas = []
    for name in AREAS:
        mine = [a for a in actions if a["area"] == name]
        result = "Fix" if any(a["level"] == "Fix" for a in mine) else "Review" if mine else "OK"
        short = "; ".join(dict.fromkeys(notes[name])) if mine or notes[name] else _clean_short(name, f, wf, up, row)
        if name == "Old copies on branches" and not f.get("branch_workflows"):
            result, short = "Not checked", "--skip-branches was used in the scan"
        if name == "Upstream actions" and up is not None and not up.get("checked"):
            result, short = "Not checked", "--skip-action-check was used in the scan"
        areas.append({"name": name, "result": result, "short": short, "evidence": EVIDENCE.get(name)})

    fixes = sum(a["level"] == "Fix" for a in actions)
    reviews = sum(a["level"] == "Review" for a in actions)
    tamper = [a for a in actions if a["area"] in TAMPERING_AREAS]
    verdict = (f"{fixes} to fix, {reviews} to review. "
               + ("Possible tampering: see the History, Workflow changes or Old copies rows." if tamper
                  else "No sign of tampering."))
    return {"verdict": verdict, "areas": areas, "actions": actions, "clean": _clean(f, row, results, wf, up),
            "limits": _limits(f, row)}


def _now_cfg(row):
    from datetime import datetime, timezone
    from repostatus.checks.repository_checks import DEFAULTS
    return row.get("now") or datetime.now(timezone.utc), {**DEFAULTS, **(row.get("cfg") or {})}


def _short_hygiene(items):
    texts = [i["text"].split(" (")[0].split(":")[0] for i in items]
    return "; ".join(texts[:3]) + (f"; {len(texts) - 3} more" if len(texts) > 3 else "")


def _clean_short(name, f, wf, up, row):
    if name == "History":
        return "No force push to the default branch; commit dates match push times"
    if name == "Workflow changes":
        commits = [c for c in (wf or {}).get("commits") or [] if not c.get("error")]
        authors = sorted({c["author"] for c in commits})
        return (f"{len(commits)} change(s) to .github/ in the last {(wf or {}).get('since_days', 365)} days"
                + (f", by {', '.join(authors)}" if authors else "") + "; none after a quiet period")
    if name == "Workflow flaws":
        return "No serious zizmor finding in a workflow that runs"
    if name == "Old copies on branches":
        if not f.get("branch_workflows"):
            return "--skip-branches was used in the scan"
        now, cfg = _now_cfg(row)
        rows = [r for r in branch_copies(f, now, cfg) if not r.get("error")]
        if not rows:
            return f"All {f['branch_workflows'].get('scanned', 0)} branches match the default branch"
        active = {r["branch"] for r in rows if r.get("group") != "stale"}
        stale = {r["branch"] for r in rows} - active
        reach = [r for r in rows if r["readable"] or r["id_token"]]
        return (f"{len(active)} active and {len(stale)} stale branch(es) carry older copies; "
                + (f"{len(reach)} can read secrets" if reach else "none can read secrets"))
    if name == "Secrets":
        from repostatus.reports.org_summary import secret_scopes
        return secret_scopes(f) or "No secrets used by the workflows"
    if name == "Upstream actions":
        n = len({u.get("slug") for w in (f.get("actions") or {}).get("items") or [] for u in w.get("uses") or []
                 if u.get("kind") in ("action", "reusable")})
        return f"All {n} action(s) exist; no moved tags" if n else "No actions used"
    if name == "Repository settings":
        return "Branch rules and CODEOWNERS in place; workflow token read-only"
    return "Actions pinned; no risky install commands"


def _clean(f, row, results, wf, up):
    codes = {c for c, _, _ in row["flags"]}
    out = []
    fps = (f.get("activity") or {}).get("force_pushes") or []
    on_default = [e for e in fps if e["ref"] == f"refs/heads/{f.get('default_branch')}"]
    if not on_default:
        out.append("Force pushes to the default branch: none"
                   + (f" ({len(fps)} on other branches, not investigated)" if fps else ""))
    if not codes & {"DATE_MISMATCH", "FUTURE_DATED_COMMIT", "COMMITTED_BEFORE_AUTHORED"}:
        out.append("Backdated or impossibly dated commits: none")
    if not codes & {"SIGNING_BREAK", "BAD_SIGNATURE", "NEW_TIMEZONE"}:
        out.append("Unusual signing or time zone on the latest commit: none")
    if not codes & {"WORKFLOW_ONLY_PUSH_AFTER_IDLE", "WORKFLOW_CHANGED_AFTER_IDLE"}:
        out.append("Pushes after a quiet period: none")
    if not codes & {"WORKFLOW_BY_NEW_ACTOR"}:
        out.append("Workflow changes by someone new: none")
    if f.get("collaborators") and not codes & {"RUN_BY_NON_COLLABORATOR"}:
        out.append("Push or manual runs started by someone without access: none")
    if not codes & {"WORKFLOW_EXFIL_PATTERN", "BRANCH_WORKFLOW_EXFIL"}:
        out.append("Workflow steps sending secrets to outside addresses: none")
    if f.get("branch_workflows") and not codes & {"DELETED_BRANCH_WORKFLOW_RAN"}:
        out.append("Workflow runs from deleted branches: none")
    if up and up.get("checked") and not up.get("moved") and not up.get("problems"):
        out.append("Upstream actions missing, renamed, or with moved tags: none")
    if not codes & {"IOC_MATCH"}:
        from repostatus.checks.ioc_matching import load_iocs
        n = len(load_iocs()["campaigns"])
        out.append(f"Indicators from {n} known GitHub Actions supply-chain campaigns (iocs.yml): none matched")
    if row.get("logs_checked") is not None and not codes & {"SECRET_IN_RUN_LOG"}:
        out.append(f"Secrets visible in the logs of {row['logs_checked']} recent run(s): none")
    if not codes & {"VSCODE_AUTORUN"}:
        out.append("Files that run a command when the folder is opened in VS Code: none")
    return out


def _limits(f, row):
    out = []
    oidc = [w["path"] for w in (f.get("actions") or {}).get("items") or []
            if any(j.get("id_token") for j in w.get("jobs") or [])]
    if oidc:
        out.append(f"Cloud logins (OIDC): {', '.join(p.rsplit('/', 1)[-1] for p in oidc)} can request a login token "
                   f"for AWS, Azure or Google Cloud. Which branches the cloud accepts is set in the cloud's trust "
                   f"policy (its `sub` condition), which Repo Status cannot read. It should require the environment "
                   f"or the default branch, not the whole repository.")
    if row.get("logs_checked") is None:
        out.append("Run logs were not read; add --logs to the deep dive to check recent runs for leaked secrets.")
    out.append("History checks cover the last 50 commits of the default branch and every recorded force push.")
    out.append("Workflow files are as of the last scan; changes made since are not included.")
    return out
