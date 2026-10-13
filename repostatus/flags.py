"""Turn collected facts into a status, investigation flags and hygiene notes.

Two kinds of time are used, and never mixed:
  server-side  = recorded by GitHub (activity API, pushed_at, package publish time). Trusted.
  commit metadata = author/committer dates written by the client. Can be forged.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

DEFAULTS = {
    "dormant_days": 90,       # no human push for this long -> dormant
    "dead_days": 365,         # no human push for this long -> dead
    "mismatch_days": 7,       # commit date older than its push by more than this -> flag
    "future_hours": 1,        # commit date newer than its push by more than this -> flag
    "image_grace_days": 30,   # image published this long after last human push -> flag
    "multi_push_seconds": 60, # same commit pushed to several branches within this window
    "signer_ratio": 0.8,      # author signs at least this share of commits
    "min_author_commits": 5,  # history needed before judging an author's habits
}


def ts(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def is_bot(login, actor_type=None):
    return actor_type == "Bot" or (login or "").endswith("[bot]")


def is_github_commit(c):
    """Commit created by GitHub (web UI merge, edit, fork sync): committer date is server-set."""
    return c["committer_email"] == "noreply@github.com" and c["signature_valid"]


def _days(a, b):
    return (a - b).total_seconds() / 86400


def last_human_activity(f):
    """Latest server-side push by a person. Returns (datetime, source, bound_only)."""
    events = (f.get("activity") or {}).get("latest") or []
    human = [e for e in events if not is_bot(e["actor"], e["actor_type"])]
    if human:
        return max(ts(e["ts"]) for e in human), "activity API", False
    if events:
        # last 100 events are all bots: human activity is older than the oldest of them
        return min(ts(e["ts"]) for e in events), "activity API (bots only; human push older)", True
    return ts(f.get("pushed_at")), "pushed_at (no activity events)", False


def classify(f, now, cfg):
    if f.get("archived"):
        return "archived"
    if f.get("empty"):
        return "empty"
    last, _, _ = last_human_activity(f)
    if not last:
        return "unknown"
    age = _days(now, last)
    if age <= cfg["dormant_days"]:
        return "active"
    if age <= cfg["dead_days"]:
        return "dormant"
    return "dead"


def _tz(s):
    return s[-6:] if s and s[-6] in "+-" else "+00:00"


def investigation_flags(f, status, now, cfg):
    """Signals from the blog. Any of these puts the repo on the deep-dive list."""
    out = []
    history = {c["oid"]: c for c in f.get("history") or []}
    act = f.get("activity") or {}
    branch = f.get("default_branch")
    inactive = status in ("dormant", "dead", "archived")

    # 1. Commit date vs push time, for recent pushes to the default branch.
    #    Not suspicious when GitHub created the commit (web merge: date set server-side)
    #    or when the same commit was pushed to another branch earlier (fast-forward merge).
    first_seen = {}
    for e in act.get("latest") or []:
        if e["after"] and e["type"] != "branch_deletion":
            first_seen[e["after"]] = min(first_seen.get(e["after"], e["ts"]), e["ts"])
    for e in act.get("default_branch") or []:
        c = history.get(e["after"])
        if not c or e["type"] == "branch_deletion":
            continue
        gap = _days(ts(e["ts"]), ts(c["committed_utc"]))
        what = f"{c['oid'][:7]} dated {c['committed_utc'][:10]}, pushed {e['ts'][:10]} by {e['actor']} ({e['type']})"
        if gap > cfg["mismatch_days"]:
            if e["type"] == "branch_creation":
                out.append(("INITIAL_IMPORT_BACKDATED", "info", what))
            elif is_github_commit(c):
                out.append(("LATE_ARRIVAL_GITHUB_COMMIT", "info", f"{what}; committed by GitHub, date is server-set"))
            elif first_seen.get(e["after"], e["ts"]) < e["ts"]:
                out.append(("LATE_ARRIVAL_FAST_FORWARD", "info",
                            f"{what}; first pushed {first_seen[e['after']][:10]} on another branch"))
            else:
                out.append(("DATE_MISMATCH", "high", f"{what}; gap {gap:.0f} days"))
        elif gap < -cfg["future_hours"] / 24:
            out.append(("FUTURE_DATED_COMMIT", "high", what))

    # 2. Committer date before author date is not produced by normal git use
    for c in (f.get("history") or [])[:10]:
        if (ts(c["author_date"]) - ts(c["committer_date"])).total_seconds() > 3600:
            out.append(("COMMITTED_BEFORE_AUTHORED", "medium",
                        f"{c['oid'][:7]} authored {c['author_date']} committed {c['committer_date']}"))

    # 3. Head commit in a timezone this author has never used before
    hist = f.get("history") or []
    if hist:
        head = hist[0]
        prior = [c for c in hist[1:] if c["author_email"] == head["author_email"]]
        if len(prior) >= cfg["min_author_commits"]:
            seen = {_tz(c["author_date"]) for c in prior}
            if _tz(head["author_date"]) not in seen:
                out.append(("NEW_TIMEZONE", "medium",
                            f"{head['oid'][:7]} by {head['author_email']} in {_tz(head['author_date'])}; "
                            f"previously {', '.join(sorted(seen))}"))
        # 4. Author normally signs, head commit is unsigned or invalid
        signed = sum(1 for c in prior if c["signature_valid"])
        if len(prior) >= cfg["min_author_commits"] and signed / len(prior) >= cfg["signer_ratio"] \
                and not head["signature_valid"]:
            out.append(("SIGNING_BREAK", "high",
                        f"{head['oid'][:7]} {head['signature']}; author signed {signed}/{len(prior)} earlier commits"))
        for c in hist[:10]:
            if c["signature"] not in ("UNSIGNED", "VALID"):
                out.append(("BAD_SIGNATURE", "high", f"{c['oid'][:7]} signature state {c['signature']}"))

    # 5. Force pushes to the default branch rewrite history
    fps = [e for e in act.get("force_pushes") or [] if e["ref"] == f"refs/heads/{branch}"]
    if fps:
        latest = max(fps, key=lambda e: e["ts"])
        out.append(("FORCE_PUSH_DEFAULT", "high" if inactive else "medium",
                    f"{len(fps)} force push(es); latest {latest['ts']} by {latest['actor']} "
                    f"({(latest['before'] or '')[:7]} -> {(latest['after'] or '')[:7]})"))

    # 6. Same commit pushed to several branches within seconds (scripted push)
    by_sha = defaultdict(list)
    for e in act.get("latest") or []:
        if e["type"] in ("push", "force_push") and e["after"]:
            by_sha[e["after"]].append(e)
    for sha, evs in by_sha.items():
        refs = {e["ref"] for e in evs}
        span = (max(ts(e["ts"]) for e in evs) - min(ts(e["ts"]) for e in evs)).total_seconds()
        if len(refs) > 1 and span <= cfg["multi_push_seconds"]:
            out.append(("MULTI_BRANCH_PUSH", "medium", f"{sha[:7]} pushed to {len(refs)} branches within {span:.0f}s"))

    # 7. Editor task that runs when the folder is opened
    if (f.get("autorun") or {}).get("run_on_folder_open"):
        out.append(("VSCODE_AUTORUN", "high", ".vscode/tasks.json runs on folder open"))

    return out


def package_flags(f, status, pkgs, cfg):
    out = []
    last, _, _ = last_human_activity(f)
    if status not in ("dormant", "dead", "archived") or not last:
        return out
    for p in pkgs:
        pub = ts(p["latest_published"])
        if pub and _days(pub, last) > cfg["image_grace_days"]:
            out.append(("PUBLISHED_AFTER_INACTIVITY", "high",
                        f"{p['type']} {p['name']} published {p['latest_published'][:10]}, "
                        f"last human push {last.date()}"))
    return out


PLAN_LIMIT = "Upgrade to GitHub Pro"


def effective_protection(f):
    """Combined branch rules from classic protection and rulesets.

    Three outcomes: rules read; rules impossible on this plan (private repo on GitHub Free,
    so nothing can block anything); or rules unreadable (e.g. missing admin permission),
    in which case the values are None = unknown, never assumed."""
    p = f.get("protection") or {}
    c, r = p.get("classic") or {}, p.get("rulesets") or {}
    has_c, has_r = bool(c) and "error" not in c, bool(r.get("types"))
    errors = [x["error"] for x in (c, r) if x.get("error")]
    plan_limited = bool(errors) and all(PLAN_LIMIT in e for e in errors)
    if errors and not plan_limited and not has_c and not has_r:
        return {"source": "unknown", "force_push_blocked": None, "deletion_blocked": None,
                "pr_required": None, "approvals": None, "code_owner_review": None, "signatures": None,
                "plan_limited": False, "error": errors[0]}
    source = "+".join(s for s, ok in (("classic", has_c), ("ruleset", has_r)) if ok)
    classic_unknown = bool(c.get("error")) and PLAN_LIMIT not in c["error"]
    if classic_unknown:
        # rulesets were read but classic protection was not: a "no" could be wrong, so report unknown
        def known(v):
            return None if v is False else v
        return {
            "source": (source + "; " if source else "") + "classic unreadable",
            "force_push_blocked": known(r.get("force_push_blocked", False)),
            "deletion_blocked": known(r.get("deletion_blocked", False)),
            "pr_required": known(r.get("pr_required", False)),
            "approvals": r.get("approvals") or None,
            "code_owner_review": known(r.get("code_owner_review", False)),
            "signatures": known(r.get("signatures", False)),
            "plan_limited": False, "error": c["error"],
        }
    return {
        "source": source or ("not available on plan" if plan_limited else "none"),
        "force_push_blocked": (has_c and not c.get("allow_force_pushes")) or r.get("force_push_blocked", False),
        "deletion_blocked": (has_c and not c.get("allow_deletions")) or r.get("deletion_blocked", False),
        "pr_required": c.get("pr_required", False) or r.get("pr_required", False),
        "approvals": max(c.get("approvals", 0), r.get("approvals", 0)),
        "code_owner_review": c.get("code_owner_review", False) or r.get("code_owner_review", False),
        "signatures": c.get("signatures", False) or r.get("signatures", False),
        "plan_limited": plan_limited,
        "error": None if plan_limited else (errors[0] if errors else None),
    }


def branch_strategy(f, now, cfg):
    items = (f.get("branches") or {}).get("items") or []
    names = [b["name"] for b in items]
    default = f.get("default_branch")
    others = [n for n in names if n != default]
    has_dev = any(n in ("develop", "development", "dev") for n in names)
    has_rel = any(n.startswith(("release/", "release-", "releases/")) for n in names)
    prefixes = Counter(n.split("/", 1)[0] for n in others if "/" in n)
    if not others:
        strategy = "single branch"
    elif has_dev and has_rel:
        strategy = "git-flow"
    elif has_dev:
        strategy = "develop + feature branches"
    elif has_rel:
        strategy = "release branches"
    else:
        strategy = "feature branches off default"
    stale = [b for b in items if b["name"] != default and b["committed"]
             and _days(now, ts(b["committed"])) > cfg["dormant_days"]]
    return {
        "strategy": strategy,
        "count": (f.get("branches") or {}).get("total", 0),
        "prefixes": ", ".join(f"{k}({v})" for k, v in prefixes.most_common(4)),
        "stale": len(stale),
    }


def hygiene(f, status, prot, now, cfg):
    """Not signs of tampering; things to fix, mostly on inactive repos."""
    out = []
    inactive = status in ("dormant", "dead")
    if prot["source"] == "unknown":
        out.append(f"branch rules could not be read ({prot['error'][:60]})")
    else:
        why = " (private repo on GitHub Free: branch rules not available)" if prot["plan_limited"] else ""
        if prot["force_push_blocked"] is False:
            out.append("force-push allowed on default branch" + why)
        if prot["pr_required"] is False:
            out.append("no PR required on default branch" + why)
        if prot["force_push_blocked"] is None:
            out.append(f"branch rules could not be read ({prot['error'][:60]})")
    collab = set(f.get("collaborators") or [])
    humans = [e for e in (f.get("activity") or {}).get("default_branch") or []
              if not is_bot(e["actor"], e["actor_type"])]
    if humans and collab:
        last = max(humans, key=lambda e: e["ts"])
        if last["actor"] not in collab:
            out.append(f"last pusher has no access now: {last['actor']}")
    co = f.get("codeowners") or {}
    if not co.get("path"):
        out.append("no CODEOWNERS")
    else:
        if co.get("errors"):
            out.append(f"CODEOWNERS errors ({len(co['errors'])})")
        if prot["code_owner_review"] is False:
            out.append("CODEOWNERS not enforced")
        if not co.get("workflows_owner"):
            out.append("workflows have no code owner")
    for w in (f.get("actions") or {}).get("items") or []:
        if w.get("dynamic") or w["state"] != "active":
            continue
        ran = ts(w.get("last_scheduled_run"))
        if inactive and "schedule" in (w.get("triggers") or []) and ran and _days(now, ran) <= 30:
            sec = f" with secrets {', '.join(w['secrets'])}" if w.get("secrets") else ""
            out.append(f"scheduled workflow still running: {w['path']}{sec}")
        if inactive and any("self-hosted" in r for r in w.get("runs_on") or []):
            out.append(f"self-hosted runner used by {w['path']}")
    return out


def evaluate(facts, owner_ctx, now=None, cfg=None):
    cfg = {**DEFAULTS, **(cfg or {})}
    now = now or datetime.now(timezone.utc)
    pkgs_by_repo = defaultdict(list)
    for p in owner_ctx.get("packages", []):
        pkgs_by_repo[p["repo"]].append(p)
    rows = []
    for f in facts:
        status = classify(f, now, cfg)
        last, source, bound = last_human_activity(f)
        pkgs = pkgs_by_repo.get(f["repo"], [])
        if f.get("empty") or f["errors"] and "history" not in f:
            rows.append({"f": f, "status": status, "last": last, "source": source, "bound": bound,
                         "pkgs": pkgs, "flags": [], "hygiene": [], "prot": None, "branches": None})
            continue
        prot = effective_protection(f)
        flags = investigation_flags(f, status, now, cfg) + package_flags(f, status, pkgs, cfg)
        rows.append({
            "f": f, "status": status, "last": last, "source": source, "bound": bound, "pkgs": pkgs,
            "flags": flags, "prot": prot, "branches": branch_strategy(f, now, cfg),
            "hygiene": hygiene(f, status, prot, now, cfg),
        })
    return rows, cfg
