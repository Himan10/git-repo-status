"""Judge each upstream action the organisation uses, from the facts collect/repository_facts.py gathered.

No check can prove an action safe. "No known problems" means none of these checks found anything:
  - a published vulnerability (GitHub Advisory Database) affecting a version you use
  - the action's repository is archived, or has not changed for a year
  - the exact version you use was released less than a week ago (supply-chain attacks are usually found
    within days, so a short wait catches most of them)
  - the action itself uses other actions without pinning them, or container images without a digest
Also noted, not problems: who maintains it, whether its releases are immutable (tags cannot be moved).
Pure: no API calls.
"""
import re
from collections import defaultdict

from repostatus.checks.repository_checks import _days, ts

COOLDOWN_DAYS = 7
UNMAINTAINED_DAYS = 365
GITHUB_OWNERS = {"actions", "github"}


def _version(v):
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:3]]
    return tuple(nums + [0] * (3 - len(nums))) if nums else None


def _satisfies(version, rng):
    """version (a tuple) against an advisory range such as '<= 45.0.7' or '>= 1.0, < 2.3'."""
    for part in (rng or "").split(","):
        m = re.match(r"\s*(<=|>=|<|>|=)?\s*v?([\d.]+)", part)
        if not m:
            return False
        op, bound = m.group(1) or "=", _version(m.group(2))
        ok = {"<": version < bound, "<=": version <= bound, ">": version > bound, ">=": version >= bound,
              "=": version == bound}[op]
        if not ok:
            return False
    return True


def affected(ref, ref_type, ranges):
    """'yes', 'possibly' (a floating tag such as v4 covers affected releases), 'no' or 'unknown' (pinned
    to a commit or a branch, so the version cannot be told)."""
    if ref_type == "version":
        v = _version(ref)
        return "yes" if v and any(_satisfies(v, r["range"]) for r in ranges) else "no"
    if ref_type == "floating":
        nums = [int(x) for x in re.findall(r"\d+", ref)]
        lo = tuple(nums + [0] * (3 - len(nums)))
        hi = tuple(nums + [9999] * (3 - len(nums)))
        return "possibly" if any(_satisfies(lo, r["range"]) or _satisfies(hi, r["range"]) for r in ranges) else "no"
    return "unknown"


def maintainer(slug, repo):
    owner = slug.split("/")[0]
    if owner in GITHUB_OWNERS:
        return "GitHub"
    return {"Organization": "organisation", "User": "individual account"}.get(repo.get("owner_type"), "unknown")


def assess(slug, repo, health, used, now):
    """{problems: [(level, text)], notes: [text], summary: text} for one action.
    used: {(sub-path, ref, ref type, kind)} as the organisation uses it."""
    problems, notes = [], []
    health = health or {}
    if repo.get("status") in (None, "not checked"):
        return {"level": "Not checked", "problems": [], "notes": [], "summary": "not checked (--skip-action-check)"}
    if repo.get("status") != "ok":
        problems.append(("Fix" if repo.get("status") == "owner gone" else "Review", f"repository {repo.get('status')}"))
    if repo.get("archived"):
        problems.append(("Review", "archived: it will get no more fixes"))
    last = ts(repo.get("pushed_at"))
    if last and _days(now, last) > UNMAINTAINED_DAYS:
        problems.append(("Review", f"no change since {repo['pushed_at'][:10]}"))
    refs = sorted({(ref, rtype) for _, ref, rtype, _ in used})
    for adv in health.get("advisories") or []:
        for ref, rtype in refs:
            hit = affected(ref, rtype, adv["ranges"])
            fixed = ", ".join(sorted({r["fixed"] for r in adv["ranges"] if r.get("fixed")})) or "no fixed version yet"
            if hit == "yes":
                problems.append(("Fix", f"{adv['ghsa']} ({adv['severity']}) affects {ref}, which you use; fixed in {fixed}"))
            elif hit == "possibly":
                problems.append(("Review", f"{adv['ghsa']} ({adv['severity']}) affects some {ref} releases; "
                                           f"fixed in {fixed}. zizmor online checks the release {ref} points to now"))
            elif hit == "unknown":
                problems.append(("Review", f"{adv['ghsa']} ({adv['severity']}) exists for this action; you pin "
                                           f"{ref[:12]} without a version, so it cannot be checked"))
    for ref, published in (health.get("versions") or {}).items():
        if published and _days(now, ts(published)) < COOLDOWN_DAYS:
            problems.append(("Review", f"{ref} was released {published[:10]}, less than {COOLDOWN_DAYS} days ago"))
    for sub, inner in (health.get("inner") or {}).items():
        where = "" if sub == "." else f" ({sub})"
        if inner.get("unpinned"):
            problems.append(("Review", f"uses {len(inner['unpinned'])} action(s) without pinning them itself{where}: "
                                       f"{', '.join(inner['unpinned'][:3])}"))
        if inner.get("images_without_digest"):
            problems.append(("Review", f"runs container images without a digest{where}: "
                                       f"{', '.join(inner['images_without_digest'][:2])}"))
    if any(rtype == "floating" for _, rtype in refs):
        notes.append("used through a floating tag (e.g. v4): every run gets the newest release, with no waiting period")
    notes.append(f"maintained by {maintainer(slug, repo)}")
    rel = health.get("latest_release")
    if rel:
        notes.append(f"latest release {rel['tag']} ({(rel.get('published_at') or '')[:10]}), "
                     + ("immutable: its tag cannot be moved" if rel.get("immutable") else "not immutable"))
    elif repo.get("status") == "ok":
        notes.append("no releases")
    if health.get("advisories") is None and repo.get("status") == "ok":
        notes.append("advisories could not be read")
    problems = list(dict.fromkeys(problems))
    worst = "Fix" if any(l == "Fix" for l, _ in problems) else "Review" if problems else "OK"
    return {"level": worst, "problems": problems, "notes": notes,
            "summary": problems[0][1] if problems else "No known problems"}


def org_actions(index, rows, now):
    """[(slug, assessment, repos using it)] for every upstream action in the scan, most serious first."""
    from repostatus.collect.repository_facts import all_uses
    users, used = defaultdict(set), defaultdict(set)
    for r in rows:
        for _, u in all_uses(r["f"]):
            if u["kind"] in ("action", "reusable") and u.get("slug"):
                users[u["slug"]].add(r["f"]["repo"])
                used[u["slug"]].add((u.get("path") or "", u.get("ref") or "", u.get("ref_type") or "", u["kind"]))
    repos, health = (index or {}).get("repos") or {}, (index or {}).get("health") or {}
    out = [(slug, assess(slug, repos.get(slug) or {"status": "not checked"}, health.get(slug), used[slug], now),
            sorted(users[slug])) for slug in users]
    rank = {"Fix": 0, "Review": 1, "OK": 2, "Not checked": 3}
    return sorted(out, key=lambda x: (rank[x[1]["level"]], -len(x[2]), x[0]))
