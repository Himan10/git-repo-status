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


def pinned_version(u, lock=None):
    """The version a commit-pinned `uses:` stands for: its `# v4.2.0` comment, else the actions.lock entry for that
    commit. None when neither says (or the use is not pinned to a commit)."""
    from repostatus.collect.workflow_parser import FLOATING_VERSION, FULL_VERSION
    if u.get("ref_type") != "sha":
        return None
    c = (u.get("version_comment") or "").strip()
    if c and (FULL_VERSION.match(c) or FLOATING_VERSION.match(c)):
        return c
    sha = (u.get("ref") or "").lower()
    for d in ((lock or {}).get("dependencies") or {}).values():
        if sha and d.get("commit", "").lower().startswith(sha[:12]) and d.get("ref"):
            return d["ref"]
    return None


def assess(slug, repo, health, used, now, pins=None):
    """{problems: [(level, text)], notes: [text], summary: text} for one action.
    used: {(sub-path, ref, ref type, kind)} as the organisation uses it; a commit whose version is known (from its
    comment or actions.lock) is listed as that version. pins: {version: {commits}} for the wording."""
    pins = pins or {}
    via = lambda ref: (f" (pinned as commit {', '.join(sorted(c[:7] for c in pins[ref]))})" if ref in pins else "")
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
                problems.append(("Fix", f"{adv['ghsa']} ({adv['severity']}) affects {ref}{via(ref)}, which you use; fixed in {fixed}"))
            elif hit == "possibly":
                problems.append(("Review", f"{adv['ghsa']} ({adv['severity']}) affects some {ref}{via(ref)} releases; "
                                           f"fixed in {fixed}. zizmor online checks the release {ref} points to now"))
            elif hit == "unknown":
                problems.append(("Review", f"{adv['ghsa']} ({adv['severity']}) exists for this action. You use commit "
                                           f"{ref[:12]}, which has no version comment and no actions.lock entry, so "
                                           f"Repo Status cannot tell whether it is in an affected release: compare "
                                           f"it with the advisory's affected versions"))
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


def lock_paths(lock, target):
    """Lockfile entries that run target, directly or through other actions: {workflow path: via}."""
    deps = lock.get("dependencies") or {}

    def reaches(key, seen=()):
        d = deps.get(key) or {}
        if d.get("slug") == target or d.get("target", "").lower() == target:
            return key
        for sub in d.get("uses") or []:
            if sub not in seen and reaches(sub, seen + (key,)):
                return key
        return None
    out = {}
    for path, keys in (lock.get("workflows") or {}).items():
        for k in keys:
            if reaches(k) and (deps.get(k) or {}).get("slug") != target:
                out[path] = f"through {k} (actions.lock)"
    return out


def who_uses(repos, target):
    """Every place an action is used, from the scan's facts (no API calls): the workflows and composite actions
    that name it, and the workflows whose actions.lock reaches it through another action. Each place has the
    version used, whether it is pinned to a commit or recorded in actions.lock, and the workflow's facts (wf:
    state and last run). target: owner/repo, any case, without @version."""
    from repostatus.collect.repository_facts import all_uses
    target = target.lower().split("@")[0].rstrip("/")
    hits = []
    for f in repos:
        acts = f.get("actions") or {}
        items = {w["path"]: w for w in acts.get("items") or []}
        lock = acts.get("lockfile") or {}
        locked = {k.split("@")[0].lower() for k in (lock.get("dependencies") or {})}
        for path, u in all_uses(f):
            if u.get("slug") and (u["slug"] == target or u["target"].lower() == target):
                hits.append({"repo": f["repo"], "path": path, "ref": u["ref"], "ref_type": u.get("ref_type", ""),
                             "version": pinned_version(u, lock), "where": u.get("where", ""), "via": "direct", "wf": items.get(path),
                             "locked": u["target"].lower() in locked or u["slug"] in locked})
        for path, via in lock_paths(lock, target).items():
            hits.append({"repo": f["repo"], "path": path, "ref": "", "ref_type": "", "version": None, "where": "", "via": via,
                         "wf": items.get(path), "locked": True})
    return hits


def org_actions(index, rows, now):
    """[(slug, assessment, repos using it)] for every upstream action in the scan, most serious first."""
    from repostatus.collect.repository_facts import all_uses
    from repostatus.collect.workflow_parser import ref_type
    users, used, pins = defaultdict(set), defaultdict(set), defaultdict(lambda: defaultdict(set))
    for r in rows:
        lock = (r["f"].get("actions") or {}).get("lockfile") or {}
        for _, u in all_uses(r["f"]):
            if u["kind"] in ("action", "reusable") and u.get("slug"):
                users[u["slug"]].add(r["f"]["repo"])
                ref, rtype = u.get("ref") or "", u.get("ref_type") or ""
                version = pinned_version(u, lock)
                if version:  # judge the commit as the version it stands for
                    pins[u["slug"]][version].add(ref)
                    ref, rtype = version, ref_type(version)
                used[u["slug"]].add((u.get("path") or "", ref, rtype, u["kind"]))
    repos, health = (index or {}).get("repos") or {}, (index or {}).get("health") or {}
    out = [(slug, assess(slug, repos.get(slug) or {"status": "not checked"}, health.get(slug), used[slug], now, pins[slug]),
            sorted(users[slug])) for slug in users]
    rank = {"Fix": 0, "Review": 1, "OK": 2, "Not checked": 3}
    return sorted(out, key=lambda x: (rank[x[1]["level"]], -len(x[2]), x[0]))
