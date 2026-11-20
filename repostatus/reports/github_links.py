"""Links to GitHub used in the reports, instead of copying commit data or diffs into them.

Commits that are themselves a finding are marked with the keyword FINDING: and the reason code, e.g.
"[a1b2c3d](https://github.com/org/repo/commit/a1b2c3d) FINDING: WORKFLOW_ONLY_PUSH_AFTER_IDLE", so they
stand out from the other commit links and can be searched for.
"""
import re
from collections import defaultdict
from urllib.parse import quote

SHA = re.compile(r"\b[0-9a-f]{7,40}\b")
# A finding about an action starts with its name ('owner/action@3e5f45b in ...', 'owner/action/sub@v4: locked at
# ...'); the commits it names are in that action's repository, not in the repository that uses it.
ACTION_REF = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^@\s]*)?@")


def commit_url(full, sha):
    return f"https://github.com/{full}/commit/{sha}"


def file_url(full, ref, path):
    """A file as it is on a branch, tag or commit."""
    return f"https://github.com/{full}/blob/{quote(ref, safe='/')}/{path}"


def compare_url(full, base, head):
    """GitHub's view of everything that differs between two branches or commits."""
    return f"https://github.com/{full}/compare/{quote(base, safe='/')}...{quote(head, safe='/')}"


def finding_commits(flags):
    """{first 7 characters of a commit: [reason codes]} for every commit a flag's detail names."""
    out = defaultdict(list)
    for code, sev, detail in flags:
        if sev not in ("high", "medium"):
            continue
        for sha in SHA.findall(detail or ""):
            if code not in out[sha[:7]]:
                out[sha[:7]].append(code)
    return out


def commit_link(full, sha, findings=None):
    """'[a1b2c3d](url)', followed by 'FINDING: CODE' when that commit is part of a finding."""
    codes = (findings or {}).get(sha[:7]) or []
    return f"[{sha[:7]}]({commit_url(full, sha)})" + (f" FINDING: {', '.join(codes)}" if codes else "")


def commits_repo(text, full):
    """The repository a finding's commits belong to: the action it starts with, else the scanned repository."""
    m = ACTION_REF.match(text or "")
    return m.group(1) if m else full


TAG_IN_TEXT = re.compile(r"(?:is commented|, tag) (v?\d[\w.\-]*)")


def action_tag(text, full):
    """The tag a finding about an action names (a moved tag), as (label, url) in the action's repository."""
    repo, m = commits_repo(text, full), TAG_IN_TEXT.search(text or "")
    if repo == full or not m:
        return None
    tag = m.group(1).rstrip(".,;:")
    return f"tag {tag} in {repo}", f"https://github.com/{repo}/tree/{quote(tag, safe='')}"


def action_compare(text, full):
    """For a finding about an action that names two commits (a moved tag), GitHub's comparison of them in the
    action's repository: (label, url), else None."""
    repo = commits_repo(text, full)
    shas = list(dict.fromkeys(SHA.findall(text or "")))
    if repo == full or len(shas) < 2:
        return None
    return f"compare {shas[0][:7]}...{shas[1][:7]} in {repo}", compare_url(repo, shas[0], shas[1])


def linkify(text, full, findings=None):
    """Turn every commit id in a sentence into a link (with its FINDING: keyword, if any). Commits in a finding
    about an action link to the action's repository, plus a link comparing them."""
    repo = commits_repo(text, full)
    out = SHA.sub(lambda m: commit_link(repo, m.group(0), findings), text or "")
    extra = [x for x in (action_tag(text, full), action_compare(text, full)) if x]
    return out + (" (" + ", ".join(f"[{label}]({url})" for label, url in extra) + ")" if extra else "")
