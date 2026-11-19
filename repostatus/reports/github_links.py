"""Links to GitHub used in the reports, instead of copying commit data or diffs into them.

Commits that are themselves a finding are marked with the keyword FINDING: and the reason code, e.g.
"[a1b2c3d](https://github.com/org/repo/commit/a1b2c3d) FINDING: WORKFLOW_ONLY_PUSH_AFTER_IDLE", so they
stand out from the other commit links and can be searched for.
"""
import re
from collections import defaultdict
from urllib.parse import quote

SHA = re.compile(r"\b[0-9a-f]{7,40}\b")


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


def linkify(text, full, findings=None):
    """Turn every commit id in a sentence into a link (with its FINDING: keyword, if any)."""
    return SHA.sub(lambda m: commit_link(full, m.group(0), findings), text or "")
