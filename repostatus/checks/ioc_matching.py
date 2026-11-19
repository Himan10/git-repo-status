"""Match a repository against known indicators of compromise (IOCs) from iocs.yml at the project root.

Uses what the scan already collected (workflow files on every branch as saved in out/, branch names,
runs, runners, repository name and description, file names, workflow commit messages, pinned action
commits). Reads the saved workflow files from disk; makes no API calls.
"""
import functools
import os
import re
from datetime import datetime

import yaml

from repostatus.output_paths import PROJECT_ROOT

IOC_FILE = os.path.join(PROJECT_ROOT, "iocs.yml")


@functools.lru_cache(maxsize=4)
def load_iocs(path=IOC_FILE):
    """{'updated': ..., 'campaigns': [...]}; an empty list when the file is missing."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except OSError:
        return {"updated": None, "campaigns": []}
    return {"updated": str(data.get("updated") or ""), "campaigns": data.get("campaigns") or []}


def file_names(iocs=None):
    """Every file name the campaigns list, for the scan to look for in each repository's file tree."""
    iocs = iocs or load_iocs()
    return sorted({n for c in iocs["campaigns"] for n in c.get("file_names") or []})


def _workflow_texts(f, owner_dir):
    """(path, where, text) for every saved workflow file: the default branch's and every branch copy."""
    out = []
    if not owner_dir:
        return out
    base = os.path.join(owner_dir, "workflows", f["repo"], ".github", "workflows")
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            out.append((f".github/workflows/{name}", f"default branch", _read(os.path.join(base, name))))
    bw = f.get("branch_workflows") or {}
    branches_of = {}
    for b in bw.get("branches") or []:
        for d in b["files"]:
            branches_of.setdefault(d["oid"][:12], []).append(b["name"])
    root = os.path.join(owner_dir, "branch-workflows", f["repo"])
    if os.path.isdir(root):
        for version in sorted(os.listdir(root)):
            folder = os.path.join(root, version, ".github", "workflows")
            for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
                where = "branch " + ", ".join(branches_of.get(version, ["(unknown)"])[:3])
                out.append((f".github/workflows/{name}", where, _read(os.path.join(folder, name))))
    return out


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _file_rule_matches(rule, path, text):
    if rule.get("path") and rule["path"] != path:
        return False
    if rule.get("pattern") and not re.search(rule["pattern"], path):
        return False
    need = rule.get("only_if_contains")
    return not need or (text is not None and any(s in text for s in need))


def match(f, owner_dir=None, iocs=None):
    """[(campaign id, campaign name, what matched)] for one repository."""
    iocs = iocs or load_iocs()
    texts = _workflow_texts(f, owner_dir)
    bw = f.get("branch_workflows") or {}
    runs = (f.get("recent_runs") or {}).get("items") or []
    branches = set(bw.get("names") or []) | {r["head_branch"] for r in runs if r.get("head_branch")}
    pinned = {}
    for w in ((f.get("actions") or {}).get("items") or []) + ((f.get("actions") or {}).get("composite_actions") or []):
        for u in w.get("uses") or []:
            if u.get("ref_type") == "sha":
                pinned.setdefault((u.get("slug"), u["ref"].lower()), w["path"])
    for key, d in (((f.get("actions") or {}).get("lockfile") or {}).get("dependencies") or {}).items():
        pinned.setdefault((d["slug"], (d.get("commit") or "").lower()), "actions.lock")
    messages = [c.get("headline") or "" for c in (f.get("workflow_history") or {}).get("items") or []]
    out = []
    for c in iocs["campaigns"]:
        hits = []
        for rule in c.get("workflow_files") or []:
            for path, where, text in texts:
                if _file_rule_matches(rule, path, text):
                    hits.append(f"workflow file {path} ({where})")
            for r in runs:  # a workflow that ran, even if its branch and file are gone now
                if _file_rule_matches(rule, r.get("path") or "", None if rule.get("only_if_contains") else ""):
                    hits.append(f"workflow {r['path']} ran on {r.get('head_branch')} {(r.get('created_at') or '')[:10]}")
        for s in c.get("workflow_strings") or []:
            hits += [f"'{s}' in {path} ({where})" for path, where, text in texts if s in (text or "")]
        hits += [f"branch {b}" for b in sorted(branches) if b in (c.get("branch_names") or [])]
        for pat in c.get("branch_patterns") or []:
            hits += [f"branch {b}" for b in sorted(branches) if re.search(pat, b)]
        names = set((f.get("runners") or {}).get("names") or [])
        hits += [f"self-hosted runner {n}" for n in c.get("runner_names") or [] if n in names]
        if f.get("repo") in (c.get("repository_names") or []):
            hits.append(f"repository named {f['repo']}")
        desc = f.get("description") or ""
        hits += [f"repository description '{d}'" for d in c.get("repository_descriptions") or [] if d in desc]
        found = set(f.get("ioc_paths") or [])
        hits += [f"file {p}" for p in sorted(found) if p.rsplit("/", 1)[-1] in (c.get("file_names") or [])]
        hits += [f"commit message '{m}'" for m in messages if m in (c.get("commit_messages") or [])]
        for action, commits in (c.get("action_commits") or {}).items():
            for sha in commits or []:
                where = pinned.get((action.lower(), sha.lower()))
                if where:
                    hits.append(f"{action} pinned to malicious commit {sha[:12]} in {where}")
        for h in dict.fromkeys(hits):
            out.append((c["id"], c["name"], h))
    return out


def exposure(f, iocs=None):
    """[(campaign name, action, window)] for actions this repository uses by a movable reference that a
    campaign compromised during a time window. The runs in that window need checking (the `uses` command)."""
    iocs = iocs or load_iocs()
    used = {}
    for w in ((f.get("actions") or {}).get("items") or []):
        for u in w.get("uses") or []:
            if u.get("ref_type") != "sha" and u.get("slug"):
                used.setdefault(u["slug"], u["ref"])
    out = []
    for c in iocs["campaigns"]:
        win = c.get("exposure_window") or {}
        for action in win.get("actions") or []:
            if action.lower() in used:
                out.append((c["name"], action, f"{str(win['from'])[:16]} to {str(win['to'])[:16]} UTC"))
    return out


def ioc_flags(f, owner_dir=None):
    flags = [("IOC_MATCH", "high", f"{name}: {what}") for _, name, what in match(f, owner_dir)]
    flags += [("IOC_EXPOSURE_WINDOW", "info", f"{action} is used by tag; {name} ran malicious code through it "
                                              f"{window}. Check runs in that window with the uses command")
              for name, action, window in exposure(f)]
    return flags
