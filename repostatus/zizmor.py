"""Run zizmor (https://docs.zizmor.sh) on the workflow files repo-status already downloaded.

The org scan runs zizmor fully offline: no token, no network, no extra API calls. It reads the
copies saved in out/<owner>/workflows/<repo>/. The deep dive runs it online (with the token) so the
audits that ask GitHub (impostor commits, known-vulnerable actions, ref confusion) also run.
"""
import json
import os
import re
import shutil
import subprocess

VERSION = "1.32.0"  # pinned; scan.sh and scan.cmd install exactly this version (tests check they agree)
TIMEOUT = 300

# zizmor rules that make a repo a deep-investigation case when they fire at High severity in a
# workflow that still runs. Rules left out (unpinned-uses, excessive-permissions, artipacked, ...)
# are common hygiene findings: they are counted in the report but do not put a repo on the list.
ESCALATE = {"template-injection", "dangerous-checkout", "impostor-commit", "known-vulnerable-actions",
            "github-env", "cache-poisoning", "obfuscation", "bot-conditions", "unredacted-secrets",
            "overprovisioned-secrets", "hardcoded-container-credentials", "insecure-commands",
            "unsound-condition", "ref-confusion", "typosquat-uses"}
INVALID = re.compile(r"failed to validate (?:file://)?(\S+?) as (\w+)")
LEVELS = {"informational": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3}


def find():
    """Path to the zizmor program, or None. scan.sh / scan.cmd put it on PATH through uv."""
    return shutil.which("zizmor")


def version(exe):
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, encoding="utf-8", errors="replace", timeout=60)
        return p.stdout.strip().split()[-1] if p.returncode == 0 and p.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _slim(finding, root):
    det = finding.get("determinations") or {}
    loc = next((l for l in finding.get("locations") or [] if (l.get("symbolic") or {}).get("kind") == "Primary"),
               (finding.get("locations") or [{}])[0])
    key = ((loc.get("symbolic") or {}).get("key") or {})
    path = _rel((key.get("Local") or {}).get("verbatim_path") or "", root)
    row = (((loc.get("concrete") or {}).get("location") or {}).get("start_point") or {}).get("row")
    return {
        "rule": finding.get("ident"),
        "desc": finding.get("desc"),
        "severity": str(det.get("severity", "")).lower(),
        "confidence": str(det.get("confidence", "")).lower(),
        "file": path,
        "line": row + 1 if isinstance(row, int) else None,  # zizmor rows are 0-based
        "note": (loc.get("symbolic") or {}).get("annotation"),
        "ignored": bool(finding.get("ignored")),
    }


def _rel(path, root):
    """Path relative to root, with / separators, as GitHub shows it."""
    if path and root:
        try:
            path = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
        except ValueError:  # different drive on Windows
            pass
    return path.replace(os.sep, "/")


def run(exe, root, raw_path=None, online_token=None, cache_dir=None, persona="regular", no_ignores=False):
    """Audit every workflow, action and Dependabot file under root.

    Returns {"status": "ok" | "error: ..." , "findings": [...]}. Offline unless online_token is given;
    the token is passed only in zizmor's own environment, never on the command line."""
    if not os.path.isdir(root):
        return {"status": "ok", "findings": [], "note": "no workflow files"}
    # --collect=all: the saved files live inside repo-status's own git folder, whose .gitignore excludes out/
    args = [exe, "--format", "json", "--no-exit-codes", "--no-progress", "--color", "never", "--no-config",
            "--collect", "all", "--persona", persona]
    env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN")}
    if online_token:
        env["ZIZMOR_GITHUB_TOKEN"] = online_token
        if cache_dir:
            args += ["--cache-dir", cache_dir]
    else:
        args.append("--offline")
    if no_ignores:
        args.append("--no-ignores")
    args.append(root)
    try:
        p = subprocess.run(args, capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"status": f"error: timed out after {TIMEOUT}s", "findings": []}
    except OSError as e:
        return {"status": f"error: {e}", "findings": []}
    invalid = sorted({_rel(m.group(1), root) for m in INVALID.finditer(p.stderr)})
    if p.returncode != 0 and "no inputs collected" in p.stderr:
        return {"status": "ok", "findings": [], "invalid": invalid, "note": "no valid files to audit"}
    if p.returncode != 0:
        msg = next((l for l in reversed(p.stderr.strip().splitlines()) if l.strip()), f"exit code {p.returncode}")
        return {"status": f"error: {msg[:200]}", "findings": [], "invalid": invalid}
    try:
        data = json.loads(p.stdout or "[]")
    except ValueError:
        return {"status": "error: output was not JSON", "findings": []}
    if raw_path:
        os.makedirs(os.path.dirname(raw_path), exist_ok=True)
        with open(raw_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
    return {"status": "ok", "findings": [_slim(f, root) for f in data], "invalid": invalid}


def escalates(f):
    """A finding that, in a workflow that still runs, puts the repo on the deep-investigation list."""
    return (f["rule"] in ESCALATE and not f["ignored"] and LEVELS.get(f["severity"], 0) >= 3
            and LEVELS.get(f["confidence"], 0) >= 2)
