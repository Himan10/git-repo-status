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

def _pinned_version():
    """The zizmor version pinned in pyproject.toml, the single place versions are set."""
    import tomllib
    from repostatus.output_paths import PROJECT_ROOT
    try:
        with open(os.path.join(PROJECT_ROOT, "pyproject.toml"), "rb") as fh:
            deps = tomllib.load(fh)["project"]["dependencies"]
    except (OSError, KeyError, ValueError):
        return None
    return next((d.split("==", 1)[1].strip() for d in deps if d.replace(" ", "").startswith("zizmor==")), None)


VERSION = _pinned_version()
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
    step = None
    for l in finding.get("locations") or []:  # zizmor marks the enclosing step as a hidden location
        feat = ((l.get("concrete") or {}).get("feature") or "").lstrip("- ")
        if (l.get("symbolic") or {}).get("annotation") == "this step" and feat.startswith("name:"):
            step = feat.splitlines()[0][5:].strip().strip("'\"")
    return {
        "rule": finding.get("ident"),
        "desc": finding.get("desc"),
        "severity": str(det.get("severity", "")).lower(),
        "confidence": str(det.get("confidence", "")).lower(),
        "file": path,
        "line": row + 1 if isinstance(row, int) else None,  # zizmor rows are 0-based
        "note": (loc.get("symbolic") or {}).get("annotation"),
        "step": step,
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


def _invoke(base_args, inputs, env, timeout):
    """Run zizmor once. Returns (findings JSON or None, invalid files, error text or None)."""
    try:
        p = subprocess.run([*base_args, *inputs], capture_output=True, encoding="utf-8", errors="replace", env=env,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, [], f"timed out after {timeout}s"
    except OSError as e:
        return None, [], str(e)
    invalid = [m.group(1) for m in INVALID.finditer(p.stderr)]
    if p.returncode != 0 and "no inputs collected" in p.stderr:
        return [], invalid, None
    if p.returncode != 0:
        if "failed to locate subfeature" in p.stderr:
            return None, invalid, "zizmor could not locate one of its findings in the file (a zizmor bug)"
        return None, invalid, next((l for l in reversed(p.stderr.strip().splitlines()) if l.strip()),
                                   f"exit code {p.returncode}")[:200]
    try:
        return json.loads(p.stdout or "[]"), invalid, None
    except ValueError:
        return None, invalid, "output was not JSON"


def audit_files(root):
    """The files zizmor reads under a saved repository folder, one by one (for retrying a failed run)."""
    out = []
    for folder, _, names in os.walk(root):
        out += [os.path.join(folder, n) for n in sorted(names) if n.endswith((".yml", ".yaml"))]
    return sorted(out)


def _base_args(exe, persona="regular", online_token=None, cache_dir=None, no_ignores=False):
    # --collect=all: the saved files live inside repo-status's own git folder, whose .gitignore excludes out/
    args = [exe, "--format", "json", "--no-exit-codes", "--no-progress", "--color", "never", "--no-config",
            "--collect=all", "--persona", persona]
    env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN")}
    if online_token:
        env["ZIZMOR_GITHUB_TOKEN"] = online_token
        if cache_dir:
            args += ["--cache-dir", cache_dir]
    else:
        args.append("--offline")
    if no_ignores:
        args.append("--no-ignores")
    return args, env


def _audit(base, env, inputs, files_of, timeout):
    """Run zizmor on all inputs at once; if that fails, on each input, and on each file of a failing input,
    so one file zizmor cannot handle only costs that file. Returns (data, invalid, skipped [(file, reason)], error)."""
    data, invalid, err = _invoke(base, inputs, env, timeout)
    if err is None:
        return data, invalid, [], None
    data, invalid, skipped, ok_any = [], list(invalid), [], False
    for item in inputs:
        part, inv, e = _invoke(base, [item], env, timeout)
        if e is None:
            data += part
            invalid += inv
            ok_any = True
            continue
        files = files_of(item) if os.path.isdir(item) else [item]
        for f in files:
            part, inv, e2 = _invoke(base, [f], env, timeout)
            invalid += inv
            if e2 is None:
                data += part
                ok_any = True
            else:
                skipped.append((f, e2))
    return data, invalid, skipped, (None if ok_any or not skipped else skipped[0][1])


def run(exe, root, raw_path=None, online_token=None, cache_dir=None, persona="regular", no_ignores=False):
    """Audit every workflow, action and Dependabot file under root.

    Returns {"status": "ok" | "error: ...", "findings": [...], "invalid": [...], "skipped": [(file, reason)]}.
    If zizmor fails on a file, the other files are still audited and the file is listed under "skipped".
    Offline unless online_token is given; the token is passed only in zizmor's own environment."""
    if not os.path.isdir(root):
        return {"status": "ok", "findings": [], "note": "no workflow files"}
    base, env = _base_args(exe, persona, online_token, cache_dir, no_ignores)
    data, invalid, skipped, err = _audit(base, env, [root], audit_files, TIMEOUT)
    invalid = sorted({_rel(i, root) for i in invalid})
    skipped = [(_rel(f, root), why) for f, why in skipped]
    if err:
        return {"status": f"error: {err}", "findings": [], "invalid": invalid, "skipped": skipped}
    if raw_path:
        os.makedirs(os.path.dirname(raw_path), exist_ok=True)
        with open(raw_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
    return {"status": "ok", "findings": [_slim(f, root) for f in data], "invalid": invalid, "skipped": skipped}


def escalates(f):
    """A finding that, in a workflow that still runs, puts the repo on the deep-investigation list."""
    return (f["rule"] in ESCALATE and not f["ignored"] and LEVELS.get(f["severity"], 0) >= 3
            and LEVELS.get(f["confidence"], 0) >= 2)


ONLINE_RULES = {"known-vulnerable-actions", "impostor-commit", "ref-confusion"}
ONLINE_TIMEOUT = 1800


def run_online(exe, roots, token, cache_dir=None, raw_path=None):
    """One zizmor run over every repository's saved workflow files, with the audits that ask GitHub.

    roots: {repo: folder}. Returns {"status", "findings": {repo: [online findings]}, "skipped": [(repo, file,
    reason)]}. Only the online rules are kept; the offline findings come from the per-repository run. Requests go
    to api.github.com only, about the actions used (name and version); the shared cache means each action is asked
    about once. If zizmor fails on a file, that file is skipped and every other repository is still audited."""
    roots = {repo: os.path.abspath(r) for repo, r in roots.items() if os.path.isdir(r)}
    if not roots:
        return {"status": "ok", "findings": {}, "skipped": []}
    if not token:
        return {"status": "not run: no GitHub token found for zizmor", "findings": {}, "skipped": []}
    base, env = _base_args(exe, online_token=token, cache_dir=cache_dir)
    base = [a for a in base if a not in ("--persona", "regular")]
    data, _, skipped, err = _audit(base, env, list(roots.values()), audit_files, ONLINE_TIMEOUT)
    where = lambda path: next(((repo, _rel(path, root)) for repo, root in roots.items()
                               if not _rel(path, root).startswith("..")), ("?", path))
    skipped = [(*where(f), why) for f, why in skipped]
    if err:
        return {"status": f"error: {err}", "findings": {}, "skipped": skipped}
    if raw_path:
        os.makedirs(os.path.dirname(raw_path), exist_ok=True)
        with open(raw_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
    out = {}
    for finding in data:
        if finding.get("ident") not in ONLINE_RULES:
            continue
        for repo, root in roots.items():
            x = _slim(finding, root)
            if not x["file"].startswith(".."):
                out.setdefault(repo, []).append(dict(x, online=True))
                break
    return {"status": "ok", "findings": out, "skipped": skipped}
