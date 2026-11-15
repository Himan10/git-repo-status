"""Read GitHub Actions files: workflows, composite actions and the actions.lock lockfile.

Pure functions, text in and facts out. No API calls, and nothing is executed.
Checks that zizmor already does (injection, triggers, pinning, permissions, ...) are left to zizmor;
this module records what repo-status needs for its own checks and for the org-wide inventory.
"""
import re

import yaml

SHA = re.compile(r"^[0-9a-fA-F]{40}$")
FULL_VERSION = re.compile(r"^v?\d+\.\d+\.\d+$")          # v1.2.3: should never move
FLOATING_VERSION = re.compile(r"^v?\d+(\.\d+)?$")        # v1, v1.2: moves with each release
SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)")
ALL_SECRETS = re.compile(r"toJSON\(\s*secrets\s*\)", re.IGNORECASE)

REGISTRY_PATTERNS = {
    "ghcr.io": r"\bghcr\.io\b",
    "docker.io": r"\b(docker\.io|registry-1\.docker\.io|index\.docker\.io)\b",
    "ecr": r"\b\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\b|aws-actions/amazon-ecr-login",
    "gcr/artifact-registry": r"\b([a-z0-9-]+-docker\.pkg\.dev|(\w+\.)?gcr\.io)\b",
    "acr": r"\b[a-z0-9]+\.azurecr\.io\b",
    "quay.io": r"\bquay\.io\b",
}
PUSH_PATTERN = re.compile(r"docker\s+push|docker/build-push-action|push:\s*true|buildah\s+push|podman\s+push|crane\s+(push|copy)")

# Events whose text (titles, bodies, branch names, comments) comes from people outside the repo
UNTRUSTED_TRIGGERS = {"issues", "issue_comment", "pull_request_target", "pull_request_review",
                      "pull_request_review_comment", "discussion", "discussion_comment"}
# AI agent actions that read issue / PR / comment text and can act with the job's token
AI_AGENT_ACTIONS = {"anthropics/claude-code-action", "anthropics/claude-code-base-action",
                    "google-github-actions/run-gemini-cli", "openai/codex-action", "actions/ai-inference"}

# Script checks zizmor does not make
PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+(-E\s+)?)?(ba|z|da)?sh\b"
    r"|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(iex|Invoke-Expression)\b", re.IGNORECASE)
GO_LATEST = re.compile(r"\bgo\s+install\s+\S+@latest\b")
PIP_INSTALL = re.compile(r"\bpip3?\s+install\b([^\n;&|]*)")
PIP_ALWAYS_OK = {"pip", "setuptools", "wheel"}
ENCODER = re.compile(r"\b(base64|xxd|od|rev)\b|\bopenssl\s+enc\b")
XTRACE = re.compile(r"\bset\s+-[a-zA-Z]*x[a-zA-Z]*\b|\bset\s+-o\s+xtrace\b|\bbash\s+-[a-zA-Z]*x")
NETWORK = re.compile(r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|socat)\b", re.IGNORECASE)
URL_HOST = re.compile(r"https?://([A-Za-z0-9.-]+)")
ENV_DUMP = re.compile(r"(^|[|;&(\s])(env|printenv)\s*($|[|>;&)])|/proc/self/environ", re.MULTILINE)
# Hosts where sending a credential is normal (publishing, uploading coverage, cloud APIs)
TRUSTED_HOSTS = ("github.com", "githubusercontent.com", "ghcr.io", "docker.io", "docker.com", "npmjs.org",
                 "pypi.org", "pythonhosted.org", "amazonaws.com", "azure.com", "microsoft.com", "googleapis.com",
                 "codecov.io", "sonarcloud.io", "slack.com", "localhost", "127.0.0.1")


def ref_type(ref):
    if not ref:
        return "none"
    if SHA.match(ref):
        return "sha"
    if FULL_VERSION.match(ref):
        return "version"
    if FLOATING_VERSION.match(ref):
        return "floating"
    return "branch-or-other"


def parse_uses(value):
    """One `uses:` value: an action, a reusable workflow, a local path or a docker image."""
    s = str(value).strip()
    if s.startswith(("./", "$/")):
        return {"kind": "local", "target": s}
    if s.startswith("docker://"):
        image = s[len("docker://"):]
        return {"kind": "docker", "target": image, "digest": "@sha256:" in image}
    target, _, ref = s.partition("@")
    parts = target.split("/")
    path = "/".join(parts[2:])
    return {
        "kind": "reusable" if path.startswith(".github/workflows/") else "action",
        "target": target,
        "slug": "/".join(parts[:2]).lower(),
        "path": path,
        "ref": ref,
        "ref_type": ref_type(ref),
    }


def version_comments(text):
    """`uses: x@<sha> # v4.2.0` comments, which YAML parsing drops. Returns {uses value: version}."""
    out = {}
    for m in re.finditer(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)['\"]?\s*#\s*(.+?)\s*$", text, re.MULTILINE):
        v = re.search(r"v?\d+(\.\d+)*", m.group(2))
        if v:
            out[m.group(1)] = v.group(0)
    return out


def _secret_env(env):
    return {k for k, v in (env or {}).items() if isinstance(v, str) and (SECRET_REF.search(v) or ALL_SECRETS.search(v))} \
        if isinstance(env, dict) else set()


def _uses_secret(run, secret_env):
    if SECRET_REF.search(run) or ALL_SECRETS.search(run):
        return True
    return any(re.search(r"\$(\{)?%s\b|\$env:%s\b" % (re.escape(k), re.escape(k)), run) for k in secret_env)


def _pip_unpinned(args):
    pkgs, skip = [], False
    for tok in args.split():
        if skip:
            skip = False
            continue
        if tok in ("-r", "-c", "--requirement", "--constraint", "-e", "--editable", "-i", "--index-url",
                   "--extra-index-url", "-f", "--find-links"):
            skip = True
            continue
        if tok.startswith("-") or tok.startswith(("$", ".", "/", "~")) or "${{" in tok:
            continue
        name = tok.strip("'\"")
        if "==" in name or "@" in name or "/" in name or name.endswith((".whl", ".tar.gz", ".zip")):
            continue
        if re.split(r"[<>=!~\[]", name)[0].lower() in PIP_ALWAYS_OK:
            continue
        pkgs.append(name)
    return pkgs


def _trusted(host):
    host = host.lower().rstrip(".")
    return any(host == t or host.endswith("." + t) for t in TRUSTED_HOSTS)


def script_findings(run, where, secret_env):
    """Checks on one `run:` script. Returns [(code, where, detail)]."""
    out = []
    has_secret = _uses_secret(run, secret_env)
    for m in PIPE_TO_SHELL.finditer(run):
        out.append(("CURL_PIPE_SHELL", where, m.group(0).strip()[:80]))
    for m in GO_LATEST.finditer(run):
        out.append(("GO_INSTALL_LATEST", where, m.group(0)))
    for m in PIP_INSTALL.finditer(run):
        pkgs = _pip_unpinned(m.group(1))
        if pkgs:
            out.append(("UNPINNED_PIP", where, "pip install " + " ".join(pkgs[:5])))
    if has_secret:
        for line in run.splitlines():
            if ENCODER.search(line) and _uses_secret(line, secret_env):
                out.append(("SECRET_ENCODED", where, line.strip()[:100]))
        if XTRACE.search(run):
            out.append(("XTRACE_WITH_SECRETS", where, "shell tracing (set -x) prints commands, including secret values, "
                                                      "in a form log masking can miss"))
    dumps_env = bool(ENV_DUMP.search(run)) or bool(ALL_SECRETS.search(run))
    if NETWORK.search(run) and (has_secret or dumps_env):
        hosts = sorted({h.lower() for h in URL_HOST.findall(run) if not _trusted(h)})
        if hosts:
            what = "environment dump" if dumps_env else "secrets"
            out.append(("EXFIL_PATTERN", where, f"sends {what} to {', '.join(hosts[:3])}"))
    return out


def _walk_steps(steps, job_name, secret_env, text_comments, out):
    for i, step in enumerate(steps if isinstance(steps, list) else []):
        if not isinstance(step, dict):
            continue
        where = f"{job_name}/{step.get('name') or step.get('id') or f'step {i + 1}'}"
        env = secret_env | _secret_env(step.get("env"))
        if "uses" in step:
            u = parse_uses(step["uses"])
            u["where"] = where
            u["version_comment"] = text_comments.get(str(step["uses"]).strip())
            out["uses"].append(u)
            if u["kind"] == "docker":
                out["images"].append({"image": u["target"], "digest": u["digest"], "where": where})
            if u.get("slug") in AI_AGENT_ACTIONS:
                out["ai_agents"].append({"action": u["slug"], "where": where})
        if isinstance(step.get("run"), str):
            out["script"] += script_findings(step["run"], where, env)
        shell = str(step.get("shell") or "")
        if XTRACE.search(shell) and env:
            out["script"].append(("XTRACE_WITH_SECRETS", where, f"shell: {shell}"))


def _image(value):
    img = value.get("image") if isinstance(value, dict) else value
    return str(img) if img else None


def parse_workflow(text):
    """Facts from one workflow file. Keeps the fields collect.py used to produce, plus new ones."""
    out = {"triggers": [], "crons": [], "secrets": [], "registries": [], "pushes_image": False,
           "runs_on": [], "parse_error": None, "uses": [], "images": [], "script": [], "ai_agents": [],
           "has_permissions": False}
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        out["parse_error"] = str(e).splitlines()[0]
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        out["triggers"] = [on]
    elif isinstance(on, list):
        out["triggers"] = [str(t) for t in on]
    elif isinstance(on, dict):
        out["triggers"] = [str(t) for t in on]
        for s in on.get("schedule") or []:
            if isinstance(s, dict) and "cron" in s:
                out["crons"].append(s["cron"])
    comments = version_comments(text)
    wf_env = _secret_env(doc.get("env"))
    out["has_permissions"] = "permissions" in doc
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        ro = job.get("runs-on")
        labels = ro if isinstance(ro, list) else [ro] if ro else []
        out["runs_on"] += [str(l) for l in labels if str(l) not in out["runs_on"]]
        if "uses" in job:  # reusable workflow call
            u = parse_uses(job["uses"])
            u["where"] = str(name)
            u["version_comment"] = comments.get(str(job["uses"]).strip())
            out["uses"].append(u)
        services = job.get("services") if isinstance(job.get("services"), dict) else {}
        for key, val in [("container", job.get("container"))] + [(f"services.{k}", v) for k, v in services.items()]:
            img = _image(val)
            if img:
                out["images"].append({"image": img, "digest": "@sha256:" in img, "where": f"{name}/{key}"})
        _walk_steps(job.get("steps"), str(name), wf_env | _secret_env(job.get("env")), comments, out)
    out["untrusted_triggers"] = sorted(UNTRUSTED_TRIGGERS & set(out["triggers"]))
    out["secrets"] = sorted({s for s in SECRET_REF.findall(text) if s != "GITHUB_TOKEN"})
    out["registries"] = [name for name, pat in REGISTRY_PATTERNS.items() if re.search(pat, text)]
    if "docker/login-action" in text and not out["registries"]:
        out["registries"].append("docker.io")  # login-action without registry: defaults to Docker Hub
    out["pushes_image"] = bool(PUSH_PATTERN.search(text))
    return out


def parse_action(text):
    """Facts from a composite action (action.yml): the actions and scripts it runs."""
    out = {"uses": [], "images": [], "script": [], "ai_agents": [], "parse_error": None}
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        out["parse_error"] = str(e).splitlines()[0]
        return out
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if isinstance(runs, dict):
        if str(runs.get("using", "")).lower() == "docker" and runs.get("image"):
            img = str(runs["image"])
            if img.startswith("docker://"):
                img = img[len("docker://"):]
                out["images"].append({"image": img, "digest": "@sha256:" in img, "where": "runs.image"})
        _walk_steps(runs.get("steps"), "action", set(), version_comments(text), out)
    return out


def parse_lockfile(text):
    """.github/workflows/actions.lock, written by `gh actions-lock` (format version v0.0.x).

    dependencies: {'owner/repo@ref': {ref, commit: 'sha1-<sha>', owner_id, repo_id, uses: [...]}}
    workflows:    {'.github/workflows/x.yml': ['owner/repo@ref', ...]}"""
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        return {"error": str(e).splitlines()[0]}
    if not isinstance(doc, dict):
        return {"error": "not a YAML mapping"}
    deps = {}
    for key, d in (doc.get("dependencies") or {}).items():
        if not isinstance(d, dict):
            continue
        target, _, key_ref = str(key).partition("@")
        commit = str(d.get("commit") or "")
        deps[str(key)] = {
            "slug": "/".join(target.split("/")[:2]).lower(),
            "target": target,
            "ref": str(d.get("ref") or key_ref),
            "commit": commit.split("-", 1)[1] if commit.startswith("sha1-") else commit,
            "owner_id": d.get("owner_id"),
            "repo_id": d.get("repo_id"),
            "uses": [str(u) for u in d.get("uses") or []],
        }
    workflows = {str(p): [str(x) for x in (v or [])] for p, v in (doc.get("workflows") or {}).items()}
    return {"version": str(doc.get("version", "")), "workflows": workflows, "dependencies": deps}
