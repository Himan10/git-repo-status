"""The HTML reports: report.html for the whole organisation, and deep-dive/<repo>.html for one repository.

Same checks and words as summary.md and the deep dive's markdown (Fix / Review / OK, no icons), laid out as a
report people work from: a Summary tab for leaders, Findings (grouped by finding type, with filters) for security
teams, Repositories for developers, then Actions and Settings. Large organisations stay readable because
findings are grouped and every list is paged; the page's length never depends on how many findings there are.

Each file is self-contained and works offline: inline style and script, nothing loaded from the internet, no
server. Everything collected from GitHub (repository and branch names, workflow text, commit messages) can be
written by an attacker, so it is only ever inserted as text: the organisation page builds its DOM with
textContent from embedded JSON, the deep-dive page escapes every value, links must point to github.com or to a
deep-dive page, and the CSV export defuses spreadsheet formulas.
"""
import html
import json
import os
import re
from collections import Counter

from repostatus.platform_support import scan_cmd
from repostatus.checks import action_health
from repostatus.reports import deep_dive_verdict, finding_explanations, org_summary
from repostatus.reports.github_links import SHA, commit_url, file_url

AREA_WHAT = {
    "History": "Force pushes, odd commit dates, unusual signing",
    "Workflow changes": "Changes after quiet periods or by someone new; secrets sent out",
    "Workflow flaws": "Injection, risky triggers, unsafe checkouts (zizmor)",
    "Old copies on branches": "Forgotten workflow copies that can still run",
    "Secrets": "Who can reach each secret; static cloud keys",
    "Upstream actions": "Moved tags, vulnerabilities, owners gone",
    "Repository settings": "Branch rules, CODEOWNERS, token permissions",
    "Workflow hygiene": "Unpinned actions, no actions.lock, risky installs",
}
RANK = {"Fix": 0, "Review": 1, "OK": 2, "Not checked": 3}
MAX_PER_ACTION = 50  # findings one action can add (e.g. one per commit); the rest are in the deep dive


def _short_note(text):
    """'force-push allowed on default branch (private repo ...)' -> 'Force-push allowed on default branch'.
    Notes that carry a count ('3 of 5 actions are not pinned ...') get one name, so they group together."""
    if re.match(r"\d+ of \d+ actions are not pinned", text):
        return "Actions not pinned to a commit"
    if text.startswith("Branch rules (block force pushes"):
        return "Branch rules not available on this plan (GitHub Free, private repository)"
    s = text.split(" (")[0].split(":")[0].strip()
    return s[:1].upper() + s[1:]


def _note_detail(text, title):
    """What a note adds to its name: 'force-push allowed (private repo on GitHub Free)' -> 'private repo on GitHub Free'."""
    if title == "Actions not pinned to a commit":
        return text.split(",")[0]
    if text.startswith("Branch rules (block force pushes"):
        return "Force pushes cannot be blocked, and pull requests and code-owner review cannot be required"
    short = text.split(" (")[0].split(":")[0]
    rest = text[len(short):].strip().strip(":").strip()
    if rest.startswith("(") and "): " in rest:  # 'name (aside): the list' -> 'the list'
        return rest.split("): ", 1)[1]
    return rest[1:-1] if rest.startswith("(") and rest.endswith(")") else rest


def _title(a):
    """A grouped action's title names what it found ('Repository settings' -> 'No CODEOWNERS; force-push ...')."""
    if not a.get("items"):
        return a["title"]
    names = list(dict.fromkeys(_short_note(i["text"]) for i in a["items"]))
    text = "; ".join(names[:3]) + (f"; and {len(names) - 3} more" if len(names) > 3 else "")
    return text[:1].upper() + text[1:]


PATH = re.compile(r"\.github/[\w.\-/]+|[\w.\-/]*action\.ya?ml")
ON_BRANCH = re.compile(r"on branch ([^\s,;:()]+)")
ZIZMOR_DOCS = "https://docs.zizmor.sh/audits/#{rule}"
NOTE_PAGE = [  # (start of note, settings page) for notes that are settings, not files
    ("force-push allowed", "rules"), ("no PR required", "rules"), ("CODEOWNERS not enforced", "rules"),
    ("approvals stay valid", "rules"), ("whoever pushed last", "rules"), ("workflow token can write", "actions"),
    ("workflows can approve", "actions"), ("any action from any author", "actions"), ("fork pull request", "actions"),
    ("pull_request_target", "actions"), ("pinning to a commit is required", "actions"), ("last pusher has no access", "access"),
    ("branch rules (block force pushes", "rules"), ("branch rules could not be read", "rules"),
    ("secrets any branch can read", "secrets"), ("static cloud keys", "secrets"), ("environments", "environments"),
    ("older workflow copies", "branches"), ("workflow files only on other branches", "branches"),
]


def _locate(text, f, lines=None):
    """Where a finding is, as (text, GitHub link): the file and the branch it is on, else the settings page
    that controls it, else the repository's file list."""
    full, branch = f.get("full_name") or f["repo"], f.get("default_branch") or "main"
    m = PATH.search(text or "")
    if m:
        path = m.group(0).rstrip(".,;:")
        b = ON_BRANCH.search(text)
        b = b.group(1) if b else branch
        anchor = f"#L{lines[0]}" if lines else ""
        shown = path + (":" + ",".join(str(n) for n in lines) if lines else "")
        return f"{shown} on {b}", file_url(full, b, path) + anchor
    low = (text or "").lower()
    for prefix, key in NOTE_PAGE:
        if low.startswith(prefix.lower()):
            link = finding_explanations.settings_link(key, full)
            return link[0], link[1]
    if low.startswith(("no codeowners", "codeowners errors", "workflows have no code owner")):
        return f".github/CODEOWNERS on {branch}", f"https://github.com/{full}/tree/{branch}/.github"
    if low.startswith(("other zizmor findings", "uses actions with known problems")) or "actions.lock" in low \
            or re.match(r"\d+ of \d+ actions are not pinned", low):
        files = _unpinned_files(f) if "not pinned" in low else []
        shown = ", ".join(p.rsplit("/", 1)[-1] for p in files[:4]) + (f" and {len(files) - 4} more" if len(files) > 4 else "")
        return (f"{shown or '.github/workflows/'} on {branch}",
                file_url(full, branch, files[0]) if len(files) == 1 else f"https://github.com/{full}/tree/{branch}/.github/workflows")
    return "Repository settings", f"https://github.com/{full}/settings"


def _unpinned_files(f):
    """Workflow and action files with a `uses:` not pinned to a commit."""
    a = f.get("actions") or {}
    return sorted({w["path"] for w in (a.get("items") or []) + (a.get("composite_actions") or [])
                   for u in w.get("uses") or [] if u.get("kind") in ("action", "reusable") and u.get("ref_type") != "sha"})


def _note_fix(text, title, a):
    """What to do about a note, in words that make sense on the page (not the markdown report's)."""
    if title in ("Actions not pinned to a commit", "No actions.lock") and a.get("fix"):
        return a["fix"]
    if title == "Other zizmor findings":
        return ("Each rule is linked under the finding to zizmor's documentation, which explains it and shows the fix. "
                "Change the workflow files named under Where.")
    if title.startswith("Branch rules not available") and a.get("fix"):
        return a["fix"]
    if title == "Invalid workflow file":
        return ("Fix the file so GitHub can run it (the Actions tab on GitHub shows the error), or delete it if it is "
                "no longer needed. An invalid file can hide a check someone expects to run.")
    if title == "Pip install without pinned versions":
        return ("Pin each package to an exact version (`package==1.2.3`), or install from a requirements file with "
                "hashes (`pip install --require-hashes -r requirements.txt`).")
    if title == "Uses actions with known problems":
        return "The Actions tab lists each action's problem and every place it is used."
    where = org_summary.where_to_fix(text)
    if where.startswith("The workflow file named"):
        return "Change the file or setting linked under Where."
    return f"Change it in: {where}"


def _commit_links(text, f, code):
    """Every commit named in a finding, linked, with its FINDING: keyword (as in the markdown reports)."""
    full = f.get("full_name") or f["repo"]
    return [[f"{sha[:7]} FINDING: {code}", commit_url(full, sha)] for sha in dict.fromkeys(SHA.findall(text or ""))]


def _findings(a, f):
    """One action of the verdict as findings: (type key, title, where, link, detail, links, why, fix, docs).
    Grouped actions (settings, hygiene) become one finding per note, so the Findings tab groups the same note
    across repositories."""
    out = []
    full = f.get("full_name") or f["repo"]
    if a.get("items"):
        for i in a["items"]:
            title = _short_note(i["text"])
            where, url = (i["settings"][0], i["settings"][1]) if i.get("settings") else _locate(i["text"], f)
            fix = _note_fix(i["text"], title, a)
            links = [[f"zizmor: {r}", ZIZMOR_DOCS.format(rule=r)] for r in re.findall(r"([a-z][a-z0-9-]+) \(\d+\)", i["text"])] \
                if title == "Other zizmor findings" else []
            out.append((f"note:{title.lower()}", title, where, url, _note_detail(i["text"], title), links,
                        a.get("why") or "", fix, None))
    elif a.get("lines"):
        rule = finding_explanations.ZIZMOR.get(a["code"], {}).get("title") or a["code"]
        nums = [ln["line"] for ln in a["lines"] if ln.get("line")]
        where, url = _locate(a["file"], f, nums)
        detail = f"Who can use it: {a.get('who') or 'unknown'}. Can read: {a.get('reach') or 'no secrets'}" \
                 + ("" if a.get("live") else ". The workflow no longer runs")
        docs = ZIZMOR_DOCS.format(rule=a["code"])
        out.append((f"zizmor:{a['code']}", rule, where, url, detail, [[f"zizmor: {a['code']}", docs]],
                    a.get("why") or "", a.get("fix") or "", docs))
    else:
        settings = [[x[0], x[1]] for x in (a.get(k) for k in ("settings", "settings2")) if x]
        for w in (a.get("where") or [""])[:MAX_PER_ACTION]:
            where, url = _locate(w, f)
            if not url and settings:
                where, url = settings[0]
            out.append((a["code"], a["title"], where, url, w, _commit_links(w, f, a["code"]) + settings[1:],
                        a.get("why") or "", a.get("fix") or "", None))
    return out


def org_page(ctx, rows, cfg, now, owner_dir, generated=None):
    """Everything report.html shows, as plain data. Findings point into shared lists of types and repositories
    so that tens of thousands of findings stay a few megabytes."""
    owner = ctx["owner"]
    areas = deep_dive_verdict.AREAS
    status = Counter(r["status"] for r in rows)
    types, type_index, repos, findings = [], {}, [], []
    quiet_running = quiet_secrets = 0
    for r in rows:
        f = r["f"]
        x = org_summary.row_for(r, now, cfg)
        name = f["repo"]
        f = {**f, "full_name": f.get("full_name") or f"{owner}/{name}"}  # older scans may not have it
        report = os.path.exists(os.path.join(owner_dir, "deep-dive", f"{name}.html"))
        if r["status"] in ("dormant", "dead") and x["workflows_run_last_90_days"]:
            quiet_running += 1
            quiet_secrets += bool(x["workflow_secrets"])
        team = x["workflows_owner"] or "none"
        entry = {"n": name, "vis": f.get("visibility") or "", "push": x["last_human_push"], "status": r["status"],
                 "team": team, "codes": sorted({c for c, _, _ in org_summary.deep_reasons(r)}),
                 "report": f"deep-dive/{name}.html" if report else None, "cmd": f"{scan_cmd()} {owner} deep {name}"}
        if f.get("empty") or "history" not in f:
            entry.update(verdict="Not checked", fix=0, review=0, areas=[],
                         main="Empty repository" if f.get("empty") else "Could not be read")
            repos.append(entry)
            continue
        result = deep_dive_verdict.assess(f, {**r, "now": now, "cfg": cfg}, f"{owner}/{name}", owner_dir)
        ri = len(repos)
        per_area = Counter()
        for a in result["actions"]:
            for key, title, where, url, detail, links, why, fix, docs in _findings(a, f):
                if key not in type_index:
                    type_index[key] = len(types)
                    types.append([key, title, a["area"], why, fix, docs])
                findings.append([type_index[key], ri, 1 if a["level"] == "Fix" else 0, where, detail, url, links])
                per_area[a["area"]] += 1
        fixes = sum(a["level"] == "Fix" for a in result["actions"])
        reviews = sum(a["level"] == "Review" for a in result["actions"])
        first = result["actions"][0] if result["actions"] else None
        entry.update(verdict="Fix" if fixes else "Review" if reviews else "OK", fix=fixes, review=reviews,
                     main=_findings(first, f)[0][1] if first else "Nothing found",
                     areas=[[ar["result"], per_area[ar["name"]]] for ar in result["areas"]])
        repos.append(entry)

    deep_rows = [r for r in rows if org_summary.deep_reasons(r)]
    by_code = {}
    for r in deep_rows:
        for code, sev, _ in org_summary.deep_reasons(r):
            e = by_code.setdefault(code, {"sev": sev, "repos": set()})
            e["repos"].add(r["f"]["repo"])
            if org_summary.SEVERITY_ORDER[sev] < org_summary.SEVERITY_ORDER[e["sev"]]:
                e["sev"] = sev
    reasons = []
    for code, e in sorted(by_code.items(), key=lambda kv: (org_summary.SEVERITY_ORDER[kv[1]["sev"]], -len(kv[1]["repos"]), kv[0])):
        _, meaning, check = org_summary.REASONS.get(code, ("repo-status", "", ""))
        reasons.append([code, meaning or code, "High" if e["sev"] == "high" else "Medium", len(e["repos"]), check])

    index = ctx.get("action_index")
    actions = {"checked": bool(index), "rows": [], "distinct": 0, "ok": 0}
    if index:
        assessed = action_health.org_actions(index, rows, now)
        bad = [x for x in assessed if x[1]["level"] in ("Fix", "Review")]
        facts = [r["f"] for r in rows]
        index_of = {e["n"]: i for i, e in enumerate(repos)}
        actions.update(distinct=len(assessed), ok=len(assessed) - len(bad), rows=[
            [slug, a["level"], "; ".join(t for _, t in a["problems"]), len(users), _places(facts, slug, index_of)]
            for slug, a, users in bad])
    hy = Counter(h.split(":")[0].split(" (")[0] for r in rows for h in r["hygiene"])
    settings = [[_short_note(k), v, org_summary.where_to_fix(k)] for k, v in hy.most_common()]
    try:
        from repostatus.checks.ioc_matching import load_iocs
        campaigns = len(load_iocs()["campaigns"])
    except Exception:  # a broken iocs.yml is reported by the scan itself
        campaigns = 0
    high = sum(1 for r in deep_rows if org_summary.priority(r) == "high")
    return {
        "owner": owner, "collected": f"{now:%d %b %Y, %H:%M}", "generated": f"{generated:%d %b %Y}" if generated else "",
        "age_days": (generated - now).days if generated else 0, "api_calls": ctx.get("api_calls"),
        "zizmor": (ctx.get("zizmor") or {}).get("version") or "", "cmd": scan_cmd(),
        "status": {k: status[k] for k in ("active", "dormant", "dead", "archived", "empty", "unknown")},
        "cfg": {k: cfg[k] for k in ("dormant_days", "dead_days")},
        "deep": {"count": len(deep_rows), "high": high, "medium": len(deep_rows) - high},
        "quiet": [quiet_running, quiet_secrets],
        "iocs": [[r["f"]["repo"], d] for r in rows for c, _, d in r["flags"] if c == "IOC_MATCH"], "campaigns": campaigns,
        "areas": areas, "area_what": [AREA_WHAT[a] for a in areas], "reasons": reasons,
        "types": types, "repos": repos, "findings": findings, "actions": actions, "settings": settings,
    }


def _places(facts, slug, index_of):
    """Where an action is used: [repo index, file, version, pinned, locked, workflow state, last run, how]."""
    out = []
    for h in action_health.who_uses(facts, slug):
        wf = h.get("wf") or {}
        ref = h["ref"][:12] + (f" ({h['version']})" if h.get("version") else " (no version comment)") \
            if h["ref_type"] == "sha" else (h["ref"] or "-")
        out.append([index_of.get(h["repo"], -1), h["path"], ref, "yes" if h["ref_type"] == "sha" else "no",
                    "yes" if h["locked"] else "no", wf.get("state") or "", (wf.get("last_run") or "")[:10],
                    "" if h["via"] == "direct" else h["via"]])
    return sorted(out, key=lambda x: (x[6] == "", [-ord(c) for c in x[6]], x[0], x[1]))


def _embed(data):
    """JSON that cannot end the <script> element it sits in, whatever the repositories contain."""
    return (json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def write_org(path, data):
    page = (ORG_TEMPLATE.replace("__TITLE__", html.escape(f"{data['owner']}: Repo Status"))
            .replace("__CSS__", CSS).replace("__JS__", ORG_JS).replace("__DATA__", _embed(data)))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)


def rebuild_org(owner_dir, facts, cfg=None, generated=None):
    """Write report.html again from facts.json (no API calls), e.g. after a deep dive added a report to link to."""
    from datetime import datetime
    from repostatus.checks import repository_checks
    ctx = facts["context"]
    now = datetime.fromisoformat(ctx["collected_at"])
    rows, cfg = repository_checks.evaluate(facts["repos"], ctx, now, cfg, owner_dir=owner_dir)
    write_org(os.path.join(owner_dir, "report.html"), org_page(ctx, rows, cfg, now, owner_dir, generated))
    return os.path.join(owner_dir, "report.html")


# ---------------------------------------------------------------- deep dive page (static, no script)

E = html.escape


def _text(s):
    """Escaped text with `code` spans."""
    parts = str(s or "").split("`")
    return "".join(f"<code>{E(p)}</code>" if i % 2 else E(p) for i, p in enumerate(parts))


def _where(s, full, code):
    """Escaped text with every commit id turned into a link, marked FINDING: CODE like the markdown report."""
    out, last = [], 0
    s = str(s or "")
    for m in SHA.finditer(s):
        out.append(_text(s[last:m.start()]))
        sha = m.group(0)
        out.append(f'<a href="{E(commit_url(full, sha))}">{E(sha[:7])}</a> <span class="code">FINDING: {E(code)}</span>')
        last = m.end()
    out.append(_text(s[last:]))
    return "".join(out)


def _link(pair):
    """('Settings > Rules', url) as a link, only to github.com."""
    label, url = pair
    return f'<a href="{E(url)}">{E(label)}</a>' if str(url).startswith("https://github.com/") else E(label)


def _word(word):
    cls = {"Fix": "fix", "Review": "review", "OK": "ok"}.get(word, "na")
    return f'<span class="v v-{cls}">{E(word)}</span>'


def _where_short(a):
    if a.get("file"):
        lines = ",".join(str(ln["line"]) for ln in a.get("lines") or [] if ln.get("line"))
        return a["file"].rsplit("/", 1)[-1] + (f":{lines}" if lines else "")
    if a.get("items"):
        return f"{len(a['items'])} item{'s' if len(a['items']) != 1 else ''}"
    w = (a.get("where") or [""])[0]
    return w[:60] + ("..." if len(w) > 60 else "") + (f" and {len(a['where']) - 1} more" if len(a.get("where") or []) > 1 else "")


def _out(label_html, url):
    """A link to GitHub or zizmor's documentation; anything else stays text."""
    ok = str(url or "").startswith(("https://github.com/", "https://docs.zizmor.sh/"))
    return f'<a href="{E(url)}">{label_html}</a>' if ok else label_html


def _details(a, f):
    full, branch = f.get("full_name") or f["repo"], f.get("default_branch") or "main"
    D = []
    if a.get("lines"):
        base = file_url(full, branch, a["file"])
        D.append(("Where", _out(f'<code>{E(a["file"])}</code>', base) + f" on {E(branch)}"
                  + (f', step "{E(a["step"])}"' if a.get("step") else "")
                  + "<ul>" + "".join(f'<li>{_out("line " + E(str(ln["line"])), base + "#L" + str(ln["line"]))}: <code>{E(ln["text"] or "")}</code>'
                                     + (" (a value GitHub generates; low risk)" if ln["harmless"] else "") + "</li>"
                                     for ln in a["lines"]) + "</ul>"))
    elif a.get("items"):
        lis = []
        for i in a["items"]:
            where, url = (i["settings"][0], i["settings"][1]) if i.get("settings") else _locate(i["text"], f)
            lis.append(f"<li>{_text(i['text'])}" + (f". Where: {_out(E(where), url)}" if where else "") + "</li>")
        D.append(("Found", "<ul>" + "".join(lis) + "</ul>"))
    elif a.get("where"):
        lis = []
        for w in a["where"][:8]:
            where, url = _locate(w, f)
            lis.append(f"<li>{_where(w, full, a['code'])}" + (f" ({_out('open ' + E(where), url)})" if url and PATH.search(w) else "") + "</li>")
        D.append(("Where", "<ul>" + "".join(lis) + (f"<li>{len(a['where']) - 8} more in the evidence file</li>" if len(a["where"]) > 8 else "") + "</ul>"))
    if a.get("who"):
        D.append(("Who can use it", f"{E(a['who'])}. {'The workflow still runs and can read' if a.get('live') else 'It can read'}: "
                                    f"{E(a['reach'])}."))
    if a.get("why"):
        D.append(("What it means", _text(a["why"])))
    if a.get("fix"):
        D.append(("What to do", _text(a["fix"])))
    if a.get("lines"):
        D.append(("How to fix it", _out(f"zizmor documentation: {E(a['code'])}", ZIZMOR_DOCS.format(rule=a["code"]))))
    links = [_link(a[k]) for k in ("settings", "settings2") if a.get(k)]
    if links:
        D.append(("Where on GitHub", " &middot; ".join(links)))
    D.append(("Finding code", f'<span class="code">FINDING: {E(a["code"])}</span>'))
    return "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in D) + "</dl>"


def deep_page(owner, f, collected_at, result, evidence_name, facts_row=None):
    """The deep-dive report: one verdict line, the findings (Fix ones open), the eight areas, evidence and limits."""
    full = f"{owner}/{f['repo']}"
    f = {**f, "full_name": f.get("full_name") or full}
    x = facts_row or {}
    acts = result["actions"]
    fixes = sum(a["level"] == "Fix" for a in acts)
    reviews = len(acts) - fixes
    rest = ". ".join(result["verdict"].split(". ")[1:])
    facts = [x.get("status"), f.get("visibility"),
             f"last push by a person {x['last_human_push']}" if x.get("last_human_push") else None,
             f"{x['enabled_workflows']} workflows enabled, {x['workflows_run_last_90_days']} ran in the last 90 days"
             if x.get("enabled_workflows") not in (None, "") else None,
             f"workflow owners {x['workflows_owner']}" if x.get("workflows_owner") else None]
    B = [f'<section><h1>{E(f["repo"])}: <span class="v-fix">{fixes} to fix</span>, <span class="v-review">{reviews} to review</span></h1>',
         f"<p>{E(rest)}</p>",
         '<p class="meta">' + " &middot; ".join(E(str(v)) for v in facts if v)
         + ' &middot; <a href="../report.html">Back to the organisation report</a></p></section>']
    B.append("<section><h2>Findings</h2>")
    if acts:
        B.append('<div class="flist"><div class="frow fhead"><span>#</span><span>Verdict</span><span>Finding</span>'
                 '<span>Area</span><span>Where</span></div>')
        for i, a in enumerate(acts, 1):
            B.append(f'<details class="fitem" id="a{i}"{" open" if a["level"] == "Fix" else ""}><summary class="frow">'
                     f'<span class="muted">{i}</span><span>{_word(a["level"])}</span><span class="ftitle">{E(_title(a))}</span>'
                     f'<span class="muted">{E(a["area"])}</span><span class="mono">{E(_where_short(a))}</span></summary>'
                     f'<div class="fbody">{_details(a, f)}</div></details>')
        B.append("</div>")
    else:
        B.append('<p class="meta">Nothing to fix or review.</p>')
    B.append("</section>")
    B.append('<section><h2>Areas checked</h2><table class="plain"><thead><tr><th style="width:200px">Area</th>'
             '<th style="width:110px">Result</th><th>In short</th></tr></thead><tbody>')
    for ar in result["areas"]:
        name = f'<a href="{E(evidence_name)}#{E(ar["evidence"])}">{E(ar["name"])}</a>' if ar.get("evidence") else E(ar["name"])
        B.append(f"<tr><td>{name}</td><td>{_word(ar['result'])}</td><td class=\"soft\">{E(ar['short'])}</td></tr>")
    B.append("</tbody></table></section>")
    B.append(f'<section class="small"><h2>Evidence and limits</h2><p><a href="{E(evidence_name)}">{E(evidence_name)}</a>: every '
             f"commit, run, branch copy, secret and setting behind this report, with links to GitHub (a markdown file; open it in "
             f"VS Code or a text editor).</p><p>What this cannot see:</p><ul>"
             + "".join(f'<li class="soft">{_text(c)}</li>' for c in result["limits"]) + "</ul>"
             + f'<details class="plain"><summary>Checked, nothing found ({len(result["clean"])})</summary><ul>'
             + "".join(f"<li>{_text(c)}</li>" for c in result["clean"]) + "</ul></details></section>")
    header = (f'<header class="top"><div class="wrap narrow bar"><div class="crumbs">Repo Status <span class="sep">/</span> '
              f'<a href="../report.html">{E(owner)}</a> <span class="sep">/</span> {E(f["repo"])}</div>'
              f'<div class="meta grow">Deep dive &middot; data collected {E(collected_at[:16].replace("T", " "))} UTC</div>'
              f'<div class="meta small">Contains private data. Share inside your organisation only.</div></div></header>')
    return (DEEP_TEMPLATE.replace("__TITLE__", E(f"{f['repo']}: deep dive")).replace("__CSS__", CSS)
            .replace("__HEADER__", header).replace("__BODY__", "\n".join(B)))


def write_deep(path, owner, f, collected_at, result, evidence_name, facts_row=None):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(deep_page(owner, f, collected_at, result, evidence_name, facts_row))


# ---------------------------------------------------------------- templates

CSS = r"""
:root{--bg:#FFFFFF;--ink:#1F2328;--soft:#3D444D;--muted:#59636E;--line:#D1D9E0;--line2:#EEF1F4;--head:#F6F8FA;--open:#FAFBFC;
--link:#0B57D0;--fix:#B42318;--review:#7D4E00;--ok:#116329;--na:#59636E;--focus:#0B57D0}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;font-variant-numeric:tabular-nums}
a{color:var(--link)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
code,.mono,.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
code{background:var(--head);border:1px solid var(--line2);border-radius:4px;padding:1px 4px;overflow-wrap:anywhere}
.code{font-weight:600}
.wrap{max-width:1440px;margin:0 auto;padding:0 24px}.narrow{max-width:1100px}
.top{border-bottom:1px solid var(--line)}.bar{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 16px;padding-top:14px;padding-bottom:14px}
.crumbs{font-size:16px;font-weight:600}.crumbs a{color:var(--ink)}.sep{color:var(--muted);font-weight:400}
.meta{color:var(--muted);font-size:13px}.grow{flex:1 1 320px}.small{font-size:13px}.muted{color:var(--muted)}.soft{color:var(--soft)}
.tabs{display:flex;flex-wrap:wrap;gap:0 4px;padding-top:0}
.tab{background:none;border:0;border-bottom:2px solid transparent;padding:8px 12px 10px;font:inherit;cursor:pointer;color:var(--ink)}
.tab[aria-current=page]{border-bottom-color:var(--ink);font-weight:600}.tab .n{color:var(--muted);font-weight:400;margin-left:4px}
main.wrap{padding-top:20px;padding-bottom:48px}
h1{margin:0 0 6px;font-size:20px;font-weight:600}h2{margin:0 0 8px;font-size:15px;font-weight:600}
section{margin-bottom:28px}p{margin:0 0 6px}
.v{font-weight:600}.v-fix{color:var(--fix);font-weight:600}.v-review{color:var(--review);font-weight:600}.v-ok{color:var(--ok)}.v-na{color:var(--na)}
.linkbtn{background:none;border:0;padding:0;color:var(--link);cursor:pointer;font:inherit;text-align:left}
.titlebtn{background:none;border:0;padding:0;color:var(--ink);cursor:pointer;font:inherit;font-weight:600;text-align:left}
table{width:100%;border-collapse:collapse;font-size:13px}
table.plain th{text-align:left;color:var(--muted);font-weight:600;padding:6px 12px 6px 0;border-bottom:1px solid var(--line)}
table.plain td{padding:6px 12px 6px 0;border-bottom:1px solid var(--line2);vertical-align:top}
.box{border:1px solid var(--line);border-radius:6px;overflow-x:auto}
.box th{text-align:left;color:var(--muted);font-weight:600;background:var(--head);padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
.box td{padding:7px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
.num,table.plain th.num,table.plain td.num,.box th.num,.box td.num,.inner table th.num,.inner table td.num{text-align:right;white-space:nowrap}.nowrap{white-space:nowrap}tr.is-open>td{background:var(--head)}
td.inner{padding:0;background:var(--open);border-bottom:1px solid var(--line)}
.inner table th{background:none;border-bottom:0;padding:6px 12px}.inner table td{border-bottom:0;border-top:1px solid var(--line2);padding:6px 12px}
.inner table th:first-child,.inner table td:first-child{padding-left:28px}
.innerbar{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;padding:8px 12px 10px 28px;border-top:1px solid var(--line2);color:var(--muted);font-size:13px}
.layout{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start}
aside{flex:1 1 220px;max-width:260px;font-size:13px}
.content{flex:999 1 640px;min-width:0;display:flex;flex-direction:column;gap:12px}
.ahead{display:flex;justify-content:space-between;align-items:baseline;padding-bottom:8px;border-bottom:1px solid var(--line)}
fieldset{border:0;border-bottom:1px solid var(--line2);margin:0;padding:0 0 8px;min-width:0}
legend{padding:12px 0 2px;margin:0;font-weight:600}
.opt{display:flex;align-items:center;gap:8px;padding:3px 0;min-height:28px;cursor:pointer}.opt input{margin:0;width:15px;height:15px;accent-color:var(--ink)}
.opt .l{flex:1 1 auto;overflow-wrap:anywhere}.opt .c{color:var(--muted)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center}.toolbar .spacer{flex:1 1 auto}
input[type=search],select{height:36px;padding:0 10px;border:1px solid var(--line);border-radius:6px;font:inherit;color:var(--ink);background:var(--bg)}
input[type=search]{flex:1 1 320px;max-width:520px}
.btn{height:36px;padding:0 12px;border:1px solid var(--line);border-radius:6px;background:var(--head);color:var(--ink);font:inherit;cursor:pointer}
.btn.sm{height:28px;padding:0 10px;background:var(--bg)}.btn:disabled{color:var(--muted);cursor:default}
.pbtn{min-width:32px;height:32px;padding:0 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit;cursor:pointer}
.pbtn[aria-current=page]{background:var(--ink);color:var(--bg);border-color:var(--ink)}.pbtn:disabled{color:var(--muted);cursor:default}
.pager{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:space-between;font-size:13px}
.pager .pages{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
.info{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:baseline;font-size:13px;color:var(--muted)}.info strong{color:var(--ink)}
.linkout{width:100%;max-width:720px;height:32px;border:1px solid var(--line);border-radius:6px;padding:0 8px;font:inherit;font-size:12px;color:var(--ink);background:var(--bg)}
.where{overflow-wrap:anywhere;font-size:12px}.links{display:flex;flex-wrap:wrap;gap:2px 14px;margin-top:4px;font-size:12px}.about{display:grid;grid-template-columns:120px minmax(0,1fr);gap:4px 16px;margin:0;padding:10px 12px 10px 28px;font-size:13px;border-bottom:1px solid var(--line2)}.about dt{color:var(--muted)}.about dd{margin:0}.areas-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:4px 24px}.areas-grid .v{display:inline-block;min-width:60px}
.notice{border:1px solid var(--fix);border-left-width:4px;padding:10px 14px;margin-bottom:20px}
.doc{max-width:980px}.facts-list{margin:0;padding-left:20px}.facts-list li{margin:0 0 4px}.facts-list li:first-child{font-weight:600}.sr{position:absolute;left:-9999px}
.flist{border:1px solid var(--line);border-radius:6px;overflow:hidden;font-size:13px}
.frow{display:grid;grid-template-columns:32px 80px minmax(0,1fr) 170px 230px;gap:12px;padding:8px 12px;align-items:baseline}
.flist .fhead{background:var(--head);color:var(--muted);font-weight:600;border-bottom:1px solid var(--line)}
.fitem{border-bottom:1px solid var(--line2)}.fitem:last-child{border-bottom:0}
.fitem summary{cursor:pointer;list-style:none}.fitem summary::-webkit-details-marker{display:none}
.fitem[open] summary{background:var(--head)}.ftitle{font-weight:600}
.fbody{padding:4px 12px 14px 136px}
.fbody dl{display:grid;grid-template-columns:140px minmax(0,1fr);gap:4px 16px;margin:0}.fbody dt{color:var(--muted)}.fbody dd{margin:0}
.fbody ul{margin:0;padding-left:18px}
details.plain summary{cursor:pointer;color:var(--link)}
@media (max-width:760px){.frow{grid-template-columns:24px 64px minmax(0,1fr)}.frow>span:nth-child(n+4){display:none}.fbody{padding-left:12px}
.fbody dl{grid-template-columns:1fr}aside{max-width:none}.wrap{padding:0 16px}}
"""

ORG_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<noscript><p style="padding:24px">This report needs JavaScript to show its tables. The same results are in summary.md and the CSV files next to this file.</p></noscript>
<div id="app"></div>
<script type="application/json" id="data">__DATA__</script>
<script>__JS__</script>
</body>
</html>
"""

DEEP_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
__HEADER__
<main class="wrap narrow">
__BODY__
</main>
</body>
</html>
"""

ORG_JS = r"""
(function () {
"use strict";
var D = JSON.parse(document.getElementById("data").textContent);
var AREAS = D.areas, R = D.repos, T = D.types;
var FIND = D.findings.map(function (x) {
  var r = R[x[1]], t = T[x[0]];
  return {type: x[0], title: t[1], area: t[2], verdict: x[2] ? "Fix" : "Review", ri: x[1], repo: r.n, team: r.team, status: r.status, vis: r.vis, where: x[3], detail: x[4], href: x[5], links: x[6] || []};
});
var RANK = {Fix: 0, Review: 1, OK: 2, "Not checked": 3};
function emptyF() { return {verdict: {}, area: {}, status: {}, vis: {}, team: {}}; }
var S = {tab: "summary", q: "", group: "type", type: null, reason: null, f: emptyF(), page: 1, size: 25, open: {}, gpage: {}, ropen: {}, aopen: {}};

// ---------------------------------------------------------------- helpers
function el(tag, props) {
  var e = document.createElement(tag), k;
  for (k in (props || {})) {
    var v = props[k];
    if (v === null || v === undefined || v === false) continue;
    if (k === "text") e.textContent = v;
    else if (k === "cls") e.className = v;
    else if (k === "on") { for (var ev in v) e.addEventListener(ev, v[ev]); }
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (var i = 2; i < arguments.length; i++) add(e, arguments[i]);
  return e;
}
function add(e, c) {
  if (c === null || c === undefined || c === false) return;
  if (Array.isArray(c)) { c.forEach(function (x) { add(e, x); }); return; }
  e.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
function safe(u) { return (typeof u === "string" && (/^https:\/\/github\.com\//.test(u) || /^https:\/\/docs\.zizmor\.sh\//.test(u) || /^deep-dive\/[A-Za-z0-9._-]+\.html$/.test(u))) ? u : null; }
function out(label, url) { var u = safe(url); return u ? el("a", {href: u, target: "_blank", rel: "noopener"}, label) : el("span", null, label); }
function whereCell(x) { return x.where ? (safe(x.href) ? out(x.where, x.href) : el("span", null, x.where)) : el("span", {cls: "muted"}, "-"); }
function linkLine(links) {
  if (!links.length) return null;
  var line = el("div", {cls: "links"});
  links.forEach(function (l) {
    var m = /^([0-9a-f]{7}) (FINDING: .*)$/.exec(l[0]);
    line.appendChild(m ? el("span", null, out(m[1], l[1]), " ", el("span", {cls: "code"}, m[2])) : out(l[0], l[1]));
  });
  return line;
}
function fmt(n) { return Number(n).toLocaleString("en-GB"); }
function word(w) { return el("span", {cls: "v v-" + ({Fix: "fix", Review: "review", OK: "ok"}[w] || "na")}, w); }
function code(t) { return String(t || "").split("`").map(function (p, i) { return i % 2 ? el("code", null, p) : document.createTextNode(p); }); }
function isPath(w) { return /^[\w.\/-]+(:[\d,]+)?$/.test(w || ""); }
function plural(n, one, many) { return fmt(n) + " " + (n === 1 ? one : many); }
function link(btnText, fn) { return el("button", {cls: "linkbtn", type: "button", on: {click: fn}}, btnText); }
function repoLink(ri, label) { var u = safe(R[ri].report); return u ? el("a", {href: u}, label || R[ri].n) : el("span", null, label || R[ri].n); }

// ---------------------------------------------------------------- the view in the address
var KEYS = ["verdict", "area", "status", "vis", "team"];
function writeHash() {
  var p = ["tab=" + S.tab];
  KEYS.forEach(function (k) { var on = Object.keys(S.f[k]).filter(function (v) { return S.f[k][v]; }); if (on.length) p.push(k + "=" + on.map(encodeURIComponent).join(",")); });
  if (S.type !== null) p.push("finding=" + encodeURIComponent(T[S.type][0]));
  if (S.reason) p.push("reason=" + encodeURIComponent(S.reason));
  if (S.q) p.push("q=" + encodeURIComponent(S.q));
  if (S.tab === "findings" && S.group !== "type") p.push("group=" + S.group);
  try { history.replaceState(null, "", "#" + p.join("&")); } catch (e) { /* some browsers refuse on file:// */ }
}
function readHash() {
  var h = (location.hash || "").slice(1);
  if (!h) return;
  h.split("&").forEach(function (kv) {
    var i = kv.indexOf("="), k = kv.slice(0, i), v = decodeURIComponent(kv.slice(i + 1));
    if (k === "tab" && ["summary", "findings", "repos", "actions", "settings"].indexOf(v) >= 0) S.tab = v;
    else if (KEYS.indexOf(k) >= 0) kv.slice(i + 1).split(",").forEach(function (x) { S.f[k][decodeURIComponent(x)] = true; });
    else if (k === "finding") T.forEach(function (t, j) { if (t[0] === v) S.type = j; });
    else if (k === "reason") S.reason = v;
    else if (k === "q") S.q = v;
    else if (k === "group" && v === "repo") S.group = "repo";
  });
}

// ---------------------------------------------------------------- frame
var app = document.getElementById("app"), tabsNav, main;
function counts() { return {findings: FIND.length, repos: R.length, actions: D.actions.rows.length, settings: D.settings.length}; }
function header() {
  var c = counts();
  tabsNav = el("nav", {cls: "wrap tabs", "aria-label": "Report sections"});
  [["summary", "Summary", ""], ["findings", "Findings", fmt(c.findings)], ["repos", "Repositories", fmt(c.repos)],
   ["actions", "Actions", fmt(c.actions)], ["settings", "Settings", fmt(c.settings)]].forEach(function (t) {
    tabsNav.appendChild(el("button", {cls: "tab", type: "button", "data-tab": t[0], on: {click: function () { go({tab: t[0]}); }}}, t[1], t[2] ? el("span", {cls: "n"}, t[2]) : null));
  });
  return el("header", {cls: "top"},
    el("div", {cls: "wrap bar"}, el("div", {cls: "crumbs"}, "Repo Status ", el("span", {cls: "sep"}, "/"), " " + D.owner),
      el("div", {cls: "meta grow"}, "Data collected " + D.collected + " UTC · " + plural(R.length, "repository", "repositories")
        + (D.zizmor ? " · zizmor " + D.zizmor : "")),
      el("div", {cls: "meta small"}, "Contains private data. Share inside your organisation only.")), tabsNav);
}
function go(patch) {
  var tabChanged = patch.tab && patch.tab !== S.tab;
  for (var k in patch) S[k] = patch[k];
  if (tabChanged) {  // a new tab starts unfiltered, unless the link that opened it sets its own filter
    S.page = 1; S.q = patch.q || ""; S.open = patch.open || {}; S.gpage = {};
    if (!patch.f) S.f = emptyF();
    if (!("type" in patch)) S.type = null;
    if (!("reason" in patch)) S.reason = null;
  }
  render();
  if (tabChanged) window.scrollTo(0, 0);
}
function render() {
  Array.prototype.forEach.call(tabsNav.children, function (b) { if (b.getAttribute("data-tab") === S.tab) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
  clear(main);
  if (D.age_days >= 1) main.appendChild(el("p", {cls: "notice"}, "Built on " + D.generated + " from data that was then " + D.age_days + " day(s) old. Run " + D.cmd + " " + D.owner + " for current data."));
  if (S.tab === "summary") main.appendChild(summary());
  else if (S.tab === "findings" || S.tab === "repos") main.appendChild(listView());
  else if (S.tab === "actions") main.appendChild(actionsTab());
  else main.appendChild(settingsTab());
  writeHash();
}

// ---------------------------------------------------------------- summary
function table(heads, rows, numeric) {
  return el("table", {cls: "plain"}, el("thead", null, el("tr", null, heads.map(function (h, i) { return el("th", {cls: numeric.indexOf(i) >= 0 ? "num" : null}, h); }))),
    el("tbody", null, rows.map(function (r) { return el("tr", null, r.map(function (c, i) { return el("td", {cls: numeric.indexOf(i) >= 0 ? "num" : null}, c); })); })));
}
function summary() {
  var d = D.deep, st = D.status;
  var fixN = FIND.filter(function (x) { return x.verdict === "Fix"; }).length;
  var fixRepos = R.filter(function (r) { return r.fix; }).length, revRepos = R.filter(function (r) { return r.review; }).length;
  var doc = el("div", {cls: "doc"});
  if (D.iocs.length) doc.appendChild(el("div", {cls: "notice"}, el("h2", null, "Known attack indicators found: " + D.iocs.length),
    el("ul", null, D.iocs.map(function (x) { return el("li", null, el("strong", null, x[0]), ": " + x[1]); }))));
  doc.appendChild(el("section", null, el("h1", null, "Summary"), el("ul", {cls: "facts-list"},
    el("li", null, (d.count ? d.count + " of " + plural(R.length, "repository needs", "repositories need") + " a deep investigation: " + d.high + " high priority, " + d.medium + " medium."
      : "No repository needs a deep investigation (no high or medium warning).")),
    el("li", null, FIND.length ? plural(FIND.length, "finding", "findings") + ": " + fmt(fixN) + " to fix in " + plural(fixRepos, "repository", "repositories") + ", " + fmt(FIND.length - fixN) + " to review in " + fmt(revRepos) + "." : "No findings."),
    el("li", null, st.active + " repositories are active, " + st.dormant + " dormant, " + st.dead + " dead and " + st.archived + " archived"
      + (st.empty + st.unknown ? "; " + (st.empty + st.unknown) + " empty or unreadable" : "") + ". " + (D.quiet[0] ? plural(D.quiet[0], "dormant or dead repository still runs", "dormant or dead repositories still run") + " workflows; " + D.quiet[1] + " of them use secrets." : "No dormant or dead repository runs workflows.")),
    D.iocs.length || !D.campaigns ? null : el("li", null, "No known attack indicators were found (" + D.campaigns + " published campaigns checked)."),
    actionsLine())));
  if (D.reasons.length) doc.appendChild(el("section", null, el("h2", null, "Why repositories need a deep investigation"),
    table(["Reason", "Priority", "Repositories", "How to check"], D.reasons.map(function (r) {
      return [link(r[1], function () { go({tab: "repos", reason: r[0], f: emptyF(), page: 1}); }), r[2], fmt(r[3]), el("span", {cls: "soft"}, r[4])];
    }), [2])));
  doc.appendChild(el("section", null, el("h2", null, "Findings by area"),
    table(["Area", "Fix", "Review", "Repositories affected", "Covers"], AREAS.map(function (a, i) {
      var m = FIND.filter(function (x) { return x.area === a; });
      var fx = m.filter(function (x) { return x.verdict === "Fix"; }).length;
      var sel = {}; sel[a] = true;
      return [link(a, function () { var f = emptyF(); f.area = sel; go({tab: "findings", f: f, type: null, page: 1, open: {}}); }),
        el("span", {cls: fx ? "v-fix" : "muted"}, fmt(fx)), fmt(m.length - fx), fmt(new Set(m.map(function (x) { return x.ri; })).size), el("span", {cls: "muted"}, D.area_what[i])];
    }), [1, 2, 3])));
  var top = R.filter(function (r) { return r.fix || r.review; }).slice().sort(byRepo).slice(0, 10);
  if (top.length) doc.appendChild(el("section", null, el("h2", null, "Act on these first"),
    table(["Repository", "Fix", "Review", "Most serious finding", "Team"], top.map(function (r) {
      return [repoLink(R.indexOf(r)), el("span", {cls: r.fix ? "v-fix" : "muted"}, String(r.fix)), String(r.review), r.main, el("span", {cls: "muted"}, r.team)];
    }), [1, 2]), el("p", {cls: "small", style: "margin-top:8px"}, link("All repositories", function () { go({tab: "repos", f: emptyF(), reason: null}); }))));
  var byT = {};
  FIND.forEach(function (x) { var e = byT[x.type] = byT[x.type] || {t: x.type, fix: false, repos: new Set(), n: 0}; e.repos.add(x.ri); e.n++; if (x.verdict === "Fix") e.fix = true; });
  var common = Object.keys(byT).map(function (k) { return byT[k]; }).sort(function (a, b) { return (b.fix - a.fix) || (b.repos.size - a.repos.size) || (b.n - a.n); }).slice(0, 10);
  if (common.length) doc.appendChild(el("section", null, el("h2", null, "Most common findings"),
    table(["Finding", "Verdict", "Repositories", "Findings"], common.map(function (e) {
      return [link(T[e.t][1], function () { var o = {}; o["t" + e.t] = true; go({tab: "findings", type: e.t, group: "type", f: emptyF(), page: 1, open: o}); }),
        word(e.fix ? "Fix" : "Review"), fmt(e.repos.size), fmt(e.n)];
    }), [2, 3])));
  return doc;
}
function byRepo(a, b) { return RANK[a.verdict] - RANK[b.verdict] || b.fix - a.fix || b.review - a.review || a.n.localeCompare(b.n); }

// ---------------------------------------------------------------- findings and repositories (filters + list)
var NAMES = {verdict: "Verdict", area: "Area", status: "Repository status", vis: "Visibility", team: "Team (CODEOWNERS)"};
var aside, info, listBox, pagerBox, shareBox, searchInput;
function keysNow() { return S.tab === "findings" ? KEYS : ["verdict", "status", "vis", "team"]; }
function baseItems() {
  var q = S.q.toLowerCase().trim();
  if (S.tab === "findings") return FIND.filter(function (x) {
    return (S.type === null || x.type === S.type) && (!q || (x.repo + " " + x.title + " " + x.where + " " + x.detail + " " + x.team).toLowerCase().indexOf(q) >= 0);
  });
  return R.filter(function (r) { return (!S.reason || r.codes.indexOf(S.reason) >= 0) && (!q || (r.n + " " + r.team).toLowerCase().indexOf(q) >= 0); })
    .map(function (r) { return {r: r, verdict: r.verdict, status: r.status, vis: r.vis, team: r.team}; });
}
function passes(x, except) {
  return keysNow().every(function (k) {
    if (k === except) return true;
    var any = Object.keys(S.f[k]).some(function (v) { return S.f[k][v]; });
    return !any || S.f[k][x[k]];
  });
}
function listView() {
  aside = el("aside", {"aria-label": "Filters"});
  searchInput = el("input", {type: "search", id: "q", value: S.q, placeholder: S.tab === "findings" ? "Search findings, repositories, files, secrets" : "Search repositories or teams", autocomplete: "off"});
  searchInput.addEventListener("input", function () { S.q = searchInput.value; S.page = 1; S.open = {}; S.gpage = {}; refresh(); });
  var group = null;
  if (S.tab === "findings") {
    var sel = el("select", {id: "grp", on: {change: function () { S.group = sel.value; S.page = 1; S.open = {}; S.gpage = {}; refresh(); }}},
      el("option", {value: "type"}, "Finding"), el("option", {value: "repo"}, "Repository"));
    sel.value = S.group;
    group = [el("label", {"for": "grp", cls: "meta"}, "Group by"), sel];
  }
  shareBox = el("div", {cls: "info"});
  var toolbar = el("div", {cls: "toolbar"}, el("label", {"for": "q", cls: "sr"}, "Search"), searchInput, group, el("span", {cls: "spacer"}),
    el("button", {cls: "btn", type: "button", on: {click: exportCsv}}, "Export CSV"),
    el("button", {cls: "btn", type: "button", on: {click: copyLink}}, "Copy link to this view"));
  info = el("div", {cls: "info"});
  listBox = el("div");
  pagerBox = el("div");
  refresh();
  return el("div", {cls: "layout"}, aside, el("div", {cls: "content"}, toolbar, shareBox, info, listBox, pagerBox));
}
function refresh() {
  var base = baseItems(), keys = keysNow();
  clear(aside);
  aside.appendChild(el("div", {cls: "ahead"}, el("strong", null, "Filters"),
    link("Clear all", function () { S.f = emptyF(); S.q = ""; S.type = null; S.reason = null; S.page = 1; S.open = {}; searchInput.value = ""; refresh(); })));
  keys.forEach(function (k) {
    var c = {};
    base.forEach(function (x) { if (passes(x, k)) c[x[k]] = (c[x[k]] || 0) + 1; });
    var opts = Object.keys(c);
    if (k === "verdict") opts = ["Fix", "Review", "OK", "Not checked"].filter(function (v) { return c[v] || S.f.verdict[v]; });
    else if (k === "area") opts = AREAS.filter(function (a) { return c[a] || S.f.area[a]; });
    else { Object.keys(S.f[k]).forEach(function (v) { if (S.f[k][v] && opts.indexOf(v) < 0) opts.push(v); }); opts.sort(function (a, b) { return (c[b] || 0) - (c[a] || 0) || (a < b ? -1 : 1); }); }
    var shown = k === "team" ? opts.slice(0, 8) : opts;
    var fs = el("fieldset", null, el("legend", null, NAMES[k]));
    shown.forEach(function (o) {
      var box = el("input", {type: "checkbox"});
      box.checked = !!S.f[k][o];
      box.addEventListener("change", function () { S.f[k][o] = box.checked; S.page = 1; S.open = {}; S.gpage = {}; refresh(); });
      fs.appendChild(el("label", {cls: "opt"}, box, el("span", {cls: "l" + (k === "verdict" ? " v-" + ({Fix: "fix", Review: "review", OK: "ok"}[o] || "na") : "")}, o), el("span", {cls: "c"}, fmt(c[o] || 0))));
    });
    if (opts.length > shown.length) fs.appendChild(el("div", {cls: "muted"}, (opts.length - shown.length) + " more: search for a team"));
    if (!shown.length) fs.appendChild(el("div", {cls: "muted"}, "None"));
    aside.appendChild(fs);
  });
  var items = base.filter(function (x) { return passes(x, null); });
  clear(info); clear(listBox); clear(pagerBox); clear(shareBox);
  if (S.tab === "findings") findingsList(items); else reposList(items);
  if (S.type !== null) info.appendChild(el("span", null, "Finding: ", el("strong", null, T[S.type][1]), " ", link("remove", function () { S.type = null; S.page = 1; refresh(); })));
  if (S.reason) info.appendChild(el("span", null, "Reason: ", el("strong", null, S.reason), " ", link("remove", function () { S.reason = null; S.page = 1; refresh(); })));
  writeHash();
}
function pager(total, unit, onPage) {
  var last = Math.max(1, Math.ceil(total / S.size));
  if (S.page > last) S.page = last;
  var page = S.page, from = (page - 1) * S.size;
  var want = [1, last, page - 2, page - 1, page, page + 1, page + 2].filter(function (n, i, a) { return n >= 1 && n <= last && a.indexOf(n) === i; }).sort(function (a, b) { return a - b; });
  var size = el("select", {id: "ps", on: {change: function () { S.size = +size.value; S.page = 1; onPage(); }}}, [25, 50, 100].map(function (n) { return el("option", {value: n}, String(n)); }));
  size.value = String(S.size);
  var pages = el("div", {cls: "pages"}, el("label", {"for": "ps", cls: "meta", style: "margin-right:4px"}, "Per page"), size, el("span", {style: "width:12px"}),
    el("button", {cls: "pbtn", type: "button", disabled: page === 1, on: {click: function () { S.page = page - 1; onPage(); }}}, "Previous"));
  want.forEach(function (n, i) {
    if (i && n - want[i - 1] > 1) pages.appendChild(el("span", {cls: "muted", style: "padding:0 4px"}, "..."));
    pages.appendChild(el("button", {cls: "pbtn", type: "button", "aria-label": "Page " + n, "aria-current": n === page ? "page" : null, on: {click: function () { S.page = n; onPage(); }}}, String(n)));
  });
  pages.appendChild(el("button", {cls: "pbtn", type: "button", disabled: page === last, on: {click: function () { S.page = page + 1; onPage(); }}}, "Next"));
  add(pagerBox, el("nav", {cls: "pager", "aria-label": "Pages"}, el("span", {cls: "muted"}, total ? fmt(from + 1) + "–" + fmt(Math.min(from + S.size, total)) + " of " + fmt(total) + " " + unit : ""), pages));
  return from;
}
function scrollList() { var b = listBox.getBoundingClientRect(); if (b.top < 0) listBox.scrollIntoView(); }
function groupsOf(items) {
  var byType = S.group === "type", map = {};
  items.forEach(function (x) { var k = byType ? "t" + x.type : "r" + x.ri; (map[k] = map[k] || []).push(x); });
  return Object.keys(map).map(function (k) {
    var its = map[k].sort(function (a, b) { return RANK[a.verdict] - RANK[b.verdict] || (a.repo < b.repo ? -1 : a.repo > b.repo ? 1 : 0); });
    var fix = its.some(function (x) { return x.verdict === "Fix"; }), r = R[its[0].ri];
    return {key: k, items: its, fix: fix, title: byType ? its[0].title : r.n, ri: its[0].ri, mid: byType ? its[0].area : r.team + " · " + r.status,
      count: byType ? new Set(its.map(function (x) { return x.ri; })).size : new Set(its.map(function (x) { return x.type; })).size};
  }).sort(function (a, b) { return (b.fix - a.fix) || (b.count - a.count) || (b.items.length - a.items.length) || (a.title < b.title ? -1 : 1); });
}
function typeInfo(ti) {
  var t = T[ti], rows = [];
  if (t[3]) rows.push(el("dt", null, "What it means"), el("dd", null, code(t[3])));
  if (t[4]) rows.push(el("dt", null, "What to do"), el("dd", null, code(t[4])));
  if (safe(t[5])) rows.push(el("dt", null, "How to fix it"), el("dd", null, out("zizmor documentation: " + t[0].replace(/^zizmor:/, ""), t[5])));
  return rows.length ? el("dl", {cls: "about"}, rows) : null;
}
function findingsList(items) {
  var groups = groupsOf(items), byType = S.group === "type";
  info.insertBefore(el("span", null, el("strong", null, plural(items.length, "finding", "findings") + " in " + plural(groups.length, byType ? "finding type" : "repository", byType ? "finding types" : "repositories"))), info.firstChild);
  var from = pager(groups.length, groups.length === 1 ? "group" : "groups", function () { S.open = {}; refresh(); scrollList(); });
  var t = el("table", {style: "min-width:860px"}, el("thead", null, el("tr", null, el("th", null, byType ? "Finding" : "Repository"), el("th", {style: "width:90px"}, "Verdict"),
    el("th", {style: "width:190px"}, byType ? "Area" : "Team and status"), el("th", {cls: "num", style: "width:110px"}, byType ? "Repositories" : "Finding types"),
    el("th", {cls: "num", style: "width:90px"}, "Findings"), el("th", {style: "width:70px"}, el("span", {cls: "sr"}, "Open")))));
  groups.slice(from, from + S.size).forEach(function (g) {
    var open = !!S.open[g.key], body = el("tbody");
    var toggle = function () { S.open[g.key] = !open; refresh(); };
    body.appendChild(el("tr", {cls: open ? "is-open" : null},
      el("td", null, el("button", {cls: "titlebtn", type: "button", "aria-expanded": open ? "true" : "false", on: {click: toggle}}, g.title)),
      el("td", null, word(g.fix ? "Fix" : "Review")), el("td", {cls: "muted"}, g.mid), el("td", {cls: "num"}, fmt(g.count)), el("td", {cls: "num"}, fmt(g.items.length)),
      el("td", {cls: "num"}, link(open ? "Hide" : "Show", toggle))));
    if (open) {
      var per = 10, last = Math.ceil(g.items.length / per), ip = Math.min(S.gpage[g.key] || 1, last);
      var its = g.items.slice((ip - 1) * per, ip * per);
      var inner = el("table", null, el("thead", null, el("tr", null, el("th", {style: "width:200px"}, byType ? "Repository" : "Finding"), el("th", {style: "width:300px"}, "Where"), el("th", null, "Detail"), el("th", {style: "width:80px"}, "Verdict"))),
        el("tbody", null, its.map(function (x) {
          return el("tr", null, el("td", null, byType ? repoLink(x.ri) : x.title), el("td", {cls: "where"}, whereCell(x)),
            el("td", null, code(x.detail || "-"), linkLine(x.links)), el("td", null, word(x.verdict)));
        })));
      var about = byType ? typeInfo(g.items[0].type) : null;
      var bar = el("div", {cls: "innerbar"}, el("span", null, last > 1 ? "Showing " + fmt((ip - 1) * per + 1) + "–" + fmt(Math.min(ip * per, g.items.length)) + " of " + fmt(g.items.length) + " in this group" : plural(g.items.length, "finding", "findings") + " in this group"));
      if (last > 1) {
        bar.appendChild(el("button", {cls: "btn sm", type: "button", disabled: ip === 1, on: {click: function () { S.gpage[g.key] = ip - 1; refresh(); }}}, "Previous"));
        bar.appendChild(el("button", {cls: "btn sm", type: "button", disabled: ip === last, on: {click: function () { S.gpage[g.key] = ip + 1; refresh(); }}}, "Next"));
      }
      if (!byType && !safe(R[g.ri].report)) bar.appendChild(el("span", null, "Full report: run ", el("code", null, R[g.ri].cmd)));
      body.appendChild(el("tr", null, el("td", {cls: "inner", colspan: "6"}, about, inner, bar)));
    }
    t.appendChild(body);
  });
  listBox.appendChild(el("div", {cls: "box"}, t, groups.length ? null : el("p", {cls: "muted", style: "padding:16px 12px;margin:0"}, "Nothing matches these filters.")));
}
function reposList(items) {
  var rows = items.map(function (x) { return x.r; }).sort(byRepo);
  info.insertBefore(el("span", null, el("strong", null, fmt(rows.length) + " of " + plural(R.length, "repository", "repositories"))), info.firstChild);
  var from = pager(rows.length, "repositories", function () { refresh(); scrollList(); });
  var t = el("table", {style: "min-width:960px"}, el("thead", null, el("tr", null, ["Repository", "Verdict", "Fix", "Review", "Most serious finding", "Status", "Team", "Last push", ""].map(function (h, i) {
    return el("th", {cls: i === 2 || i === 3 ? "num" : null}, h || el("span", {cls: "sr"}, "Areas")); }))));
  rows.slice(from, from + S.size).forEach(function (r) {
    var ri = R.indexOf(r), open = !!S.ropen[r.n], body = el("tbody");
    var toggle = function () { S.ropen[r.n] = !open; refresh(); };
    body.appendChild(el("tr", {cls: open ? "is-open" : null},
      el("td", null, el("strong", null, repoLink(ri)), " ", el("span", {cls: "muted"}, r.vis)), el("td", {cls: "nowrap"}, word(r.verdict)),
      el("td", {cls: "num"}, el("span", {cls: r.fix ? "v-fix" : "muted"}, String(r.fix))), el("td", {cls: "num"}, String(r.review)),
      el("td", null, r.main), el("td", null, r.status), el("td", {cls: "muted"}, r.team), el("td", {cls: "muted nowrap"}, r.push || "-"),
      el("td", {cls: "num nowrap"}, r.areas.length ? link(open ? "Hide areas" : "Areas", toggle) : null)));
    if (open) body.appendChild(el("tr", null, el("td", {cls: "inner", colspan: "9", style: "padding:8px 12px 12px 28px"},
      el("div", {cls: "areas-grid"}, r.areas.map(function (a, i) { return el("div", null, word(a[0]), " " + AREAS[i] + (a[1] ? " (" + a[1] + ")" : "")); })),
      safe(r.report) ? null : el("p", {cls: "small muted", style: "margin:8px 0 0"}, "Full report with what to do and links to GitHub: run ", el("code", null, r.cmd), "."))));
    t.appendChild(body);
  });
  listBox.appendChild(el("div", {cls: "box"}, t, rows.length ? null : el("p", {cls: "muted", style: "padding:16px 12px;margin:0"}, "Nothing matches these filters.")));
}

// ---------------------------------------------------------------- share and export
function copyLink() {
  writeHash();
  var url = location.href;
  clear(shareBox);
  var show = function (msg) {
    clear(shareBox);
    var box = el("input", {cls: "linkout", readonly: true, value: url, "aria-label": "Link to this view"});
    add(shareBox, [el("span", null, msg), box]);
    box.focus(); box.select();
  };
  try {
    navigator.clipboard.writeText(url).then(function () { clear(shareBox); add(shareBox, el("span", null, "Link copied. It opens this file with the same tab and filters.")); },
      function () { show("Copy this link:"); });
  } catch (e) { show("Copy this link:"); }
}
function cell(v) {
  var s = String(v === null || v === undefined ? "" : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;  // a spreadsheet must not run it as a formula
  return '"' + s.replace(/"/g, '""') + '"';
}
function exportCsv() {
  var base = baseItems().filter(function (x) { return passes(x, null); }), lines;
  if (S.tab === "findings") lines = [["verdict", "finding", "area", "repository", "team", "status", "where", "detail", "link"]].concat(
    base.map(function (x) { return [x.verdict, x.title, x.area, x.repo, x.team, x.status, x.where, x.detail, safe(x.href) || ""]; }));
  else lines = [["repository", "verdict", "fix", "review", "most_serious_finding", "status", "visibility", "team", "last_push"]].concat(
    base.map(function (x) { var r = x.r; return [r.n, r.verdict, r.fix, r.review, r.main, r.status, r.vis, r.team, r.push]; }));
  var csv = "\ufeff" + lines.map(function (l) { return l.map(cell).join(","); }).join("\r\n") + "\r\n";
  var a = el("a", {href: URL.createObjectURL(new Blob([csv], {type: "text/csv;charset=utf-8"})), download: D.owner + "-" + S.tab + ".csv"});
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

// ---------------------------------------------------------------- actions and settings
function actionsLine() {
  var A = D.actions;
  if (!A.rows.length) return null;
  var fix = A.rows.filter(function (x) { return x[1] === "Fix"; }).length, repos = new Set();
  A.rows.forEach(function (x) { x[4].forEach(function (p) { repos.add(p[0]); }); });
  return el("li", null, plural(A.rows.length, "third-party action has", "third-party actions have") + " a problem (" + fix + " to fix, " + (A.rows.length - fix) + " to review), used in "
    + plural(repos.size, "repository", "repositories") + ". ", link("See where", function () { go({tab: "actions"}); }));
}
function actionsTab() {
  var A = D.actions;
  if (!A.checked) return el("p", {cls: "meta"}, "Upstream actions were not checked (the scan used --skip-action-check).");
  if (!A.rows.length) return el("p", {cls: "meta"}, A.distinct + " distinct actions are used; none has a known problem.");
  var box = el("div");
  function draw() {
    clear(box);
    var t = el("table", {style: "min-width:900px"}, el("thead", null, el("tr", null, el("th", null, "Action"), el("th", {style: "width:90px"}, "Verdict"),
      el("th", null, "Problem"), el("th", {cls: "num", style: "width:110px"}, "Repositories"), el("th", {cls: "num", style: "width:80px"}, "Places"), el("th", {style: "width:70px"}, el("span", {cls: "sr"}, "Open")))));
    A.rows.forEach(function (x, i) {
      var open = S.aopen[i] === undefined ? x[1] === "Fix" : S.aopen[i], body = el("tbody");
      var toggle = function () { S.aopen[i] = !open; draw(); };
      var repos = new Set(x[4].map(function (p) { return p[0]; }));
      body.appendChild(el("tr", {cls: open ? "is-open" : null},
        el("td", null, el("button", {cls: "titlebtn mono", type: "button", "aria-expanded": open ? "true" : "false", on: {click: toggle}}, x[0])),
        el("td", null, word(x[1])), el("td", null, x[2]), el("td", {cls: "num"}, fmt(repos.size)), el("td", {cls: "num"}, fmt(x[4].length)),
        el("td", {cls: "num"}, link(open ? "Hide" : "Show", toggle))));
      if (open) {
        var inner = el("table", null, el("thead", null, el("tr", null, el("th", null, "Repository"), el("th", null, "Used in"), el("th", null, "Version"),
          el("th", {style: "width:80px"}, "Pinned"), el("th", {style: "width:80px"}, "Locked"), el("th", {style: "width:150px"}, "Workflow last ran"))),
          el("tbody", null, x[4].map(function (p) {
            return el("tr", null, el("td", null, p[0] >= 0 ? repoLink(p[0]) : "-"),
              el("td", null, el("span", {cls: "mono"}, p[1]), p[7] ? el("div", {cls: "small muted"}, p[7]) : null),
              el("td", {cls: "mono"}, p[2]), el("td", {cls: p[3] === "no" ? "v-review" : null}, p[3]), el("td", null, p[4]),
              el("td", {cls: "nowrap"}, p[6] ? p[6] + (p[5] && p[5] !== "active" ? " (" + p[5].replace(/_/g, " ") + ")" : "") : (p[1].indexOf(".github/workflows/") === 0 ? "never" : "-")));
          })));
        body.appendChild(el("tr", null, el("td", {cls: "inner", colspan: "6"}, inner,
          el("div", {cls: "innerbar"}, plural(x[4].length, "place", "places") + " in " + plural(repos.size, "repository", "repositories") + ", most recently run first. Default branches, as of the scan."))));
      }
      t.appendChild(body);
    });
    box.appendChild(el("div", {cls: "box"}, t));
  }
  draw();
  return el("div", null, el("p", {cls: "meta", style: "margin-bottom:12px"}, A.distinct + " distinct actions are used; " + A.ok
    + " have no known problem. These have one, with every repository and workflow that uses them. Fix items are open."), box);
}
function settingsTab() {
  if (!D.settings.length) return el("p", {cls: "meta"}, "No setting needs changing.");
  return el("div", {cls: "box"}, el("table", {style: "min-width:760px"},
    el("thead", null, el("tr", null, el("th", null, "Setting"), el("th", {cls: "num"}, "Repositories"), el("th", null, "Where to change it"))),
    el("tbody", null, D.settings.map(function (x) { return el("tr", null, el("td", null, x[0]), el("td", {cls: "num"}, fmt(x[1])), el("td", {cls: "muted"}, code(x[2]))); }))));
}

readHash();
app.appendChild(header());
main = el("main", {cls: "wrap"});
app.appendChild(main);
render();
})();
"""
