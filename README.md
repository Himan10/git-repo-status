# Repo Status

Repo Status looks at every GitHub repository in an organisation or personal account and tells you:

- **which repositories are still in use and which are dead**
- **what is still attached to the dead ones**: automated jobs (GitHub Actions), stored secrets, published container images, branch rules, code owners
- **whether anyone has quietly rewritten a repository's history**, a technique attackers use to hide malicious code (see [How to investigate a GitHub repo's real history](https://opensourcemalware.com/blog/how-to-investigate-a-github-repos-real-history))
- **whether the GitHub Actions workflows can be attacked or have been tampered with**: [zizmor](https://docs.zizmor.sh) checks what each workflow file says (injection, risky triggers, unpinned actions, ...); Repo Status adds what happened around it: workflows changed after a repo went quiet, workflows that send secrets to outside addresses, dead repos still running workflows with secrets, and upstream actions that disappeared or whose version tags moved
- **which repositories need a closer look, and why**, at the top of the report

**It is safe to run.** It only reads information from GitHub. It never changes anything and never runs anything from a repository. Of a repository's files it reads only the configuration files that GitHub Actions uses (workflows, action definitions, `actions.lock`, Dependabot settings); never the source code.

---

## 1. One-time setup

Repo Status runs on macOS, Linux and Windows. Choose your platform:

git-repo-status have two separate starting points for different-2 platforms:
- `./scan.sh` (linux/macos)
- `scan.cmd` (windows)

Commands in this README and the wiki are written for macOS / Linux as `./scan.sh`. **On Windows, type `scan.cmd` (or `.\scan.cmd` in PowerShell) in its place**; everything after it stays the same. For example, `./scan.sh git-org --skip-forks` becomes `scan.cmd git-org --skip-forks`.

Type each command into the window and press Enter.

**Step 1. Install the two tools Repo Status needs**

- `gh` is GitHub's official command-line tool. Repo Status uses it to talk to GitHub, and it keeps your login safe.
- `uv` runs Repo Status. It downloads the right version of Python by itself; you do not need to install Python.

macOS: `brew install gh uv` (needs [Homebrew](https://brew.sh))

Linux: install `gh` from [cli.github.com](https://github.com/cli/cli#installation), then `curl -LsSf https://astral.sh/uv/install.sh | sh`

Windows (two commands, then close and reopen the window so it finds the new tools):

```
winget install --id GitHub.cli -e
winget install --id astral-sh.uv -e
```

**Step 2. Log in to GitHub**

Command: `gh auth login`

Answer the questions like this: **GitHub.com**, then **HTTPS**, then **Login with a web browser**. Copy the code it shows, press Enter, paste the code in the browser page that opens, and approve.

**Step 3. Go to the Repo Status folder**

Command: `cd path/to/repo-status`

Tip: type `cd ` (with a space), drag the `repo-status` folder from Finder or File Explorer into the window, and press Enter.

**Step 4. Check everything works**

macOS / Linux: `./scan.sh check`

Windows: `scan.cmd check` (PowerShell: `.\scan.cmd check`)

You should see:

```
Platform: Windows 11
GitHub CLI: gh version 2.88.1 (2026-03-12)
Python: 3.12.12
Logged in to GitHub as: your-username
zizmor: 1.32.0
Self-test: passed (59 tests)
```

If something is missing, the message tells you what to install. See [Common problems](#5-common-problems).

---

## 2. Scan an organisation

Type `./scan.sh` followed by the organisation name as it appears in its GitHub address (`github.com/git-org` becomes `git-org`).

Command: `./scan.sh git-org`

What you will see:

```
git-org: organisation. 8 repos found (0 forks); scanning 8.
Organisation audit log: unavailable (404 Not Found)
Estimated API calls: about 120. Available this hour: 5000 of 5000.
  [1/8] docs-site: ok
  [2/8] test-sandbox: ok
  ...
  [8/8] web-portal: ok
Done: 109 API calls. Facts saved to .../out/git-org/facts.json

Results:
  out/git-org/summary.md        (read this first)
  out/git-org/repo-status.csv   (open in Excel)
  out/git-org/actions-inventory.csv   (every action used, and where)
```

The scan also prints `zizmor: v1.32.0, offline (no token, no network)` near the start. zizmor is installed by `scan.sh` / `scan.cmd` (pinned to that version) and runs on the workflow files Repo Status already read; it makes no API calls of its own.

- `summary.md` opens with **"Deep investigation needed: N of M repositories"**: how many repositories need a closer look, a table of the reasons (what each one means and how to check it), and one line per repository with its priority (high or medium). Each repository is counted once, however many reasons it has. In `repo-status.csv` the same information is in the `deep_dive`, `deep_dive_priority` and `deep_dive_reason_codes` columns, ready to filter in Excel.
- After the deep-investigation list, `summary.md` has **Workflow security (zizmor)** (each zizmor rule: how many findings, in how many repositories) and **Actions used** (how many `uses:` are unpinned, how many repositories have an `actions.lock`, upstream actions that disappeared).
- A zizmor finding only puts a repository on the deep-investigation list when it is serious (for example template injection or an impostor commit) **and** the workflow still runs or holds secrets. Common findings such as unpinned actions are counted in the zizmor section but do not.
- You see every repository in the organisation **that your account can see**. As a member you also see private repositories you have access to.
- "Organisation audit log: unavailable" is normal for organisations not on GitHub Enterprise. It does not affect the results.

## 3. Scan a personal account

Same command, with the username (`github.com/git-user` becomes `git-user`):

Command: `./scan.sh git-user`

Output: `git-user: your own account (public and private repos you own). 40 repos found (14 forks); scanning 40.`

How a personal account differs from an organisation:

| | Organisation | Your own account | Someone else's account |
|---|---|---|---|
| Repositories included | All you can access | Public and private repositories you own | Public repositories only |
| Repositories in organisations you belong to | Yes | No; scan each organisation separately | No |
| Forks (copies of other people's projects) | Usually few | Often many | Often many |

**Personal accounts often hold many forks.** Forks are copies of other people's projects and are usually not what you want to review. Leave them out with:

Command: `./scan.sh git-user --skip-forks`

Output: `git-user: your own account (public and private repos you own). 40 repos found (14 forks); scanning 26.`

### Investigate a repository

Command: `./scan.sh git-org deep REPO`

Writes `out/git-org/deep-dive/REPO.md` with: every force push (what the history looked like before and after), every change to `.github/` in the last year (with the workflow diff, who pushed it according to GitHub, and the runs that followed), every zizmor finding including the online checks (impostor commits, actions with known vulnerabilities) and findings hidden by `# zizmor: ignore` comments, and any upstream action whose version tag moved, with a link to compare the two commits.

### After an upstream action is compromised

When a popular action is hijacked (as happened to `aquasecurity/trivy-action` in March 2026), find out who used it and whether it ran during the bad window:

Command: `./scan.sh git-org uses aquasecurity/trivy-action --since 2026-03-19 --until 2026-03-20`

It lists every repository and workflow that uses the action (directly, or through another action recorded in `actions.lock`) and every run in that window, with links. Saved to `out/git-org/uses/`. Without `--since` it makes no API calls.

## 4. More in the wiki

| Page | What it covers |
|---|---|
| [Rate Limits](https://github.com/Himan10/git-repo-status/wiki/Rate-Limits) | How many repositories fit in GitHub's hourly allowance, and what happens when it runs low |
| [Scan Options](https://github.com/Himan10/git-repo-status/wiki/Scan-Options) | Leaving out forks or archived repositories, scanning chosen repositories, changing the dead/dormant thresholds |
| [Understanding Results](https://github.com/Himan10/git-repo-status/wiki/Understanding-Results) | The `out` folder, how to read `summary.md`, every column in `repo-status.csv` |
| [Status Values and Flags](https://github.com/Himan10/git-repo-status/wiki/Status-Values-and-Flags) | What active, dormant and dead mean; every warning flag and hygiene note, and what to do about each |
| [Deep Dive Investigation](https://github.com/Himan10/git-repo-status/wiki/Deep-Dive-Investigation) | Investigating a flagged repository with `./scan.sh NAME deep REPO`, and how to read the report |
| [Architecture](https://github.com/Himan10/git-repo-status/wiki/Architecture) | How the tool is built and how it talks to GitHub |

---

## 5. Common problems

| Message | What to do |
|---|---|
| `Missing: GitHub CLI (gh)` or `Missing: uv` | Install it (section 1, step 1). The message shows the command for your platform |
| `Not logged in to GitHub` | Run `gh auth login` (section 1, step 2) |
| `permission denied: ./scan.sh` (macOS / Linux) | Run `chmod +x scan.sh` once, then try again |
| `'uv' is not recognized as an internal or external command` (Windows) | Install uv (section 1, step 1), then close and reopen the window |
| `'scan.cmd' is not recognized` or `The term 'scan.cmd' is not recognized` (Windows) | You are not in the Repo Status folder (section 1, step 3); in PowerShell, type `.\scan.cmd` |
| `'per_page' is not recognized as an internal or external command` (Windows) | You have an older copy of Repo Status. Get the latest version; this was fixed |
| `gh was found as a batch file` (Windows) | Install the regular gh program with `winget install --id GitHub.cli -e` |
| `GitHub account or organisation '...' not found` | Check the spelling against the GitHub address |
| `Not enough API calls left this hour` | Wait until the time shown, or use `--skip-forks` / `--repo` |
| `No scan found for ...` | Run the scan (`./scan.sh NAME`) before the deep dive (`./scan.sh NAME deep REPO`) |
| `'...' is not in the last scan` | Use the exact name from the `repo` column of `repo-status.csv` |
| `errors: ... 403` next to a repository | Your account lacks permission for part of that repository (often branch rules, which need admin rights). The rest of the row is still valid |
| `Organisation audit log: unavailable` | Normal outside GitHub Enterprise; nothing to do |
| Deep dive says "0 force pushes" but the CSV says "force-push allowed" | Not a contradiction: one is what happened, the other is what the settings allow (see [Status Values and Flags](https://github.com/Himan10/git-repo-status/wiki/Status-Values-and-Flags)) |
| `Branch rules not available on this plan` in summary.md | Private repositories on GitHub Free cannot have branch rules; force-push cannot be blocked there |

## 6. Safety and privacy

- Repo Status only reads. Your normal GitHub login may allow changes, so for scans at work use a **read-only token**, which makes GitHub itself refuse any change:
  1. GitHub > Settings > Developer settings > Personal access tokens > **Fine-grained tokens** > Generate new token.
  2. Resource owner: the organisation you will scan (one token per organisation). Repository access: **All repositories**.
  3. Repository permissions, all **Read-only**: **Metadata**, **Contents**, **Actions**, **Administration**. No organisation permissions are needed.
  4. If the organisation uses single sign-on, authorise the token for it (Configure SSO next to the token).
  5. Before scanning, set the token. macOS / Linux: `export GH_TOKEN=<token>`. Windows Command Prompt: `set GH_TOKEN=<token>`. PowerShell: `$env:GH_TOKEN="<token>"`.
- What a fine-grained token cannot do, because GitHub does not allow it:
  - **Images and packages** (`packages` columns): GitHub's packages API accepts only classic tokens with `read:packages`. With a fine-grained token these columns stay empty and `summary.md` shows a package listing error.
  - **Organisation audit log**: needs a classic token with `read:audit_log`, an organisation owner, and GitHub Enterprise Cloud. Only used to report whether it is available.
- For image and package results, use a **classic token** instead (Personal access tokens > Tokens (classic)) with `repo`, `read:org`, `read:packages`, and `read:audit_log` if you are an organisation owner on Enterprise Cloud. Classic `repo` also allows changes, so GitHub will not refuse writes; Repo Status still only reads.
- With either token, the access list (`last pusher has no access now`) is only shown for repositories your account can **write** to. That is GitHub's rule, not the token's.
- zizmor: during the scan it runs **offline**. Repo Status removes the token from zizmor's environment and passes `--offline`. During a deep dive it runs online so it can ask GitHub about the actions a workflow uses; the token is passed only in zizmor's own environment and its responses are cached in `out/<owner>/zizmor-cache`.
- The results contain repository names, secret **names** (never values), people's usernames and email addresses, and copies of each repository's workflow files (`out/<owner>/workflows/`). Keep the `out` folder private; it is excluded from git.

---

## For developers

The same steps without the wrapper script:

```
uv run --python 3.12 --with pyyaml --with zizmor==1.32.0 scan.py git-org [--skip-forks ...]   # what scan.sh / scan.cmd run
uv run --python 3.12 --with pyyaml --with zizmor==1.32.0 run.py all --owner git-org [--no-zizmor] [--skip-action-check]
uv run --python 3.12 --with pyyaml --with zizmor==1.32.0 run.py collect --owner git-org     # API calls only
uv run --python 3.12 --with pyyaml run.py report --owner git-org --dead-days 180   # no API calls
uv run --python 3.12 --with pyyaml run.py uses --owner git-org --action actions/checkout [--since 2026-03-19]
uv run --python 3.12 --with pyyaml --with zizmor==1.32.0 deep_dive.py --owner git-user --repo cli-tool
uv run --python 3.12 --with pyyaml --with zizmor==1.32.0 python -m unittest discover -s tests
```

Without `uv`: `python3.12 -m venv .venv && .venv/bin/pip install pyyaml` (Windows: `py -3.12 -m venv .venv` and `.venv\Scripts\pip install pyyaml`), then use the venv's Python instead of `uv run --python 3.12 --with pyyaml`.

`scan.sh` (macOS / Linux) and `scan.cmd` (Windows) only check that `uv` is installed and then run `scan.py`, which holds the checks and commands for every platform. API calls never put `?` or `&` on the command line, because Windows `cmd.exe` treats `&` as a command separator; `tests/test_ghapi.py` guards this.

Code layout: `collect.py` (API calls, saves facts), `workflows.py` (parses workflow files and `actions.lock`; pure), `zizmor.py` (runs zizmor and reads its JSON), `flags.py` and `workflow_flags.py` (judgement; pure), `report.py` (summary and CSVs). zizmor's version is pinned in `repostatus/zizmor.py`, `scan.sh` and `scan.cmd`; a test fails if they disagree. Change all three together, and pick a release at least two weeks old.

Text encoding (enforced by `tests/test_report.py`): every `open()` of a text file and every text-mode `subprocess.run` names its encoding (`utf-8`; the CSV uses `utf-8-sig` so Excel on Windows reads it). Windows otherwise falls back to a legacy code page and crashes on non-ASCII names. `.gitattributes` keeps `scan.cmd` at CRLF and `.sh` / `.py` files at LF line endings.

How it works, every GitHub API call, and the detection rules are in the [wiki](https://github.com/Himan10/git-repo-status/wiki).

Known limits:

- CODEOWNERS path matching is approximate; GitHub's own validation is used for errors.
- Registries in workflows are found by text matching. Images outside GitHub's registry are reported, not verified.
- Timezone and signing checks need at least 5 earlier changes by the same person.
- A deep dive needs the old history to still be on GitHub; once GitHub deletes it, only a copy taken earlier can show it.
- No automatic retry if the hourly limit runs out mid-scan.
