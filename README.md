# Repo Status

Repo Status audits every GitHub repository in an organisation (or personal account) in one run, and tells you **which repositories need a closer look, and why**.

Organisations collect repositories faster than anyone reviews them. Repositories nobody works on keep their secrets and keep running workflows, forgotten branches keep old copies of those workflows, and the third-party actions every workflow pulls in can change without any change to your code. These are exactly the places recent supply-chain attacks have used: action tags moved to malicious code, and stolen accounts planting workflows that steal secrets. GitHub shows all of this one repository and one settings page at a time.

Repo Status looks at all of it at once, without changing anything. For every repository it answers:

- Is anyone still working on it?
- Has its history been rewritten?
- Can its workflows be attacked, or have they been tampered with?
- Who can reach its secrets?
- Is it set up the way GitHub recommends?

You get one report for the whole organisation, a web page that opens in any browser with the repositories that need attention at the top; CSVs to sort and filter; and for any repository a one-page report saying what to fix and where on GitHub to fix it.

It is built for security and platform engineers, and anyone responsible for an organisation's GitHub, who want a complete, repeatable picture instead of spot checks.

## What it checks

| Area | Check | Type |
|---|---|---|
| **Activity** | Which repositories are active, dormant or dead (by GitHub's record of the last push by a person) | Hygiene |
|  | What dead repositories still have: workflows that run, secrets, published images | Hygiene |
|  | Packages or images published after a repository went quiet | Security |
| **History** | Rewritten history: force pushes to the default branch | Security |
|  | Backdated, future-dated or impossibly dated commits | Security |
|  | Unusual signing or time zone on the latest commit | Security |
|  | The same commit pushed to many branches within seconds | Security |
| **Workflow flaws** | Command injection, risky triggers, unsafe checkouts and other [zizmor](https://docs.zizmor.sh) findings, in workflows that still run | Security |
|  | Actions pinned to impostor commits, or versions with known vulnerabilities | Security |
|  | AI agent actions that outsiders can steer through issues or comments | Security |
|  | Self-hosted runners on public repositories | Security |
|  | A VS Code task that runs as soon as the folder is opened | Security |
| **Workflow changes** | Workflows changed after a repository went quiet, or by someone new | Security |
|  | Workflow steps that send secrets to an outside address | Security |
|  | Workflows still running, with secrets, in dormant or dead repositories | Security |
| **Workflow runs** | Runs of workflows that are not on the default branch, or on branches since deleted | Security |
|  | Runs started by people who no longer have access, or re-run by someone else | Security |
| **Other branches** | Old workflow copies on other branches that can still run, and when they last ran | Security |
|  | Which secrets each copy could read | Security |
| **Secrets** | Secrets that every branch can read (repository or organisation secrets) | Security |
|  | Environments without required reviewers, or that admins can bypass | Security |
|  | Static cloud keys (AWS, Azure, Google) where a short-lived login would do | Security |
|  | Secrets passed through `base64` or `set -x`, which log masking misses | Security |
|  | Secrets visible in run logs (`deep --logs`) | Security |
| **Upstream actions** | Actions whose owner is gone, renamed or replaced | Security |
|  | Version tags that moved after you pinned or locked them | Security |
|  | Published vulnerabilities in the versions you use | Security |
|  | Unmaintained actions, versions less than a week old, actions that do not pin what they use | Hygiene |
| **Known attacks** | Indicators of published supply-chain campaigns (Shai-Hulud, GhostAction, tj-actions, reviewdog, trivy-action) in workflows, branches, runs, runners and pinned commits | Security |
| **Repository settings** | Branch rules: force push, required pull requests, stale approvals, self-approval | Hygiene |
|  | CODEOWNERS present and enforced, workflows covered | Hygiene |
|  | Last person to push who no longer has access | Hygiene |
|  | Workflow token can write, workflows can approve pull requests | Hygiene |
|  | Allowed actions, required pinning, fork pull request approval and secrets | Hygiene |
|  | `pull_request_target` workflows in public repositories that GitHub's default rule blocks from 2 Dec 2026 | Hygiene |
| **Workflow hygiene** | Actions not pinned to a commit; missing or incomplete `actions.lock` | Hygiene |
|  | `curl \| sh`, unpinned `pip` or `go install` | Hygiene |
|  | Invalid workflow files that GitHub cannot run | Hygiene |
| **Incident response** | When an action is reported compromised: which repositories use it, and whether it ran during the attack window | On demand |

**It is safe to run.** It only reads from GitHub, never changes anything, and never runs code from a repository. Of a repository's files it reads only the GitHub Actions configuration (workflows, action definitions, `actions.lock`, Dependabot settings), never the source code.

---

## 1. Setup

Works on macOS, Linux and Windows. **On Windows, type `scan.cmd` (PowerShell: `.\scan.cmd`) wherever this guide says `./scan.sh`.**

**Install the two tools it needs:** `gh` (GitHub's command-line tool) and `uv` (runs Repo Status and installs the right Python by itself).

| Computer | Command |
|---|---|
| macOS | `brew install gh uv` |
| Windows | `winget install --id GitHub.cli -e` and `winget install --id astral-sh.uv -e`, then reopen the window |
| Linux | [install gh](https://github.com/cli/cli#installation), then `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

**Log in:** `gh auth login` (choose GitHub.com, HTTPS, log in with a web browser). For work, a read-only token is better; see [Safety and privacy](#5-safety-and-privacy).

**Check it works**, from the Repo Status folder: `./scan.sh check`

```
Platform: Darwin 25.6.0
GitHub CLI: gh version 2.88.1 (2026-03-12)
Python: 3.14.3
Logged in to GitHub as: your-username
GitHub API allowance: 5,000 of 5,000 per hour left (personal limit; see Rate Limits in the wiki for 15,000)
zizmor: 1.32.0
Self-test: passed (158 tests)
```

Something wrong? See [Common Problems](https://github.com/Himan10/git-repo-status/wiki/Common-Problems).

---

## 2. Scan

Use the name from the GitHub address (`github.com/your-org` becomes `your-org`). The same command works for a personal account; add `--skip-forks` to leave out forks.

Command: `./scan.sh your-org`

Results go to `out/your-org/`:

| File | What it is |
|---|---|
| **`report.html`** | **Open this first**, in any browser (works offline). A one-page Summary for leaders; every finding, grouped and filterable, for security teams; every repository for developers |
| `summary.md` | The same results as text. It opens with "Deep investigation needed: N of M repositories" and the reasons, then attack indicators, workflow security, workflows on other branches, unusual runs, action health, and settings worth fixing (with where to fix them) |
| `repo-status.csv` | One row per repository (open in Excel) |
| `branch-workflows.csv`, `runs-worth-a-look.csv`, `actions-inventory.csv` | Every workflow copy on other branches; every unusual run; every action used, and where |

Large organisations need more than an hour of GitHub's API allowance: the scan pauses and continues by itself, and `--resume` picks up a scan that stopped. See [Rate Limits](https://github.com/Himan10/git-repo-status/wiki/Rate-Limits). Options such as `--skip-branches` or other thresholds: [Scan Options](https://github.com/Himan10/git-repo-status/wiki/Scan-Options).

---

## 3. Investigate a repository

Command: `./scan.sh your-org deep REPO`

Writes **`out/your-org/deep-dive/REPO.html`** (and the same as text in `REPO.md`): one screen with a verdict ("1 to fix, 3 to review"), eight areas marked Fix, Review or OK, and what to do, with a direct link to the right GitHub settings page. `report.html` then links to it. Everything behind it is in `REPO-evidence.md`. Add `--logs` to also check recent run logs for leaked secrets (logs are never saved).

More: [Deep Dive Investigation](https://github.com/Himan10/git-repo-status/wiki/Deep-Dive-Investigation).

---

## 4. After an upstream action is compromised

When an action you use is hijacked (as `aquasecurity/trivy-action` was in March 2026), find who used it and whether it ran during the bad window:

Command: `./scan.sh your-org uses aquasecurity/trivy-action --since 2026-03-19 --until 2026-03-20`

Known attack indicators are kept in `iocs.yml` and checked on every scan; see [Workflow Security](https://github.com/Himan10/git-repo-status/wiki/Workflow-Security#known-attack-indicators) to add new ones.

---

## 5. Safety and privacy

- **It only reads.** For work, use a **read-only fine-grained token** so GitHub itself refuses any change: GitHub > Settings > Developer settings > Fine-grained tokens. Resource owner: your organisation; repository access: all repositories; repository permissions, all read-only: **Metadata, Contents, Actions, Administration, Secrets, Environments**. Authorise it for SSO if your organisation uses it, then set it: `export GH_TOKEN=<token>` (Windows: `set GH_TOKEN=<token>`).
- **Secrets are only ever read by name**, never by value.
- **Packages and images** can only be listed with a classic token (`read:packages`), which also allows changes; without one, those columns stay empty.
- **zizmor's online checks** send GitHub's own API only the names and versions of the actions you use, never your workflow files. `--no-online-audits` turns them off.
- **Run logs** are read only with `deep ... --logs`, scanned in memory and never saved; findings are masked.
- **The `out` folder** holds repository names, usernames and email addresses, secret names and copies of workflow files. It is excluded from git; keep it private.

Every API call and the permission it needs: [GitHub API Calls](https://github.com/Himan10/git-repo-status/wiki/GitHub-API-Calls).

---

## 6. Learn more

| Wiki page | What it covers |
|---|---|
| [Understanding Results](https://github.com/Himan10/git-repo-status/wiki/Understanding-Results) | Every file, section of `summary.md` and CSV column |
| [Status Values and Flags](https://github.com/Himan10/git-repo-status/wiki/Status-Values-and-Flags) | Every status, warning and hygiene note, and what to do about each |
| [Workflow Security](https://github.com/Himan10/git-repo-status/wiki/Workflow-Security) | zizmor, workflows on other branches, secrets and environments, action health, attack indicators |
| [Deep Dive Investigation](https://github.com/Himan10/git-repo-status/wiki/Deep-Dive-Investigation) | The deep-dive report and evidence file |
| [Scan Options](https://github.com/Himan10/git-repo-status/wiki/Scan-Options) · [Rate Limits](https://github.com/Himan10/git-repo-status/wiki/Rate-Limits) | Options, thresholds, and how big organisations are handled |
| [Common Problems](https://github.com/Himan10/git-repo-status/wiki/Common-Problems) | Error messages and what to do |
| [Architecture](https://github.com/Himan10/git-repo-status/wiki/Architecture) · [GitHub API Calls](https://github.com/Himan10/git-repo-status/wiki/GitHub-API-Calls) | How it works, its limits, and every call it makes |

---

## For developers

Without the launcher, from the project folder (`uv` installs what `pyproject.toml` and `uv.lock` specify):

```
uv run python -m repostatus your-org [options]       # what scan.sh / scan.cmd run
uv run python -m repostatus your-org report          # rebuild the reports from the last scan, no API calls
uv run python -m unittest discover -s tests          # the tests
```
