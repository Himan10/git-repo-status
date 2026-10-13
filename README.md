# Repo Status

Repo Status looks at every GitHub repository in an organisation or personal account and tells you:

- **which repositories are still in use and which are dead**
- **what is still attached to the dead ones**: automated jobs (GitHub Actions), stored secrets, published container images, branch rules, code owners
- **whether anyone has quietly rewritten a repository's history**, a technique attackers use to hide malicious code (see [How to investigate a GitHub repo's real history](https://opensourcemalware.com/blog/how-to-investigate-a-github-repos-real-history))

**It is safe to run.** It only reads information from GitHub. It never changes anything, never downloads a repository's code and never runs it.

---

## 1. One-time setup

You need a Mac with the Terminal app (Applications > Utilities > Terminal). Type each command below into Terminal and press Enter.

**Step 1. Install the two tools Repo Status needs:**

Command: `brew install gh uv`

- `gh` is GitHub's official command-line tool. Repo Status uses it to talk to GitHub and it keeps your login safe. Once done, login to github `gh auth login`
- `uv` runs Repo Status. It downloads the right version of Python by itself; you do not need to install Python.

**Step 2. Check everything works:**

Command: `./scan.sh check`

You should see:

```
GitHub CLI: gh version 2.88.1 (2026-03-12)
uv: uv 0.10.7 (08ab1a344 2026-02-27)
Logged in to GitHub as: your-username
Self-test: passed
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
```

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
| `Missing: GitHub CLI (gh)` or `Missing: uv` | Run `brew install gh uv` |
| `Not logged in to GitHub` | Run `gh auth login` (section 1) |
| `permission denied: ./scan.sh` | Run `chmod +x scan.sh` once, then try again |
| `GitHub account or organisation '...' not found` | Check the spelling against the GitHub address |
| `Not enough API calls left this hour` | Wait until the time shown, or use `--skip-forks` / `--repo` |
| `No scan found for ...` | Run `./scan.sh NAME` before `./scan.sh NAME deep REPO` |
| `'...' is not in the last scan` | Use the exact name from the `repo` column of `repo-status.csv` |
| `errors: ... 403` next to a repository | Your account lacks permission for part of that repository (often branch rules, which need admin rights). The rest of the row is still valid |
| `Organisation audit log: unavailable` | Normal outside GitHub Enterprise; nothing to do |
| Deep dive says "0 force pushes" but the CSV says "force-push allowed" | Not a contradiction: one is what happened, the other is what the settings allow (see [Status Values and Flags](https://github.com/Himan10/git-repo-status/wiki/Status-Values-and-Flags)) |
| `Branch rules not available on this plan` in summary.md | Private repositories on GitHub Free cannot have branch rules; force-push cannot be blocked there |

## 6. Safety and privacy

- Repo Status only reads. Your normal GitHub login may allow changes, so for scans at work use a **read-only token**, which makes GitHub itself refuse any change:
  1. GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token.
  2. Resource owner: the organisation. Repository access: All repositories.
  3. Permissions, all **Read-only**: Metadata, Contents, Actions, Administration, Packages; Organisation: Members.
  4. Before scanning, run `export GH_TOKEN=` followed by the token.
- The results contain repository names, secret **names** (never values), people's usernames and email addresses. Keep the `out` folder private; it is excluded from git.

---

## For developers

The same steps without the wrapper script:

```
uv run --python 3.12 --with pyyaml run.py all --owner git-org [--skip-forks ...]
uv run --python 3.12 --with pyyaml run.py collect --owner git-org     # API calls only
uv run --python 3.12 --with pyyaml run.py report --owner git-org --dead-days 180   # no API calls
uv run --python 3.12 --with pyyaml deep_dive.py --owner git-user --repo cli-tool
uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
```

Without `uv`: `python3.12 -m venv .venv && .venv/bin/pip install pyyaml`, then use `.venv/bin/python` instead of `uv run --python 3.12 --with pyyaml`.

How it works, every GitHub API call, and the detection rules are in the [wiki](https://github.com/Himan10/git-repo-status/wiki).

Known limits:

- CODEOWNERS path matching is approximate; GitHub's own validation is used for errors.
- Registries in workflows are found by text matching. Images outside GitHub's registry are reported, not verified.
- Timezone and signing checks need at least 5 earlier changes by the same person.
- A deep dive needs the old history to still be on GitHub; once GitHub deletes it, only a copy taken earlier can show it.
- No automatic retry if the hourly limit runs out mid-scan.
