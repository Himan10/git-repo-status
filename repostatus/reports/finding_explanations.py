"""Plain-language explanations used by the deep-dive report: what a finding means, who can exploit it,
how to fix it, and where on GitHub to do that. Kept in one place so every report says it the same way.

Each entry: title (what was found), why (what an attacker gets), fix (what to change), settings (which
page on GitHub, as a menu path and a link pattern; None when the fix is in a file).
"""

# Pages on GitHub. {full} is owner/repo.
SETTINGS = {
    "secrets": ("Settings > Secrets and variables > Actions", "https://github.com/{full}/settings/secrets/actions"),
    "environments": ("Settings > Environments", "https://github.com/{full}/settings/environments"),
    "rules": ("Settings > Rules > Rulesets (or Settings > Branches)", "https://github.com/{full}/settings/rules"),
    "actions": ("Settings > Actions > General", "https://github.com/{full}/settings/actions"),
    "access": ("Settings > Collaborators and teams", "https://github.com/{full}/settings/access"),
    "workflows": ("Actions tab > the workflow > ... > Disable workflow", "https://github.com/{full}/actions"),
    "branches": ("Code > Branches", "https://github.com/{full}/branches"),
}

ZIZMOR = {
    "template-injection": {
        "title": "Command injection",
        "why": "Text from outside the workflow is pasted into a shell script before it runs, so whoever controls "
               "that text can run their own commands inside the job, with its secrets and token.",
        "fix": "Pass the value through an environment variable and quote it: `env: { VALUE: \"${{ ... }}\" }`, "
               "then use `\"$VALUE\"` in the script.",
    },
    "dangerous-checkout": {
        "title": "Privileged workflow checks out code from a pull request",
        "why": "The workflow runs with secrets, then checks out and may run code from someone else's pull request.",
        "fix": "Do not check out the pull request's code in a privileged workflow; split it into an unprivileged "
               "`pull_request` workflow.",
    },
    "impostor-commit": {
        "title": "Action pinned to a commit that is not in the action's repository",
        "why": "The pinned commit exists only in a fork. Anyone can create such a commit, so the 'pinned' action "
               "may be someone else's code.",
        "fix": "Pin the action to a commit from its own repository (a release tag's commit).",
    },
    "known-vulnerable-actions": {
        "title": "Action version with a published vulnerability",
        "why": "The GitHub Advisory Database lists a security flaw in this version of the action.",
        "fix": "Update the action to a fixed version.",
    },
    "github-env": {
        "title": "Untrusted text written to GITHUB_ENV or GITHUB_PATH",
        "why": "Writing attacker-controlled text there can set environment variables or programs for every later "
               "step, which lets the attacker run code in the job.",
        "fix": "Do not write untrusted values to GITHUB_ENV / GITHUB_PATH; use step outputs instead.",
    },
    "cache-poisoning": {
        "title": "Cache shared between untrusted and release workflows",
        "why": "A cache written by a less trusted workflow is restored in a release or privileged workflow, so "
               "planted files end up in what you build or publish.",
        "fix": "Do not restore caches in release workflows, or keep their cache keys separate.",
    },
    "obfuscation": {
        "title": "Obfuscated action reference or expression",
        "why": "The workflow hides what it really uses or does, which is how planted workflows avoid review.",
        "fix": "Rewrite the reference or expression plainly and check who added it.",
    },
    "bot-conditions": {
        "title": "Bot check that can be spoofed",
        "why": "`github.actor == 'dependabot[bot]'` is true for anyone who re-runs a bot's job, so the step meant "
               "for the bot runs for them.",
        "fix": "Check `github.event.pull_request.user.login` instead of `github.actor`.",
    },
    "unredacted-secrets": {
        "title": "Secret parsed as structured data",
        "why": "Fields taken out of a JSON secret are not hidden in logs, so they can appear in plain text.",
        "fix": "Store each value as its own secret.",
    },
    "overprovisioned-secrets": {
        "title": "Every secret handed to the job at once",
        "why": "`toJSON(secrets)` gives the job (and anything it runs) all secrets of the repository, not just "
               "the ones it needs.",
        "fix": "Reference only the secrets the job needs, by name.",
    },
    "hardcoded-container-credentials": {
        "title": "Registry password written in the workflow",
        "why": "Anyone who can read the repository can read the password.",
        "fix": "Move it to a secret and rotate it.",
    },
    "insecure-commands": {
        "title": "Deprecated insecure workflow commands enabled",
        "why": "Any output of the job can then set environment variables and paths, which lets text in logs run code.",
        "fix": "Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS`.",
    },
    "unsound-condition": {
        "title": "Condition that is always true",
        "why": "The `if:` is written so that it never stops the step, so a guard you rely on does not work.",
        "fix": "Write the condition without the trailing newline / block scalar.",
    },
    "ref-confusion": {
        "title": "Action reference that can mean two things",
        "why": "A branch and a tag share the name, so the code that runs depends on which one GitHub picks.",
        "fix": "Pin the action to a commit.",
    },
    "typosquat-uses": {
        "title": "Action name that looks like a well-known one",
        "why": "It may be a lookalike published to catch typos.",
        "fix": "Check the action's owner and replace it with the real one if it is a lookalike.",
    },
}

FLAGS = {
    "FORCE_PUSH_DEFAULT": {"title": "History of the default branch was overwritten", "settings": "rules",
                           "why": "A force push can remove or replace commits, which hides changes from review.",
                           "fix": "Check what changed (evidence file); block force pushes with a branch rule."},
    "DATE_MISMATCH": {"title": "A commit reached GitHub long after the date it claims", "settings": None,
                      "why": "Backdating makes a new change look old and reviewed.",
                      "fix": "Ask the author; compare the commit with the push in the evidence file."},
    "FUTURE_DATED_COMMIT": {"title": "A commit claims a date after it was pushed", "settings": None,
                            "why": "The date was set by hand.", "fix": "Ask the author."},
    "SIGNING_BREAK": {"title": "Unsigned commit from someone who always signs", "settings": None,
                      "why": "It may not come from that person.", "fix": "Confirm with the author."},
    "BAD_SIGNATURE": {"title": "Commit signature does not verify", "settings": None,
                      "why": "The commit may not be what it claims.", "fix": "Review the commit and the signing key."},
    "COMMITTED_BEFORE_AUTHORED": {"title": "Impossible commit dates", "settings": None,
                                  "why": "Normal git never produces this; the dates were edited.", "fix": "Ask the author."},
    "NEW_TIMEZONE": {"title": "Latest commit from a time zone its author never used", "settings": None,
                     "why": "Often travel; sometimes a stolen account.", "fix": "Confirm with the author."},
    "MULTI_BRANCH_PUSH": {"title": "Same commit pushed to several branches within seconds", "settings": None,
                          "why": "Looks scripted.", "fix": "Check which tool did it."},
    "PUBLISHED_AFTER_INACTIVITY": {"title": "Package published after the repository went quiet", "settings": None,
                                   "why": "Nobody works on the code, but something published from it.",
                                   "fix": "Check who published it and from which workflow run."},
    "VSCODE_AUTORUN": {"title": "Opening the repository in VS Code runs a command", "settings": None,
                       "why": "`.vscode/tasks.json` starts a task on folder open: whoever controls it runs code on "
                              "the developer's machine.", "fix": "Read the task before opening the folder; remove it."},
    "WORKFLOW_ONLY_PUSH_AFTER_IDLE": {"title": "Quiet repository woke up with a workflow-only change", "settings": "workflows",
                                      "why": "The pattern of stolen-account campaigns that plant secret-stealing workflows.",
                                      "fix": "Review the change and the runs after it; if unexpected, disable the workflow and rotate its secrets."},
    "WORKFLOW_CHANGED_AFTER_IDLE": {"title": "First push after a quiet period changed a workflow", "settings": None,
                                    "why": "Worth a look: planted workflows often arrive this way.",
                                    "fix": "Review the workflow change."},
    "WORKFLOW_BY_NEW_ACTOR": {"title": "Workflow changed by someone with no other recent commits", "settings": None,
                              "why": "Changes to workflows decide what runs with the secrets.",
                              "fix": "Confirm the change with that person."},
    "WORKFLOW_EXFIL_PATTERN": {"title": "Workflow step sends secrets to an outside address", "settings": "workflows",
                               "why": "That is how secret-stealing workflows work.",
                               "fix": "Read the step now; if unexpected, disable the workflow and rotate its secrets."},
    "ZOMBIE_WORKFLOW_WITH_SECRETS": {"title": "Inactive repository still runs a workflow with secrets", "settings": "workflows",
                                     "why": "Nobody watches it, but it still uses live credentials.",
                                     "fix": "Disable the workflow, or delete the secrets if nobody needs them."},
    "AI_AGENT_UNTRUSTED_TRIGGER": {"title": "AI agent runs on text from outsiders", "settings": None,
                                   "why": "Instructions hidden in an issue or comment can steer the agent and its token.",
                                   "fix": "Run it only for trusted users, with a read-only token."},
    "BRANCH_WORKFLOW_EXFIL": {"title": "Workflow on another branch sends secrets out", "settings": "branches",
                              "why": "It runs when that branch is pushed, with the repository's secrets.",
                              "fix": "Delete the branch and rotate the secrets it could read."},
    "DELETED_BRANCH_WORKFLOW_RAN": {"title": "Workflow ran from a branch that was then deleted", "settings": None,
                                    "why": "A common way to run something once and hide it.",
                                    "fix": "Open the runs and read their logs while GitHub still keeps them."},
    "OUTDATED_WORKFLOW_ON_BRANCH": {"title": "Old, flawed workflow copy on another branch can still run", "settings": "branches",
                                    "why": "The fix on the default branch does not protect the old copy, which still reads the secrets.",
                                    "fix": "Delete or update the branch; keep secrets in an environment limited to the default branch."},
    "RUN_BY_NON_COLLABORATOR": {"title": "Workflow started by someone with no access now", "settings": "access",
                                "why": "Push and manual runs need write access. Either the person lost access after "
                                       "starting it, or their token or an app acting for them is still in use.",
                                "fix": "Open the runs (evidence file); check who this is and revoke any token or app "
                                       "still acting for them."},
    "SELF_HOSTED_ON_PUBLIC_REPO": {"title": "Self-hosted runner on a public repository", "settings": "actions",
                                   "why": "Anyone can open a pull request on a public repository, and its workflow "
                                          "can run on your own machine, with whatever that machine can reach.",
                                   "fix": "Use GitHub-hosted runners for public repositories, or limit the runner group "
                                          "to private repositories."},
    "IOC_MATCH": {"title": "Matches a known attack", "settings": None,
                  "why": "Something in this repository matches an indicator published for a known GitHub Actions "
                         "supply-chain campaign (iocs.yml lists each campaign and its sources).",
                  "fix": "Treat the repository as compromised until proven otherwise: read the matching file or run, "
                         "disable affected workflows, and rotate every secret they could read."},
    "SECRET_IN_RUN_LOG": {"title": "Secret visible in a run log", "settings": "secrets",
                          "why": "GitHub hides registered secrets in logs, but not tokens it does not know or values "
                                 "encoded first. Anyone who can read the log can read this one.",
                          "fix": "Rotate the credential now, then delete the run's logs (run page > ... > Delete all "
                                 "logs) and stop the step from printing it."},
    "ACTION_OWNER_GONE": {"title": "Owner of a used action no longer exists", "settings": None,
                          "why": "Anyone can register the name and publish code that your workflow then runs.",
                          "fix": "Replace the action, or copy it into the organisation."},
    "ACTION_OWNER_RENAMED": {"title": "Owner of a used action was renamed", "settings": None,
                             "why": "The old name can be registered by someone else.", "fix": "Update `uses:` to the new name."},
    "ACTION_REPO_REPLACED": {"title": "Locked action's repository was re-created", "settings": None,
                             "why": "The name now belongs to a different repository, possibly someone else's.",
                             "fix": "Do not relock; find out who owns the new repository."},
    "ACTION_REPO_GONE": {"title": "Used action no longer exists", "settings": None,
                         "why": "The workflow fails, and the name may be claimed later.", "fix": "Replace the action."},
    "TAG_MOVED": {"title": "Version tag of a used action moved", "settings": None,
                  "why": "Version tags should never move; a moved tag is what a hijacked action looks like.",
                  "fix": "Compare the two commits (link in the evidence file) before running the workflow again."},
}


def settings_link(key, full):
    """('Settings > ...', 'https://github.com/owner/repo/settings/...') or None."""
    if not key or key not in SETTINGS:
        return None
    path, url = SETTINGS[key]
    return path, url.format(full=full)


UNTRUSTED = {"pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment",
             "pull_request_review", "pull_request_review_comment"}


def who_can_trigger(triggers, visibility):
    """Who can start a workflow with these triggers, in plain words."""
    t = set(triggers or [])
    out = []
    if t & UNTRUSTED:
        out.append("anyone who can open an issue, comment or pull request"
                   + (" (on a public repository: anyone with a GitHub account)" if visibility == "public"
                      else " (on this private repository: anyone with read access)"))
    if t & {"workflow_dispatch", "push", "pull_request"}:
        out.append("anyone with write access, or a stolen token")
    if "workflow_run" in t:
        out.append("whoever can start the workflow it follows")
    if "schedule" in t and not out:
        out.append("nobody directly: it runs on a timer, so only the data it reads can be influenced")
    return "; ".join(out) or "depends on its triggers (" + ", ".join(sorted(t)) + ")"


# Parts of an expression that are generated by GitHub and cannot carry shell code
SAFE_SUFFIXES = ("sha", "_id", ".id", "number", "run_attempt")


def harmless_expression(expr):
    return expr.strip().lower().endswith(SAFE_SUFFIXES)
