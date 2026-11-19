"""Settings checks from GitHub's hardening guidance: pull request review rules, allowed actions, required
pinning, fork pull request settings, environments without reviewers, static cloud keys, self-hosted runners
on public repositories, and pull_request_target against GitHub's default block (2 December 2026).

  uv run python -m unittest discover -s tests
"""
import unittest
from datetime import datetime, timezone

from repostatus.checks import repository_checks
from repostatus.checks.workflow_checks import settings_hygiene, workflow_flags
from repostatus.collect import workflow_parser

BEFORE, AFTER = datetime(2026, 11, 20, tzinfo=timezone.utc), datetime(2026, 12, 3, tzinfo=timezone.utc)


def wf(text, path=".github/workflows/ci.yml"):
    return dict(workflow_parser.parse_workflow(text), path=path, state="active", id=1)


def repo(visibility="private", items=(), **actions):
    return {"repo": "r", "visibility": visibility, "archived": False, "history": [],
            "actions": dict({"items": list(items)}, **actions), "secrets": {}}


def notes(f, now=BEFORE):
    return settings_hygiene(f, now)


class PullRequestRules(unittest.TestCase):
    def protection(self, **rules):
        f = {"protection": {"classic": None, "rulesets": dict({"types": ["pull_request"], "pr_required": True}, **rules)},
             "codeowners": {"path": None}, "activity": {}, "collaborators": []}
        prot = repository_checks.effective_protection(f)
        return repository_checks.hygiene(f, "active", prot, BEFORE, repository_checks.DEFAULTS)

    def test_both_off(self):
        got = self.protection(dismiss_stale=False, last_push_approval=False)
        self.assertIn("approvals stay valid after new commits are pushed (dismiss stale approvals is off)", got)
        self.assertTrue(any(n.startswith("whoever pushed last can approve") for n in got))

    def test_both_on(self):
        got = self.protection(dismiss_stale=True, last_push_approval=True)
        self.assertFalse(any(n.startswith(("approvals stay", "whoever pushed")) for n in got))


class ActionsSettings(unittest.TestCase):
    def test_allowed_actions_and_required_pinning(self):
        f = repo(items=[wf("on: push\njobs:\n  b:\n    steps: [{uses: actions/checkout@v4}]\n")],
                 allowed_actions="all", sha_pinning_required=True)
        got = notes(f)
        self.assertIn("any action from any author may be used (allowed-actions policy is 'all')", got)
        self.assertIn("pinning to a commit is required, so workflows with unpinned actions fail", got)

    def test_fork_pull_requests_public(self):
        self.assertTrue(any("first-time contributors need approval" in n
                            for n in notes(repo("public", fork_prs={"approval_policy": "first_time_contributors"}))))
        self.assertEqual(notes(repo("public", fork_prs={"approval_policy": "all_external_contributors"})), [])

    def test_fork_pull_requests_private(self):
        got = notes(repo(fork_prs={"run_workflows_from_fork_pull_requests": True, "send_secrets_and_variables": True,
                                   "send_write_tokens_to_workflows": True, "require_approval_for_fork_pr_workflows": False}))
        self.assertEqual(got, ["fork pull request workflows receive the repository's secrets",
                               "fork pull request workflows get a token that can write",
                               "fork pull request workflows run without approval"])
        self.assertEqual(notes(repo(fork_prs={"run_workflows_from_fork_pull_requests": False,
                                              "send_secrets_and_variables": True})), [])


class SecretsSettings(unittest.TestCase):
    def test_environment_without_reviewers_and_static_keys(self):
        f = repo()
        f["secrets"] = {"repo_secrets": ["AWS_ACCESS_KEY_ID", "NPM_TOKEN"], "org_secrets": [], "environments": {
            "production": {"secrets": ["ROLE"], "rules": ["branch_policy"]},
            "staging": {"secrets": ["X"], "rules": ["required_reviewers"]}}}
        got = notes(f)
        self.assertIn("environments hold secrets without required reviewers (below GitHub Enterprise, only public "
                      "repositories can have required reviewers): production", got)
        self.assertIn("static cloud keys stored as secrets (an OIDC login stores none): AWS_ACCESS_KEY_ID", got)


PRT = """on: pull_request_target
jobs:
  label:
    environment: production
    steps: [{run: echo hi}]
"""


class PullRequestTarget(unittest.TestCase):
    def test_public_repository_default_block(self):
        f = repo("public", items=[wf(PRT, ".github/workflows/label.yml")], policies={"items": []})
        self.assertTrue(any(n.startswith("pull_request_target will be blocked from 2026-12-02") for n in notes(f)))
        self.assertTrue(any(n.startswith("pull_request_target is blocked") for n in notes(f, AFTER)))
        self.assertIn("environments do not protect pull_request_target workflows, which run as the default branch: "
                      "label.yml uses production", notes(f))

    def test_policy_that_allows_it(self):
        f = repo("public", items=[wf(PRT)], policies={"items": [
            {"name": "allow labels", "enforcement": "active", "restricts_events": True,
             "allowed_events": ["pull_request", "pull_request_target"]}]})
        self.assertFalse(any("will be blocked" in n for n in notes(f)))

    def test_private_repositories_are_not_affected(self):
        self.assertFalse(any("blocked" in n for n in notes(repo(items=[wf(PRT)]))))


class SelfHosted(unittest.TestCase):
    def test_public_repository(self):
        w = wf("on: push\njobs:\n  b:\n    runs-on: [self-hosted, linux]\n    steps: [{run: make}]\n")
        flags = workflow_flags(repo("public", items=[w]), "active", BEFORE, repository_checks.DEFAULTS)
        self.assertEqual([(c, s) for c, s, _ in flags], [("SELF_HOSTED_ON_PUBLIC_REPO", "high")])
        self.assertEqual(workflow_flags(repo("private", items=[w]), "active", BEFORE, repository_checks.DEFAULTS), [])


if __name__ == "__main__":
    unittest.main()
