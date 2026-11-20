"""Commit and file links in the reports, and the FINDING: keyword on commits that are themselves a finding.

  uv run python -m unittest discover -s tests
"""
import unittest

from repostatus import deep_dive
from repostatus.reports import github_links

FULL = "org/app"
SHA_FINDING, SHA_PLAIN = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "f" * 40


class Links(unittest.TestCase):
    def test_commit_link_marks_findings(self):
        findings = github_links.finding_commits([
            ("WORKFLOW_ONLY_PUSH_AFTER_IDLE", "high", f"dev pushed (0000000 -> {SHA_FINDING[:7]}); changed ci.yml"),
            ("LATE_ARRIVAL_FAST_FORWARD", "info", f"{SHA_PLAIN[:7]} is informational, not a finding")])
        self.assertEqual(github_links.commit_link(FULL, SHA_FINDING, findings),
                         f"[a1b2c3d](https://github.com/org/app/commit/{SHA_FINDING}) FINDING: WORKFLOW_ONLY_PUSH_AFTER_IDLE")
        self.assertEqual(github_links.commit_link(FULL, SHA_PLAIN, findings),
                         f"[fffffff](https://github.com/org/app/commit/{SHA_PLAIN})")

    def test_branch_names_are_url_encoded(self):
        self.assertEqual(github_links.file_url(FULL, "feat/a b", ".github/workflows/ci.yml"),
                         "https://github.com/org/app/blob/feat/a%20b/.github/workflows/ci.yml")
        self.assertEqual(github_links.compare_url(FULL, "main", "fix/x"), "https://github.com/org/app/compare/main...fix/x")


class EvidenceHasNoDiffs(unittest.TestCase):
    def test_workflow_changes_are_links(self):
        f = {"full_name": FULL, "repo": "app", "idle_wakeups": [], "actions": {"items": []}}
        wf = {"since_days": 365, "error": None, "runs": {}, "commits": [
            {"oid": SHA_FINDING, "headline": "ci: add", "author": "x", "date": "2026-09-14T00:00:00Z",
             "verified": False, "pushed_at": "2026-09-14T00:00:01Z", "pushed_by": "x",
             "files": [{"name": ".github/workflows/ci.yml", "status": "added", "+": 9, "-": 0}]},
            {"oid": SHA_PLAIN, "headline": "docs", "author": "y", "date": "2026-09-01T00:00:00Z", "verified": True,
             "pushed_at": None, "pushed_by": None, "files": []}]}
        text = "\n".join(deep_dive.workflow_markdown(wf, f, {SHA_FINDING[:7]: ["WORKFLOW_BY_NEW_ACTOR"]}))
        self.assertIn("FINDING: WORKFLOW_BY_NEW_ACTOR", text)
        self.assertIn(f"https://github.com/org/app/commit/{SHA_PLAIN}", text)
        self.assertEqual(text.count("FINDING:"), 2)  # the marked row and the explanation line
        self.assertNotIn("diff", text.replace("differ", ""))

    def test_report_items_link_their_commits(self):
        lines = deep_dive._item_lines({"code": "SIGNING_BREAK", "where": [f"{SHA_FINDING[:7]} UNSIGNED; author signed 9/9"],
                                       "why": "", "fix": ""}, FULL)
        self.assertIn("[a1b2c3d](https://github.com/org/app/commit/a1b2c3d) FINDING: SIGNING_BREAK", lines[0])


class ActionCommits(unittest.TestCase):
    """A moved tag names commits of the action's repository; linking them to the repository that uses the
    action leads to GitHub's 'nothing found' page."""

    def test_commented_pin(self):
        t = ("aws-actions/configure-aws-credentials@3e5f45b in .github/workflows/deploy.yml is commented v4.2.0, "
             "but that tag now points to 9a8b7c6: the comment is wrong")
        out = github_links.linkify(t, "acme/app", {"3e5f45b": ["TAG_MOVED"]})
        self.assertIn("[3e5f45b](https://github.com/aws-actions/configure-aws-credentials/commit/3e5f45b) FINDING: TAG_MOVED", out)
        self.assertIn("(https://github.com/aws-actions/configure-aws-credentials/commit/9a8b7c6)", out)
        self.assertIn("(https://github.com/aws-actions/configure-aws-credentials/tree/v4.2.0)", out)
        self.assertIn("(https://github.com/aws-actions/configure-aws-credentials/compare/3e5f45b...9a8b7c6)", out)
        self.assertNotIn("acme/app", out)

    def test_lockfile_entry_with_sub_path(self):
        t = "some-org/deploy-action/sub@v2.1.0: locked at 1a2b3c4, tag v2.1.0 now points to 5d6e7f8"
        self.assertEqual(github_links.commits_repo(t, "acme/app"), "some-org/deploy-action")

    def test_ordinary_findings_stay_in_the_repository(self):
        t = 'a1b2c3d "fix" by someone, dated 2026-11-01'
        self.assertEqual(github_links.commits_repo(t, "acme/app"), "acme/app")
        self.assertEqual(github_links.linkify(t, "acme/app"), '[a1b2c3d](https://github.com/acme/app/commit/a1b2c3d) "fix" by someone, dated 2026-11-01')
        self.assertEqual(github_links.commits_repo(".github/workflows/ci.yml ran 3 time(s) on branch x", "acme/app"), "acme/app")


if __name__ == "__main__":
    unittest.main()
