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


if __name__ == "__main__":
    unittest.main()
