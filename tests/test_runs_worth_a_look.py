"""Runs worth a look: only workflow runs with something unusual about them, each with its reasons.

  uv run python -m unittest discover -s tests
"""
import csv
import os
import tempfile
import unittest
from datetime import datetime, timezone

from repostatus.checks.repository_checks import DEFAULTS
from repostatus.checks.workflow_checks import runs_worth_a_look, workflow_flags
from repostatus.reports import org_summary

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def run(**kw):
    r = {"id": 1, "path": ".github/workflows/ci.yml", "head_branch": "main", "event": "push", "actor": "dev",
         "actor_type": "User", "started_by": "dev", "run_attempt": 1, "status": "completed",
         "created_at": "2026-11-10T00:00:00Z", "conclusion": "success", "url": "https://github.com/o/r/actions/runs/1",
         "head_sha": "a" * 40, "from_fork": False}
    r.update(kw)
    return r


def repo(runs, visibility="private", names=("main", "feat"), collaborators=("dev",)):
    return {"repo": "r", "full_name": "o/r", "visibility": visibility, "default_branch": "main", "archived": False,
            "history": [], "collaborators": list(collaborators), "actions": {"items": []},
            "branch_workflows": {"names": list(names), "default_files": ["ci.yml"], "truncated": False,
                                 "branches": [], "blobs": {}},
            "recent_runs": {"items": runs}}


def reasons(f, status="active", flags=()):
    return [[c for c, _ in x["reasons"]] for x in runs_worth_a_look(f, status, NOW, DEFAULTS, flags)]


class Reasons(unittest.TestCase):
    def test_ordinary_run_is_not_listed(self):
        self.assertEqual(reasons(repo([run()])), [])

    def test_planted_workflow_on_deleted_branch(self):
        f = repo([run(path=".github/workflows/x.yml", head_branch="gone")])
        self.assertEqual(reasons(f), [["NOT_ON_DEFAULT", "BRANCH_DELETED"]])

    def test_deleted_branch_alone_is_normal_and_tags_are_not_branches(self):
        f = repo([run(head_branch="pr-branch-merged-and-deleted"), run(path=".github/workflows/rel.yml", head_branch="v1.0.0")])
        f["recent_runs"]["tags"] = ["v1.0.0"]
        self.assertEqual(reasons(f), [["NOT_ON_DEFAULT"]])  # the tag run: its file is not on main, but v1.0.0 exists

    def test_organisation_account_is_not_an_outsider(self):
        f = repo([run(actor="acme", actor_type="Organization", started_by="acme")])
        self.assertEqual(reasons(f), [])

    def test_push_by_someone_without_access(self):
        f = repo([run(actor="stranger", started_by="stranger")])
        self.assertEqual(reasons(f), [["NOT_A_COLLABORATOR"]])
        flags = workflow_flags(f, "active", NOW, DEFAULTS)
        self.assertEqual([(c, s) for c, s, _ in flags], [("RUN_BY_NON_COLLABORATOR", "medium")])

    def test_outsiders_may_comment_on_public_repos(self):
        f = repo([run(actor="stranger", event="issue_comment")], visibility="public")
        self.assertEqual(reasons(f), [])

    def test_bots_and_fork_pull_requests_are_not_outsiders(self):
        f = repo([run(actor="dependabot[bot]", actor_type="Bot"),
                  run(actor="stranger", event="pull_request", head_branch="patch-1", from_fork=True)])
        self.assertEqual(reasons(f), [])

    def test_unknown_collaborators_never_accuse(self):
        f = repo([run(actor="stranger")], collaborators=())  # list could not be read
        self.assertEqual(reasons(f), [])

    def test_rerun_by_someone_else(self):
        f = repo([run(run_attempt=2, actor="other", started_by="dev")], collaborators=("dev", "other"))
        self.assertEqual(reasons(f), [["RERUN_BY_OTHER"]])

    def test_ran_a_flagged_change(self):
        f = repo([run(head_sha="b" * 40)])
        self.assertEqual(reasons(f, flags=[("WORKFLOW_BY_NEW_ACTOR", "medium", f"{'b' * 7} \"ci\" by x")]),
                         [["RAN_FLAGGED_CHANGE"]])

    def test_inactive_repo_and_age_window(self):
        f = repo([run(), run(created_at="2026-01-01T00:00:00Z", actor="stranger")])
        self.assertEqual(reasons(f, status="dead"), [["INACTIVE_REPO"]])  # the January run is outside 90 days


class Report(unittest.TestCase):
    def test_section_and_csv(self):
        f = repo([run(path=".github/workflows/x.yml", head_branch="gone"), run(run_attempt=2, actor="other"),
                  run()], collaborators=("dev", "other"))
        rows = [{"f": f, "status": "active", "flags": []}]
        text = "\n".join(org_summary._runs_section(rows, DEFAULTS, NOW))
        self.assertIn("## Runs worth a look (2)", text)
        self.assertLess(text.index("has since been deleted"), text.index("re-run by other"))  # strongest first
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "runs.csv")
            org_summary.write_runs_csv(p, rows, NOW, DEFAULTS)
            with open(p, newline="", encoding="utf-8-sig") as fh:
                got = list(csv.DictReader(fh))
        self.assertEqual([g["reason_codes"] for g in got], ["NOT_ON_DEFAULT, BRANCH_DELETED", "RERUN_BY_OTHER"])


if __name__ == "__main__":
    unittest.main()
