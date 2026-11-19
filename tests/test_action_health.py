"""Action health: published vulnerabilities in the versions used, maintenance, waiting period, immutable
releases, whether an action pins what it uses; and mapping zizmor's online findings back to repositories.

  uv run python -m unittest discover -s tests
"""
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from repostatus.checks import action_health
from repostatus.collect import zizmor_runner

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
TJ = [{"range": "<= 45.0.7", "fixed": "46.0.1"}]  # GHSA-mrrh-fwg8-r2c3, as GitHub publishes it
OK_REPO = {"status": "ok", "archived": False, "owner_type": "Organization", "pushed_at": "2026-11-01T00:00:00Z"}


class VersionRanges(unittest.TestCase):
    def test_exact_versions(self):
        self.assertEqual(action_health.affected("v45.0.7", "version", TJ), "yes")
        self.assertEqual(action_health.affected("v46.0.1", "version", TJ), "no")
        self.assertEqual(action_health.affected("v1.2.0", "version", [{"range": ">= 1.0, < 1.3"}]), "yes")
        self.assertEqual(action_health.affected("v1.3.0", "version", [{"range": ">= 1.0, < 1.3"}]), "no")

    def test_floating_and_unknown(self):
        self.assertEqual(action_health.affected("v45", "floating", TJ), "possibly")
        self.assertEqual(action_health.affected("v46", "floating", TJ), "no")
        self.assertEqual(action_health.affected("a" * 40, "sha", TJ), "unknown")


def used(*refs):
    return {("", ref, rtype, "action") for ref, rtype in refs}


class Assess(unittest.TestCase):
    def test_no_known_problems(self):
        a = action_health.assess("actions/checkout", OK_REPO, {"advisories": [], "versions": {}, "inner": {},
                                 "latest_release": {"tag": "v7.0.1", "published_at": "2026-07-20T00:00:00Z",
                                                    "immutable": False}}, used(("v7", "floating")), NOW)
        self.assertEqual((a["level"], a["summary"]), ("OK", "No known problems"))
        self.assertIn("maintained by GitHub", a["notes"])
        self.assertTrue(any("not immutable" in n for n in a["notes"]))
        self.assertTrue(any("floating tag" in n for n in a["notes"]))

    def test_vulnerable_version_used(self):
        adv = [{"ghsa": "GHSA-mrrh-fwg8-r2c3", "severity": "high", "ranges": TJ}]
        a = action_health.assess("tj-actions/changed-files", OK_REPO, {"advisories": adv},
                                 used(("v45.0.7", "version")), NOW)
        self.assertEqual(a["level"], "Fix")
        self.assertIn("affects v45.0.7, which you use; fixed in 46.0.1", a["summary"])
        a = action_health.assess("tj-actions/changed-files", OK_REPO, {"advisories": adv}, used(("v46", "floating")), NOW)
        self.assertEqual(a["level"], "OK")

    def test_review_problems(self):
        old = dict(OK_REPO, pushed_at="2024-01-01T00:00:00Z", owner_type="User")
        health = {"advisories": [], "versions": {"v2.0.0": "2026-11-12T00:00:00Z"},
                  "inner": {".": {"unpinned": ["actions/cache@v4"], "images_without_digest": []}}}
        a = action_health.assess("someone/tool", old, health, used(("v2.0.0", "version")), NOW)
        texts = " | ".join(t for _, t in a["problems"])
        self.assertEqual(a["level"], "Review")
        self.assertIn("no change since 2024-01-01", texts)
        self.assertIn("less than 7 days ago", texts)
        self.assertIn("without pinning them itself: actions/cache@v4", texts)
        self.assertIn("maintained by individual account", a["notes"])

    def test_not_checked(self):
        a = action_health.assess("x/y", {"status": "not checked"}, None, used(("v1", "floating")), NOW)
        self.assertEqual(a["level"], "Not checked")

    def test_org_view_sorts_problems_first(self):
        f = lambda repo, slug, ref, rtype: {"repo": repo, "actions": {"items": [
            {"path": ".github/workflows/ci.yml", "uses": [{"kind": "action", "slug": slug, "target": slug, "path": "",
                                                           "ref": ref, "ref_type": rtype}]}]}}
        rows = [{"f": f("a", "actions/checkout", "v4", "floating")}, {"f": f("b", "x/old", "v1.0.0", "version")}]
        index = {"repos": {"actions/checkout": OK_REPO, "x/old": dict(OK_REPO, archived=True)}, "health": {}}
        got = action_health.org_actions(index, rows, NOW)
        self.assertEqual([(s, a["level"], u) for s, a, u in got],
                         [("x/old", "Review", ["b"]), ("actions/checkout", "OK", ["a"])])


class OnlineZizmor(unittest.TestCase):
    def test_findings_are_mapped_to_their_repository(self):
        with tempfile.TemporaryDirectory() as d:
            roots = {n: os.path.join(d, n) for n in ("one", "two")}
            for r in roots.values():
                os.makedirs(os.path.join(r, ".github", "workflows"))

            def finding(rule, repo):
                path = os.path.join(roots[repo], ".github", "workflows", "ci.yml")
                return {"ident": rule, "desc": "", "determinations": {"severity": "High", "confidence": "High"},
                        "locations": [{"symbolic": {"kind": "Primary", "key": {"Local": {"verbatim_path": path}}},
                                       "concrete": {"location": {"start_point": {"row": 4}}}}], "ignored": False}
            out = [finding("known-vulnerable-actions", "two"), finding("unpinned-uses", "one")]
            done = subprocess.CompletedProcess([], 0, stdout=json.dumps(out), stderr="")
            with mock.patch.object(zizmor_runner.subprocess, "run", return_value=done) as run:
                res = zizmor_runner.run_online("zizmor", roots, "token-value")
            env = run.call_args.kwargs["env"]
        self.assertEqual(res["status"], "ok")
        self.assertEqual(list(res["findings"]), ["two"])  # offline rules are dropped: the per-repo run has them
        self.assertEqual(res["findings"]["two"][0]["file"], ".github/workflows/ci.yml")
        self.assertEqual(env["ZIZMOR_GITHUB_TOKEN"], "token-value")
        self.assertNotIn("token-value", " ".join(run.call_args.args[0]))  # never on the command line

    def test_no_token_means_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("no GitHub token", zizmor_runner.run_online("zizmor", {"a": d}, None)["status"])


if __name__ == "__main__":
    unittest.main()
