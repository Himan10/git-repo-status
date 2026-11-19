"""The deep-dive report: eight areas with Fix / Review / OK, actions with quoted lines, plain-language
explanations and links to the right GitHub settings page. No network.

  uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
"""
import os
import tempfile
import unittest
from datetime import datetime, timezone

from repostatus.reports import finding_explanations
from repostatus.checks import repository_checks
from repostatus.reports import deep_dive_verdict
from repostatus.collect import workflow_parser

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
DEPLOY = """name: deploy
on: [workflow_dispatch, workflow_run]
permissions: {id-token: write}
jobs:
  deploy:
    environment: production
    steps:
      - name: Resolve the tag
        run: |
          TAG="${{ github.event.inputs.tag }}"
          TAG="sha-${{ github.event.workflow_run.head_sha }}"
      - run: echo ${{ secrets.ROLE }}
"""


def facts(owner_dir):
    path = os.path.join(owner_dir, "workflows", "app", ".github", "workflows")
    os.makedirs(path)
    with open(os.path.join(path, "deploy.yml"), "w", encoding="utf-8") as fh:
        fh.write(DEPLOY)
    wf = dict(workflow_parser.parse_workflow(DEPLOY), path=".github/workflows/deploy.yml", state="active", id=1,
              last_run="2026-11-10T00:00:00Z")
    finding = lambda line: {"rule": "template-injection", "severity": "high", "confidence": "high", "ignored": False,
                            "file": ".github/workflows/deploy.yml", "line": line, "step": "Resolve the tag"}
    return {
        "repo": "app", "visibility": "private", "default_branch": "main", "archived": False, "history": [],
        "activity": {"force_pushes": []}, "actions": {"items": [wf]},
        "zizmor": {"status": "ok", "findings": [finding(10), finding(11),
                                                {"rule": "unpinned-uses", "severity": "high", "confidence": "high",
                                                 "ignored": False, "file": ".github/workflows/deploy.yml", "line": 3}]},
        "secrets": {"repo_secrets": ["NPM"], "org_secrets": [], "errors": [],
                    "environments": {"production": {"custom": True, "policies": [{"name": "main", "type": "branch"}],
                                                    "protected_branches_only": False, "secrets": ["ROLE"],
                                                    "admins_bypass": True}}},
    }


def row(f, extra_flags=(), hygiene=()):
    return {"f": f, "status": "active", "now": NOW, "cfg": repository_checks.DEFAULTS,
            "flags": [("ZIZMOR_HIGH_IN_LIVE_WORKFLOW", "high", "zizmor template-injection ...")] + list(extra_flags),
            "hygiene": list(hygiene) or [
                "force-push allowed on default branch (private repo on GitHub Free: branch rules not available)",
                "no PR required on default branch (private repo on GitHub Free: branch rules not available)",
                "secrets any branch can read (repository or organisation secret, not in an environment): NPM",
                "no actions.lock"],
            "prot": {"plan_limited": True}}


class Assess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = facts(self.tmp.name)
        self.v = deep_dive_verdict.assess(self.f, row(self.f), "org/app", self.tmp.name, up={"checked": True, "moved": [],
                                                                                   "problems": []})
        self.areas = {a["name"]: a for a in self.v["areas"]}

    def test_eight_areas_in_fixed_order(self):
        self.assertEqual([a["name"] for a in self.v["areas"]], deep_dive_verdict.AREAS)
        self.assertEqual({k: a["result"] for k, a in self.areas.items() if a["result"] != "OK"},
                         {"Workflow flaws": "Fix", "Secrets": "Review", "Repository settings": "Review",
                          "Workflow hygiene": "Review", "Old copies on branches": "Not checked"})
        self.assertEqual(self.v["verdict"], "1 to fix, 4 to review. No sign of tampering.")

    def test_injection_quotes_lines_and_marks_generated_values(self):
        a = self.v["actions"][0]
        self.assertEqual((a["level"], a["title"]), ("Fix", "Command injection (deploy.yml)"))
        self.assertEqual([(l["line"], l["harmless"]) for l in a["lines"]], [(10, False), (11, True)])
        self.assertIn("github.event.inputs.tag", a["lines"][0]["text"])
        self.assertIn("anyone with write access", a["who"])
        self.assertEqual(a["reach"], "ROLE and an OIDC cloud login")  # main may use the environment

    def test_secrets_actions_link_to_this_repositorys_settings(self):
        sec = next(a for a in self.v["actions"] if a["code"] == "secrets")
        self.assertEqual(sec["settings"][1], "https://github.com/org/app/settings/secrets/actions")
        bypass = next(a for a in self.v["actions"] if a["code"] == "admin-bypass")
        self.assertEqual(bypass["settings"][1], "https://github.com/org/app/settings/environments")

    def test_plan_limited_rules_are_one_item_with_a_doable_fix(self):
        s = next(a for a in self.v["actions"] if a["area"] == "Repository settings")
        self.assertEqual(len(s["items"]), 1)
        self.assertIn("GitHub Free", s["items"][0]["text"])
        self.assertIn("write access", s["fix"])

    def test_hygiene_counts_unpinned_and_says_how(self):
        h = next(a for a in self.v["actions"] if a["area"] == "Workflow hygiene")
        self.assertEqual(h["items"][0]["text"], "no actions.lock")
        self.assertIn("gh actions-lock", h["fix"])
        u = workflow_parser.parse_uses("actions/checkout@v4")
        self.f["actions"]["items"][0]["uses"] = [u]
        v = deep_dive_verdict.assess(self.f, row(self.f), "org/app", self.tmp.name)
        h = next(a for a in v["actions"] if a["area"] == "Workflow hygiene")
        self.assertTrue(h["items"][0]["text"].startswith("1 of 1 actions are not pinned to a commit"))

    def test_tampering_rows_change_the_verdict(self):
        v = deep_dive_verdict.assess(self.f, row(self.f, [("FORCE_PUSH_DEFAULT", "high", "1 force push")]), "org/app",
                           self.tmp.name)
        self.assertIn("Possible tampering", v["verdict"])
        self.assertEqual(next(a for a in v["areas"] if a["name"] == "History")["result"], "Fix")

    def test_clean_repository(self):
        f = facts(os.path.join(self.tmp.name, "clean"))
        f["zizmor"]["findings"], f["secrets"]["environments"] = [], {}
        f["actions"]["items"][0]["uses"] = []
        r = row(f, hygiene=["unused"])
        r["flags"] = []
        v = deep_dive_verdict.assess(f, r, "org/app", os.path.join(self.tmp.name, "clean"))
        self.assertEqual(v["verdict"], "0 to fix, 0 to review. No sign of tampering.")
        self.assertTrue(all(a["result"] in ("OK", "Not checked") for a in v["areas"]))


class Rendered(unittest.TestCase):
    def test_report_is_short_plain_words_and_links_resolve(self):
        from repostatus import deep_dive
        with tempfile.TemporaryDirectory() as d:
            f = facts(d)
            v = deep_dive_verdict.assess(f, row(f), "org/app", d, up={"checked": True, "moved": [], "problems": []})
            out = os.path.join(d, "app.md")
            deep_dive.write_report(out, "org", f, "2026-11-15T22:36:00", v, "app-evidence.md")
            with open(out, encoding="utf-8") as fh:
                text = fh.read()
        self.assertLess(len(text.splitlines()), 120)
        self.assertTrue(text.isascii(), "no icons or emoji in the report")
        self.assertIn("**1 to fix, 4 to review. No sign of tampering.**", text)
        anchors = {a for _, a in deep_dive.EVIDENCE_SECTIONS}
        self.assertTrue(set(deep_dive_verdict.EVIDENCE.values()) <= anchors)
        console = deep_dive.console_table(v)
        self.assertTrue(console.isascii())

    def test_console_wraps_instead_of_cutting(self):
        from repostatus import deep_dive
        long = "AWS_DEPLOY_ROLE_ARN limited by environment production, but admins can bypass it; " \
               "environments hold secrets without required reviewers: production"
        v = {"verdict": "0 to fix, 1 to review.", "actions": [],
             "areas": [{"name": "Secrets", "result": "Review", "short": long}]}
        text = deep_dive.console_table(v, width=80)
        self.assertEqual(" ".join(text.split()).count("without required reviewers: production"), 1)  # nothing lost
        self.assertTrue(all(len(line) <= 80 for line in text.splitlines()))


class Explanations(unittest.TestCase):
    def test_every_escalating_rule_and_flag_is_explained(self):
        from repostatus.reports import org_summary
        from repostatus.collect import zizmor_runner
        self.assertEqual(set(zizmor_runner.ESCALATE) - set(finding_explanations.ZIZMOR), set())
        self.assertEqual({c for c in org_summary.REASONS if c != "ZIZMOR_HIGH_IN_LIVE_WORKFLOW"} - set(finding_explanations.FLAGS), set())

    def test_who_can_trigger(self):
        self.assertIn("anyone with a GitHub account", finding_explanations.who_can_trigger(["issue_comment"], "public"))
        self.assertIn("read access", finding_explanations.who_can_trigger(["pull_request_target"], "private"))
        self.assertIn("write access", finding_explanations.who_can_trigger(["workflow_dispatch"], "private"))

    def test_generated_values(self):
        self.assertTrue(finding_explanations.harmless_expression("github.event.workflow_run.head_sha"))
        self.assertFalse(finding_explanations.harmless_expression("github.event.pull_request.title"))


if __name__ == "__main__":
    unittest.main()
