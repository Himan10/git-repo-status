"""The HTML reports (report.html and deep-dive/<repo>.html): same verdicts as the markdown, self-contained, no
icons, and everything taken from GitHub stays text, even when a repository or workflow is hostile. No network.

  uv run python -m unittest discover -s tests
"""
import json
import os
import re
import tempfile
import unittest

from repostatus.reports import deep_dive_verdict, html_report
from test_deep_dive_report import NOW, facts, row

HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def org_row(f, flags=()):
    r = row(f, extra_flags=flags)
    r.update(last=NOW, source="activity API", bound=False, pkgs=[], prot={}, branches={})
    return r


def links(page):
    return re.findall(r'(?:href|src)="([^"]*)"', page)


class OrgPage(unittest.TestCase):
    def build(self, d, flags=()):
        f = facts(d)
        ctx = {"owner": "acme", "api_calls": 12, "zizmor": {"version": "1.32.0"}}
        data = html_report.org_page(ctx, [org_row(f, flags)], dict(row(f)["cfg"]), NOW, d, generated=NOW)
        path = os.path.join(d, "report.html")
        html_report.write_org(path, data)
        with open(path, encoding="utf-8") as fh:
            return data, fh.read()

    def test_verdicts_match_the_deep_dive(self):
        with tempfile.TemporaryDirectory() as d:
            data, _ = self.build(d)
        repo = data["repos"][0]
        self.assertEqual((repo["n"], repo["verdict"], repo["fix"]), ("app", "Fix", 1))
        self.assertEqual(data["deep"]["count"], 1)
        self.assertIn("deep app", repo["cmd"])
        self.assertIsNone(repo["report"])  # no deep-dive page yet, so no link to a missing file
        # findings point into the type and repository lists; the injection is one Fix finding in Workflow flaws
        fixes = [f for f in data["findings"] if f[2] == 1]
        self.assertEqual(len(fixes), 1)
        self.assertEqual(data["types"][fixes[0][0]][1:3], ["Command injection", "Workflow flaws"])
        # every finding says where it is, with a link: here the file and lines on the default branch
        self.assertEqual(fixes[0][3], ".github/workflows/deploy.yml:10,11 on main")
        self.assertEqual(fixes[0][5], "https://github.com/acme/app/blob/main/.github/workflows/deploy.yml#L10")
        self.assertEqual(data["types"][fixes[0][0]][5], "https://docs.zizmor.sh/audits/#template-injection")
        self.assertEqual([f for f in data["findings"] if not f[3]], [])  # no finding without a place
        self.assertEqual(data["repos"][fixes[0][1]]["n"], "app")
        # notes that carry a count share one finding type, so they group across repositories
        names = [t[1] for t in data["types"]]
        self.assertEqual(len(names), len(set(names)))

    def test_counted_notes_share_a_name(self):
        self.assertEqual(html_report._short_note("3 of 5 actions are not pinned to a commit, so ..."),
                         html_report._short_note("11 of 11 actions are not pinned to a commit, so ..."))
        self.assertEqual(html_report._short_note("no CODEOWNERS (private repo)"), "No CODEOWNERS")

    def test_hostile_text_cannot_leave_the_data_block(self):
        with tempfile.TemporaryDirectory() as d:
            data, page = self.build(d, flags=[("WORKFLOW_BY_NEW_ACTOR", "medium", HOSTILE)])
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img", page)
        self.assertEqual(page.count("</script>"), 2)  # the data block and the page's own script, nothing else
        embedded = re.search(r'<script type="application/json" id="data">(.*?)</script>', page, re.S).group(1)
        self.assertEqual(json.loads(embedded), json.loads(json.dumps(data)))  # escaped, yet the same data
        self.assertIn(HOSTILE, [f[4] for f in json.loads(embedded)["findings"]])

    def test_self_contained_and_no_icons(self):
        with tempfile.TemporaryDirectory() as d:
            _, page = self.build(d)
        self.assertEqual([u for u in links(page) if not u.startswith("#")], [])  # nothing loaded from anywhere
        self.assertNotIn("http://", page)
        self.assertTrue(all(ord(c) < 0x2190 for c in page), "no icons or emoji in the report")
        # the script only allows links to GitHub and to deep-dive pages
        self.assertIn(r"/^https:\/\/github\.com\//", page)
        self.assertNotIn("innerHTML", page)
        # layout rules that broke the page before: a floated filter heading squeezed the first option into a
        # one-letter-wide column; the report is always white, also on computers set to dark mode
        self.assertNotIn("float:", html_report.CSS)
        self.assertNotIn("prefers-color-scheme", html_report.CSS)
        self.assertIn('<meta name="color-scheme" content="light">', page)
        # number headers align with their numbers: the right-align rule must beat the tables' left-aligned headers
        for selector in ("table.plain th.num", ".box th.num", ".inner table th.num"):
            self.assertIn(selector, html_report.CSS)
        self.assertIn(r"/^[=+\-@\t\r]/.test(s)", page)  # CSV export defuses spreadsheet formulas


class DeepPage(unittest.TestCase):
    def build(self, d, flags=()):
        f = facts(d)
        r = row(f, extra_flags=flags)
        result = deep_dive_verdict.assess(f, r, "acme/app", d)
        return html_report.deep_page("acme", f, "2026-11-15T10:00:00Z", result, "app-evidence.md",
                                     {"status": "active", "last_human_push": "2026-11-10"})

    def test_verdict_and_open_areas(self):
        with tempfile.TemporaryDirectory() as d:
            page = self.build(d)
        self.assertIn('<h1>app: <span class="v-fix">1 to fix</span>', page)
        self.assertIn('<details class="fitem" id="a1" open><summary class="frow"><span class="muted">1</span>'
                      '<span><span class="v v-fix">Fix</span></span>', page)  # Fix findings start open
        self.assertIn('<details class="fitem" id="a2"><summary', page)  # Review findings start closed
        self.assertIn('href="../report.html"', page)
        self.assertNotIn("<script", page)  # the deep-dive page works without any script

    def test_hostile_text_is_escaped_and_commits_are_linked(self):
        detail = HOSTILE + " in commit abc1234def5"
        with tempfile.TemporaryDirectory() as d:
            page = self.build(d, flags=[("WORKFLOW_BY_NEW_ACTOR", "medium", detail)])
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn('<a href="https://github.com/acme/app/commit/abc1234def5">abc1234</a> '
                      '<span class="code">FINDING: WORKFLOW_BY_NEW_ACTOR</span>', page)
        for u in links(page):
            self.assertTrue(u.startswith(("https://github.com/", "https://docs.zizmor.sh/", "#", "../report.html", "app-evidence.md")), u)
        self.assertTrue(all(ord(c) < 0x2190 for c in page), "no icons or emoji in the report")


if __name__ == "__main__":
    unittest.main()
