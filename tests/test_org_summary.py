"""The deep-investigation section and cross-platform file handling.

  uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
"""
import ast
import csv
import os
import tempfile
import unittest
from datetime import datetime, timezone

from repostatus.reports import org_summary

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = {"dormant_days": 90, "dead_days": 365}


def row(name, status, flags):
    f = {"repo": name, "errors": [], "default_branch": "main", "history": [], "activity": {}}
    return {"f": f, "status": status, "last": NOW, "source": "activity API", "bound": False, "pkgs": [],
            "prot": None, "branches": None, "hygiene": [], "flags": flags}


ROWS = [
    row("legacy-api", "dead", [("FORCE_PUSH_DEFAULT", "high", "1 force push(es)"),
                               ("NEW_TIMEZONE", "medium", "abc1234 in -08:00")]),
    row("web", "active", [("NEW_TIMEZONE", "medium", "def5678 in +09:00"),
                          ("INITIAL_IMPORT_BACKDATED", "info", "not a reason")]),
    row("docs", "active", []),
]


class DeepSection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "summary.md")
            org_summary.write_summary(p, {"owner": "acme"}, ROWS, CFG, NOW, 10)
            with open(p, encoding="utf-8") as fh:
                cls.md = fh.read()

    def test_counts_each_repo_once(self):
        self.assertIn("## Deep investigation needed: 2 of 3 repositories", self.md)

    def test_reason_counts(self):
        self.assertIn("| FORCE_PUSH_DEFAULT | repo-status | high | 1 |", self.md)
        self.assertIn("| NEW_TIMEZONE | repo-status | medium | 2 |", self.md)

    def test_info_flags_are_not_reasons(self):
        self.assertNotIn("| INITIAL_IMPORT_BACKDATED |", self.md)

    def test_priority_and_deep_dive_command(self):
        from repostatus.platform_support import scan_cmd
        self.assertIn(f"| legacy-api | dead | high | FORCE_PUSH_DEFAULT, NEW_TIMEZONE | "
                      f"`{scan_cmd()} acme deep legacy-api` |", self.md)
        self.assertIn("| web | active | medium | NEW_TIMEZONE | - |", self.md)
        # high priority first
        self.assertLess(self.md.index("| legacy-api | dead | high"), self.md.index("| web | active | medium"))

    def test_none(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "summary.md")
            org_summary.write_summary(p, {"owner": "acme"}, [ROWS[2]], CFG, NOW, 1)
            with open(p, encoding="utf-8") as fh:
                self.assertIn("Deep investigation needed: 0 of 1 repositories\n\nNone.", fh.read())


class Csv(unittest.TestCase):
    def test_priority_and_codes_columns(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "repo-status.csv")
            org_summary.write_csv(p, ROWS, NOW)
            with open(p, newline="", encoding="utf-8-sig") as fh:
                got = {r["repo"]: r for r in csv.DictReader(fh)}
        self.assertEqual(got["legacy-api"]["deep_dive_priority"], "high")
        self.assertEqual(got["legacy-api"]["deep_dive_reason_codes"], "FORCE_PUSH_DEFAULT, NEW_TIMEZONE")
        self.assertEqual(got["web"]["deep_dive_priority"], "medium")
        self.assertEqual(got["docs"]["deep_dive"], "no")
        self.assertEqual(got["docs"]["deep_dive_priority"], "")


class WorkflowCounts(unittest.TestCase):
    """GitHub calls an enabled workflow "active"; that is not the same as running, and a broken file is not enabled."""

    def test_enabled_and_recently_run(self):
        r = row("t", "dead", [])
        r["f"]["actions"] = {"items": [
            {"path": ".github/workflows/broken.yml", "state": "active", "last_run": None},
            {"path": ".github/workflows/ok.yml", "state": "active", "last_run": "2026-10-01T00:00:00Z"},
            {"path": ".github/workflows/old.yml", "state": "active", "last_run": "2025-01-01T00:00:00Z"},
            {"path": ".github/workflows/off.yml", "state": "disabled_manually", "last_run": "2026-10-02T00:00:00Z"}]}
        r["f"]["zizmor"] = {"invalid": [".github/workflows/broken.yml"]}
        x = org_summary.row_for(r, NOW, CFG)
        self.assertEqual((x["workflows"], x["enabled_workflows"], x["workflows_run_last_90_days"]), (4, 2, 2))


class NonAscii(unittest.TestCase):
    """Names and commit text are often not ASCII; Windows' default encoding cannot hold them."""

    def test_round_trip(self):
        text = "abc1234 by 林小明 → José"
        rows = [row("r", "active", [("SIGNING_BREAK", "high", text)])]
        with tempfile.TemporaryDirectory() as d:
            md, cs = os.path.join(d, "s.md"), os.path.join(d, "s.csv")
            org_summary.write_summary(md, {"owner": "o"}, rows, CFG, NOW, 1)
            org_summary.write_csv(cs, rows, NOW)
            with open(md, encoding="utf-8") as fh:
                self.assertIn(text, fh.read())
            with open(cs, "rb") as fh:
                raw = fh.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "CSV needs a BOM so Excel on Windows reads UTF-8")
        self.assertIn(text.encode("utf-8"), raw)


class EncodingGuard(unittest.TestCase):
    """Every text file and text-mode subprocess must name its encoding, or Windows falls back to a legacy code page."""

    def test_open_and_subprocess_name_encoding(self):
        bad = []
        for root, dirs, files in os.walk(HERE):
            dirs[:] = [x for x in dirs if x not in ("out", ".venv", ".git", "__pycache__", "wiki")]
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read(), path)
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    fn = node.func
                    called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                    kw = {k.arg for k in node.keywords}
                    if called == "open":
                        mode = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) \
                            else next((k.value.value for k in node.keywords if k.arg == "mode"), "r")
                        if "b" not in mode and "encoding" not in kw:
                            bad.append(f"{os.path.relpath(path, HERE)}:{node.lineno} open() without encoding")
                    elif called == "run" and isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "subprocess":
                        # byte mode (no text=) is fine; text mode must say which encoding
                        if kw & {"text", "universal_newlines"} and "encoding" not in kw:
                            bad.append(f"{os.path.relpath(path, HERE)}:{node.lineno} text-mode subprocess.run "
                                       f"without encoding")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
