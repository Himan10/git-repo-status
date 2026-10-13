"""Synthetic cases. The tampered repo replays the pattern from the opensourcemalware.com write-up
(nestjsx/nest-access-control): a commit dated 2025-12-24, force-pushed on 2026-09-08, from a
different timezone, unsigned, with a .vscode task that runs on folder open.

  uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
"""
import unittest
from datetime import datetime, timezone

from repostatus import flags

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


def commit(oid, date, tz="+05:30", signed=True, email="dev@example.com", author_date=None):
    utc = date + "Z"
    local = (author_date or date) + tz
    return {"oid": oid, "committed_utc": utc, "author_date": local, "committer_date": local,
            "author_email": email, "author_login": "dev", "committer_email": email, "committer_login": "dev",
            "signature": "VALID" if signed else "UNSIGNED", "signature_valid": signed}


def event(t, typ, sha, before="b" * 40, ref="refs/heads/main", actor="dev"):
    return {"ts": t + "Z", "type": typ, "ref": ref, "actor": actor, "actor_type": "User",
            "before": before, "after": sha}


def repo(history, default_events, force=(), latest=None, autorun=False):
    return {
        "repo": "r", "default_branch": "main", "archived": False, "errors": [],
        "pushed_at": default_events[0]["ts"], "history": history,
        "activity": {"latest": latest or list(default_events), "default_branch": list(default_events),
                     "force_pushes": list(force)},
        "autorun": {"tasks_json": autorun, "run_on_folder_open": autorun},
        "collaborators": ["dev"], "protection": {}, "codeowners": {"path": None}, "actions": {"items": []},
        "branches": {"total": 1, "items": [{"name": "main", "committed": history[0]["committed_utc"]}]},
    }


# Ten normal, signed commits, each pushed a few minutes after it was made
NORMAL = [commit(f"{i:040x}", f"2025-{12 - i // 3:02d}-{10 + i:02d}T10:00:00") for i in range(1, 11)]
NORMAL_EVENTS = [event(c["committed_utc"][:-6] + "05:00", "push", c["oid"]) for c in NORMAL]


class Tampered(unittest.TestCase):
    def setUp(self):
        bad = commit("e" * 40, "2025-12-24T09:12:00", tz="-08:00", signed=False)
        fp = event("2026-09-08T03:41:00", "force_push", bad["oid"], before=NORMAL[0]["oid"])
        f = repo([bad] + NORMAL, [fp] + NORMAL_EVENTS, force=[fp], autorun=True)
        status = flags.classify(f, NOW, flags.DEFAULTS)
        self.codes = {c for c, _, _ in flags.investigation_flags(f, status, NOW, flags.DEFAULTS)}

    def test_date_mismatch(self):
        self.assertIn("DATE_MISMATCH", self.codes)

    def test_force_push(self):
        self.assertIn("FORCE_PUSH_DEFAULT", self.codes)

    def test_timezone(self):
        self.assertIn("NEW_TIMEZONE", self.codes)

    def test_signing_break(self):
        self.assertIn("SIGNING_BREAK", self.codes)

    def test_autorun(self):
        self.assertIn("VSCODE_AUTORUN", self.codes)


class Clean(unittest.TestCase):
    def test_no_flags(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        status = flags.classify(f, NOW, flags.DEFAULTS)
        self.assertEqual(flags.investigation_flags(f, status, NOW, flags.DEFAULTS), [])

    def test_pr_merge_is_not_mismatch(self):
        # a PR opened in August and merged in October: merge commit is created by GitHub at merge time
        merge = commit("f" * 40, "2026-10-01T12:00:00", author_date="2026-10-01T12:00:00")
        f = repo([merge] + NORMAL, [event("2026-10-01T12:00:01", "pr_merge", merge["oid"])] + NORMAL_EVENTS)
        codes = {c for c, _, _ in flags.investigation_flags(f, "active", NOW, flags.DEFAULTS)}
        self.assertNotIn("DATE_MISMATCH", codes)

    def test_github_created_commit_synced_late(self):
        # fork sync: commit made by GitHub upstream in May, brought into this repo in June
        c = dict(commit("c" * 40, "2024-05-01T17:14:05"), committer_email="noreply@github.com")
        f = repo([c] + NORMAL, [event("2024-05-18T17:21:58", "push", c["oid"])] + NORMAL_EVENTS)
        codes = {c for c, _, _ in flags.investigation_flags(f, "dead", NOW, flags.DEFAULTS)}
        self.assertNotIn("DATE_MISMATCH", codes)
        self.assertIn("LATE_ARRIVAL_GITHUB_COMMIT", codes)

    def test_fast_forward_merge_is_not_mismatch(self):
        c = commit("d" * 40, "2026-08-01T10:00:00")
        feat = event("2026-08-01T10:05:00", "push", c["oid"], ref="refs/heads/feat/x")
        main = event("2026-08-20T10:00:00", "push", c["oid"])
        f = repo([c] + NORMAL, [main] + NORMAL_EVENTS, latest=[main, feat] + NORMAL_EVENTS)
        codes = {c for c, _, _ in flags.investigation_flags(f, "active", NOW, flags.DEFAULTS)}
        self.assertNotIn("DATE_MISMATCH", codes)


class Status(unittest.TestCase):
    def test_bot_pushes_do_not_keep_repo_alive(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        bot = dict(event("2026-10-10T00:00:00", "push", "a" * 40), actor="dependabot[bot]", actor_type="Bot")
        f["activity"]["latest"] = [bot] + NORMAL_EVENTS
        self.assertEqual(flags.classify(f, NOW, flags.DEFAULTS), "dormant")

    def test_image_published_after_inactivity(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        pkg = {"type": "container", "name": "r", "latest_published": "2026-09-01T00:00:00Z"}
        codes = {c for c, _, _ in flags.package_flags(f, "dormant", [pkg], flags.DEFAULTS)}
        self.assertIn("PUBLISHED_AFTER_INACTIVITY", codes)


class BranchRules(unittest.TestCase):
    PLAN = "403 Upgrade to GitHub Pro or make this repository public to enable this feature."

    def test_plan_limited_is_allowed_with_reason(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        f["protection"] = {"classic": {"error": self.PLAN}, "rulesets": {"error": self.PLAN}}
        prot = flags.effective_protection(f)
        self.assertEqual(prot["source"], "not available on plan")
        self.assertIs(prot["force_push_blocked"], False)
        notes = flags.hygiene(f, "active", prot, NOW, flags.DEFAULTS)
        self.assertTrue(any(n.startswith("force-push allowed") and "GitHub Free" in n for n in notes))

    def test_unreadable_rules_are_unknown_not_allowed(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        f["protection"] = {"classic": {"error": "404 Not Found"}, "rulesets": {"error": "403 Resource not accessible"}}
        prot = flags.effective_protection(f)
        self.assertEqual(prot["source"], "unknown")
        self.assertIsNone(prot["force_push_blocked"])
        notes = flags.hygiene(f, "active", prot, NOW, flags.DEFAULTS)
        self.assertFalse(any(n.startswith("force-push allowed") for n in notes))
        self.assertTrue(any(n.startswith("branch rules could not be read") for n in notes))

    def test_classic_unreadable_with_rulesets_is_unknown(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        # ruleset only blocks deletion; classic protection (unreadable) might block force push
        f["protection"] = {"classic": {"error": "404 Not Found"},
                           "rulesets": {"types": ["deletion"], "deletion_blocked": True, "force_push_blocked": False}}
        prot = flags.effective_protection(f)
        self.assertIsNone(prot["force_push_blocked"])
        self.assertIs(prot["deletion_blocked"], True)
        self.assertEqual(prot["source"], "ruleset; classic unreadable")

    def test_no_rules_is_allowed(self):
        f = repo(NORMAL, NORMAL_EVENTS)
        f["protection"] = {"classic": None, "rulesets": {"types": [], "force_push_blocked": False}}
        prot = flags.effective_protection(f)
        self.assertEqual(prot["source"], "none")
        self.assertIs(prot["force_push_blocked"], False)


if __name__ == "__main__":
    unittest.main()
