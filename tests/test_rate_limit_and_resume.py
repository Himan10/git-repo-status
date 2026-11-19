"""Long scans: pausing for GitHub's hourly limit, retrying refused repositories, resuming a stopped scan.
No network, no real waiting.

  uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
"""
import argparse
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from repostatus.github import api_client
from repostatus.github.rate_limit import Pacer
from repostatus.collect.scan_progress import Progress


class FakeGH:
    """Counts calls; rate_limit() answers from a script of (remaining, reset) pairs."""

    def __init__(self, answers, limit=5000):
        self.answers, self.limit, self.calls, self.asked = list(answers), limit, 0, 0
        self._hits = [0]

    def rate_limit(self):
        self.asked += 1
        self.calls += 1
        remaining, reset = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return {"remaining": remaining, "limit": self.limit, "reset": reset}

    @property
    def rate_limited(self):
        return self._hits[0]

    def fork(self):
        return self


class Pacing(unittest.TestCase):
    def pacer(self, answers):
        self.slept = []
        gh = FakeGH(answers)
        return gh, Pacer(gh, workers=4, sleep=self.slept.append, now=lambda: 1000.0, log=lambda m: None)

    def test_plenty_left_asks_github_once(self):
        gh, p = self.pacer([(5000, 4600)])
        for _ in range(250):  # 5,000 calls in total
            p.before()
            gh.calls += 20  # a repository's worth of calls
        # once at start, once when the local estimate came near the reserve (2 x 400 calls)
        self.assertEqual(gh.asked, 2)
        self.assertEqual(self.slept, [])

    def test_waits_for_reset_when_low(self):
        gh, p = self.pacer([(300, 4600), (5000, 8200)])
        p.before()
        self.assertEqual(self.slept, [3605.0])  # until the reset, plus 5 seconds
        self.assertEqual((p.pauses, p.estimate()), (1, 5000))

    def test_refusal_waits_a_minute_when_allowance_is_fine(self):
        gh, p = self.pacer([(4000, 4600)])
        p.wait_after_refusal()  # e.g. GitHub's per-minute limit
        self.assertEqual(self.slept, [60.0])


class RateLimitTracking(unittest.TestCase):
    def test_refusals_are_recorded_per_repository_client(self):
        refused = subprocess.CompletedProcess([], 1, stdout=json.dumps({"message": "API rate limit exceeded for user"}),
                                              stderr="gh: API rate limit exceeded (HTTP 403)")
        with mock.patch.object(api_client.subprocess, "run", lambda *a, **k: refused):
            gh = api_client.GitHub()
            repo_a, repo_b = gh.fork(), gh.fork()
            _, err = repo_a.with_recorder(None).try_get("repos/o/a")
        self.assertIn("rate limit", err)
        self.assertEqual((repo_a.rate_limited, repo_b.rate_limited, gh.calls), (1, 0, 1))

    def test_other_errors_are_not_rate_limits(self):
        nf = subprocess.CompletedProcess([], 1, stdout=json.dumps({"message": "Not Found"}), stderr="(HTTP 404)")
        with mock.patch.object(api_client.subprocess, "run", lambda *a, **k: nf):
            gh = api_client.GitHub()
            gh.try_get("repos/o/a")
        self.assertEqual(gh.rate_limited, 0)


class ProgressFiles(unittest.TestCase):
    def test_save_resume_finish(self):
        with tempfile.TemporaryDirectory() as d:
            p = Progress(d, resume=False)
            p.save({"repo": "a/b weird name", "errors": []})
            p2 = Progress(d, resume=True)
            self.assertEqual(list(p2.done), ["a/b weird name"])
            self.assertEqual(p2.started, p.started)
            Progress(d, resume=False)  # a new scan starts clean
            self.assertEqual(Progress(d, resume=True).done, {})
            p2.finish()
            self.assertFalse(os.path.exists(os.path.join(d, "progress")))


class ScanAndResume(unittest.TestCase):
    """A scan of three repositories stops at the third; --resume collects only that one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from repostatus import scan_org
        self.scan_org = scan_org
        self.collected = []
        self.stop_at = "c"

        def fake_collect(gh, owner, meta, *args, **kw):
            if meta["name"] == self.stop_at:
                raise KeyboardInterrupt
            self.collected.append(meta["name"])
            return {"repo": meta["name"], "errors": [], "history": [], "empty": True}

        ctx = {"owner": "acme", "type": "Organization", "viewer": "me", "audit_log": "n/a",
               "repos": [{"name": n} for n in ("a", "b", "c")], "packages": []}
        for target, value in (("collect_repo", fake_collect), ("owner_context", lambda gh, o: json.loads(json.dumps(ctx))),
                              ("GitHub", lambda: FakeGH([(5000, 9999999999)])),
                              ("out_dir", lambda owner, create=True: self.tmp.name),
                              ("_hard_exit", self.exit)):
            patcher = mock.patch.object(scan_org, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def exit(code):
        raise SystemExit(code)

    def args(self, resume):
        return argparse.Namespace(owner="acme", repo=None, workers=1, skip_forks=False, skip_archived=False,
                                  ignore_rate_limit=False, no_zizmor=True, no_online_audits=True, skip_action_check=True,
                                  skip_branches=True,
                                  resume=resume, max_branches=1000)

    def test_stop_then_resume(self):
        with self.assertRaises(SystemExit) as stopped, mock.patch("sys.stderr") as err:
            self.scan_org.cmd_collect(self.args(resume=False))
        self.assertEqual(stopped.exception.code, 130)
        self.assertIn("--resume", "".join(c.args[0] for c in err.write.call_args_list))
        self.assertEqual(self.collected, ["a", "b"])
        self.stop_at = None
        with mock.patch("sys.stderr"):
            self.scan_org.cmd_collect(self.args(resume=True))
        self.assertEqual(self.collected, ["a", "b", "c"])  # a and b were not collected again
        with open(os.path.join(self.tmp.name, "facts.json"), encoding="utf-8") as fh:
            facts = json.load(fh)
        self.assertEqual([f["repo"] for f in facts["repos"]], ["a", "b", "c"])
        self.assertTrue(facts["context"]["resumed"])
        self.assertEqual(facts["context"]["api_calls"], 2)  # one allowance check per session
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "progress")))  # cleaned up when complete


if __name__ == "__main__":
    unittest.main()
