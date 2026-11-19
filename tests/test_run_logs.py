"""The optional run-log check (deep dive --logs): which runs are read, what is found, and that values are
always masked. All tokens below are fake and built in the test.

  uv run python -m unittest discover -s tests
"""
import base64
import unittest

from repostatus.checks import log_scanner
from repostatus.collect import run_logs
from repostatus.github.api_client import ApiError

FAKE_GH = "ghp_" + "A1b2C3d4" * 4 + "XyZw"          # 40 characters, GitHub classic token shape
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"               # access key id shape
TS = "2026-10-20T01:16:30.2033510Z "


def log(*lines):
    return "\n".join(TS + l for l in lines)


class Scanner(unittest.TestCase):
    def test_plain_token_is_found_and_masked(self):
        got = log_scanner.scan(log("##[group]Run ./deploy.sh", f"using key {FAKE_AWS} for upload"))
        self.assertEqual(len(got), 1)
        n, step, kind, detail = got[0]
        self.assertEqual((n, step, kind), (2, "./deploy.sh", "AWS access key"))
        self.assertIn("AKIA...MNOP", detail)
        self.assertNotIn(FAKE_AWS, detail)

    def test_values_github_already_masked_are_not_reported(self):
        self.assertEqual(log_scanner.scan(log("token: ***", "echo *** | docker login")), [])

    def test_double_base64_like_tj_actions(self):
        blob = base64.b64encode(base64.b64encode(f'{{"github_token":{{"value":"{FAKE_GH}","isSecret":true}}}}'.encode())).decode()
        got = log_scanner.scan(log(blob))
        self.assertEqual([k for _, _, k, _ in got], ["encoded GitHub token"])
        self.assertIn("base64 twice", got[0][3])
        self.assertNotIn(FAKE_GH, " ".join(d for *_, d in got))

    def test_attack_indicator(self):
        got = log_scanner.scan(log("curl https://scan.aquasecurtiy.org/x"), ["scan.aquasecurtiy.org"])
        self.assertEqual([k for _, _, k, _ in got], ["attack indicator"])

    def test_ordinary_log_is_clean(self):
        text = log("##[group]Run actions/checkout@v4", "Syncing repository: org/app",
                   "sha256:" + "a" * 64, "Successfully built 3f1c2a9b8d7e")
        self.assertEqual(log_scanner.scan(text), [])


class FakeGH:
    def __init__(self, logs):
        self.logs, self.calls = logs, []

    def try_get(self, path):
        self.calls.append(path)
        return {"jobs": [{"id": jid, "name": f"job {jid}", "html_url": f"u{jid}"} for jid in self.logs]}, None

    def get_text(self, path):
        self.calls.append(path)
        jid = int(path.split("/jobs/")[1].split("/")[0])
        if self.logs[jid] is None:
            raise ApiError(path, "410", "Gone")
        return self.logs[jid]


class Fetching(unittest.TestCase):
    def test_check_runs(self):
        gh = FakeGH({1: log(f"key {FAKE_AWS}"), 2: None})
        got = run_logs.check_runs(gh, "org/app", [{"id": 99, "path": ".github/workflows/ci.yml", "url": "u"}])
        self.assertEqual([(x["job"], len(x["findings"]), x["error"]) for x in got],
                         [("job 1", 1, None), ("job 2", 0, "log no longer available (GitHub keeps logs 90 days by default)")])
        self.assertIn("repos/org/app/actions/runs/99/jobs?per_page=100", gh.calls)

    def test_candidates(self):
        f = {"actions": {"items": [{"path": ".github/workflows/deploy.yml", "secrets": ["ROLE"]},
                                   {"path": ".github/workflows/ci.yml", "secrets": []}]},
             "recent_runs": {"items": [{"id": 3, "path": ".github/workflows/deploy.yml"},
                                       {"id": 2, "path": ".github/workflows/deploy.yml"},
                                       {"id": 1, "path": ".github/workflows/ci.yml"}]}}
        worth = [{"id": 7, "path": ".github/workflows/x.yml"}, {"id": 3, "path": ".github/workflows/deploy.yml"}]
        self.assertEqual([r["id"] for r in run_logs.candidate_runs(f, worth)], [7, 3])  # worth first; latest deploy run once


if __name__ == "__main__":
    unittest.main()
