"""Command lines sent to gh must be safe on Windows: cmd.exe treats & as a command separator,
so no argument may contain "?" or "&", and the multi-line GraphQL query goes on standard input.

  uv run --python 3.12 --with pyyaml python -m unittest discover -s tests
"""
import subprocess
import unittest
from unittest import mock

from repostatus import ghapi
from repostatus.collect import HISTORY_QUERY


class Captured:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, stdout='{"data": {}}' if "graphql" in argv else "[]", stderr="")


class CommandLines(unittest.TestCase):
    def setUp(self):
        self.cap = Captured()
        patcher = mock.patch.object(ghapi.subprocess, "run", self.cap)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gh = ghapi.GitHub()

    def argv(self):
        return self.cap.calls[-1][0]

    def test_query_string_becomes_fields(self):
        self.gh.get("repos/o/r/activity?ref=feat%2Fx&per_page=30")
        argv = self.argv()
        self.assertIn("repos/o/r/activity", argv)
        self.assertIn("ref=feat/x", argv)
        self.assertIn("per_page=30", argv)
        self.assertFalse([a for a in argv if "?" in a or "&" in a], argv)

    def test_paginated_get_has_no_query_string(self):
        self.gh.get("orgs/o/repos?type=all&per_page=100", paginate=True)
        argv = self.argv()
        self.assertIn("--paginate", argv)
        self.assertFalse([a for a in argv if "?" in a or "&" in a], argv)

    def test_path_without_query(self):
        self.gh.get("repos/o/r/branches/main/protection")
        self.assertEqual(self.argv()[-1], "repos/o/r/branches/main/protection")

    def test_graphql_query_on_stdin(self):
        self.gh.graphql(HISTORY_QUERY, owner="o", name="r", n=50)
        argv, kw = self.cap.calls[-1]
        self.assertEqual(kw["input"], HISTORY_QUERY)
        self.assertIn("query=@-", argv)
        self.assertFalse([a for a in argv if "\n" in a or "{" in a], argv)
        self.assertIn("n=50", argv)

    def test_output_read_as_utf8(self):
        self.gh.get("user")
        kw = self.cap.calls[-1][1]
        self.assertEqual(kw["encoding"], "utf-8")

    def test_mutation_refused(self):
        with self.assertRaises(ValueError):
            self.gh.graphql("mutation { deleteRepository }")
        self.assertEqual(self.cap.calls, [])


class RateLimitHeaders(unittest.TestCase):
    def test_parses_crlf_and_lf(self):
        for nl in ("\r\n", "\n"):
            out = nl.join(["HTTP/2.0 200 OK", "X-Ratelimit-Limit: 5000", "X-Ratelimit-Remaining: 4321",
                           "X-Ratelimit-Reset: 1700000000", "", '{"login":"x"}'])
            with mock.patch.object(ghapi.subprocess, "run",
                                   return_value=subprocess.CompletedProcess([], 0, stdout=out, stderr="")):
                self.assertEqual(ghapi.GitHub().rate_limit()["remaining"], 4321)


if __name__ == "__main__":
    unittest.main()
