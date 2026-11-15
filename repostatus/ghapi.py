"""Read-only access to the GitHub API through the gh CLI.

Only GET requests and GraphQL queries are allowed. Anything else raises, so the
tool cannot change a repository even when the token has write scopes.

Works the same on macOS, Linux and Windows:
  - query parameters are passed as separate -f fields, never as "?a=1&b=2" in an
    argument, because Windows cmd.exe treats & as "start another command";
  - GraphQL queries are sent on standard input, not as a multi-line argument;
  - gh output is always read as UTF-8, whatever the system's default encoding.
"""
import json
import re
import shutil
import subprocess
from urllib.parse import parse_qsl

_MUTATION = re.compile(r"^\s*mutation\b", re.IGNORECASE)


class ApiError(Exception):
    def __init__(self, path, status, message):
        super().__init__(f"{path}: HTTP {status} {message}")
        self.path, self.status, self.message = path, status, message


def gh_path():
    """Full path of the gh executable, or None if it is not installed."""
    return shutil.which("gh")


def split_query(path):
    """'repos/x/activity?ref=main&per_page=30' -> ('repos/x/activity', ['-f', 'ref=main', '-f', 'per_page=30'])"""
    endpoint, _, query = path.partition("?")
    fields = []
    for k, v in parse_qsl(query, keep_blank_values=True):
        fields += ["-f", f"{k}={v}"]
    return endpoint, fields


class GitHub:
    def __init__(self, recorder=None, counter=None):
        self.recorder = recorder  # callable(name, data) to keep raw evidence
        self._counter = counter if counter is not None else [0]
        self._gh = gh_path() or "gh"

    @property
    def calls(self):
        return self._counter[0]

    def with_recorder(self, recorder):
        return GitHub(recorder, self._counter)

    def _exec(self, args, stdin=None):
        self._counter[0] += 1
        return subprocess.run([self._gh, "api", *args], input=stdin, capture_output=True,
                              text=True, encoding="utf-8", errors="replace")

    def _run(self, args, path, stdin=None):
        p = self._exec(args, stdin)
        if p.returncode != 0:
            status, message = "?", (p.stderr or p.stdout).strip()
            try:
                body = json.loads(p.stdout)
                message = body.get("message", message)
                status = body.get("status", status)
            except (ValueError, AttributeError):
                pass
            m = re.search(r"HTTP (\d{3})", p.stderr)
            if m:
                status = m.group(1)
            raise ApiError(path, str(status), message)
        return json.loads(p.stdout) if p.stdout.strip() else None

    def get(self, path, paginate=False, record=None):
        endpoint, fields = split_query(path)
        args = ["-X", "GET", "-H", "Accept: application/vnd.github+json", endpoint, *fields]
        if paginate:
            args[0:0] = ["--paginate", "--slurp"]
        data = self._run(args, path)
        if paginate:
            data = [item for page in data for item in (page if isinstance(page, list) else [page])]
        if self.recorder and record:
            self.recorder(record, data)
        return data

    def rate_limit(self):
        """Remaining REST calls this hour, read from the headers of a real request.
        The /rate_limit endpoint was seen reporting a full allowance while headers showed calls used."""
        p = self._exec(["-i", "-X", "GET", "user"])
        head = re.split(r"\r?\n\r?\n", p.stdout, maxsplit=1)[0]
        h = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in head.splitlines()) if v}
        return {"limit": int(h.get("x-ratelimit-limit", 0)), "remaining": int(h.get("x-ratelimit-remaining", 0)),
                "reset": int(h.get("x-ratelimit-reset", 0))}

    def try_get(self, path, paginate=False, record=None):
        """Like get(), but returns (data, error_status) instead of raising."""
        try:
            return self.get(path, paginate, record), None
        except ApiError as e:
            return None, f"{e.status} {e.message}"[:120]

    def graphql(self, query, record=None, **variables):
        if _MUTATION.match(query):
            raise ValueError("GraphQL mutations are not allowed")
        args = ["graphql", "-F", "query=@-"]  # query text read from standard input
        for k, v in variables.items():
            args += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
        data = self._run(args, "graphql", stdin=query)
        if self.recorder and record:
            self.recorder(record, data)
        return data["data"]
