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
import os
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


def gh_token():
    """The token gh uses (GH_TOKEN, GITHUB_TOKEN, or the gh login), for zizmor's online audits. None if absent.
    Passed only in zizmor's own environment, never on a command line or to disk."""
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if t:
        return t
    exe = gh_path()
    if not exe:
        return None
    p = subprocess.run([exe, "auth", "token"], capture_output=True, encoding="utf-8", errors="replace")
    return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None


def split_query(path):
    """'repos/x/activity?ref=main&per_page=30' -> ('repos/x/activity', ['-f', 'ref=main', '-f', 'per_page=30'])"""
    endpoint, _, query = path.partition("?")
    fields = []
    for k, v in parse_qsl(query, keep_blank_values=True):
        fields += ["-f", f"{k}={v}"]
    return endpoint, fields


def is_rate_limit(status, message):
    """GitHub's answer when the hourly allowance or the per-minute limit is used up (403 or 429)."""
    return str(status) == "429" or "rate limit" in (message or "").lower()


class GitHub:
    def __init__(self, recorder=None, counter=None, hits=None):
        self.recorder = recorder  # callable(name, data) to keep raw evidence
        self._counter = counter if counter is not None else [0]
        self._hits = hits if hits is not None else [0]  # rate-limit refusals seen by this client
        self._gh = gh_path() or "gh"

    @property
    def calls(self):
        return self._counter[0]

    @property
    def rate_limited(self):
        return self._hits[0]

    def with_recorder(self, recorder):
        return GitHub(recorder, self._counter, self._hits)

    def fork(self):
        """Same call counter, own rate-limit record: one per repository, so a refusal is retried
        for the repository it happened in."""
        return GitHub(self.recorder, self._counter)

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
            if is_rate_limit(status, message):
                self._hits[0] += 1
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

    def get_text(self, path):
        """A plain-text download, such as a job log. GitHub answers with a redirect to its log storage,
        which gh follows; the token is not sent there (the link itself carries a short-lived signature)."""
        endpoint, fields = split_query(path)
        p = self._exec(["-X", "GET", endpoint, *fields])
        if p.returncode != 0:
            m = re.search(r"HTTP (\d{3})", p.stderr)
            status = m.group(1) if m else "?"
            if is_rate_limit(status, p.stderr):
                self._hits[0] += 1
            raise ApiError(path, status, (p.stderr or "").strip()[:200])
        return p.stdout

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

    def graphql_partial(self, query, record=None, **variables):
        """Like graphql(), but keeps the data when GitHub also returns errors for some fields
        (e.g. "Could not resolve file" for branches without the path). gh exits non-zero then.
        Returns (data, errors); raises ApiError only when no data came back at all."""
        if _MUTATION.match(query):
            raise ValueError("GraphQL mutations are not allowed")
        args = ["graphql", "-F", "query=@-"]
        for k, v in variables.items():
            if v is not None:
                args += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
        p = self._exec(args, stdin=query)
        try:
            body = json.loads(p.stdout) if p.stdout.strip() else {}
        except ValueError:
            body = {}
        if not body.get("data"):
            if p.returncode == 0:
                return {}, []
            message = (body.get("errors") or [{}])[0].get("message") or p.stderr.strip()[:200]
            if is_rate_limit("?", message) or any(e.get("type") == "RATE_LIMITED" for e in body.get("errors") or []):
                self._hits[0] += 1
            raise ApiError("graphql", "?", message)
        if self.recorder and record:
            self.recorder(record, body)
        return body["data"], body.get("errors") or []
