"""Read-only access to the GitHub API through the gh CLI.

Only GET requests and GraphQL queries are allowed. Anything else raises, so the
tool cannot change a repository even when the token has write scopes.
"""
import json
import re
import subprocess

_MUTATION = re.compile(r"^\s*mutation\b", re.IGNORECASE)


class ApiError(Exception):
    def __init__(self, path, status, message):
        super().__init__(f"{path}: HTTP {status} {message}")
        self.path, self.status, self.message = path, status, message


class GitHub:
    def __init__(self, recorder=None, counter=None):
        self.recorder = recorder  # callable(name, data) to keep raw evidence
        self._counter = counter if counter is not None else [0]

    @property
    def calls(self):
        return self._counter[0]

    def with_recorder(self, recorder):
        return GitHub(recorder, self._counter)

    def _run(self, args, path):
        self._counter[0] += 1
        p = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
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
        args = ["-X", "GET", "-H", "Accept: application/vnd.github+json", path]
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
        self._counter[0] += 1
        p = subprocess.run(["gh", "api", "-i", "-X", "GET", "user"], capture_output=True, text=True)
        h = {k.strip().lower(): v.strip() for k, _, v in
             (line.partition(":") for line in p.stdout.split("\r\n\r\n")[0].splitlines()) if v}
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
        args = ["graphql", "-f", f"query={query}"]
        for k, v in variables.items():
            args += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
        data = self._run(args, "graphql")
        if self.recorder and record:
            self.recorder(record, data)
        return data["data"]
