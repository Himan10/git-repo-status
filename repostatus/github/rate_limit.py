"""Keep a long scan inside GitHub's hourly API allowance.

GitHub allows a fixed number of REST calls per hour (5,000 for a personal token, 15,000 for apps on
GitHub Enterprise Cloud). A scan of a few hundred repositories needs more than one hour's worth, so
instead of failing when the allowance runs out, the scan pauses until GitHub resets it and continues.
Saving finished repositories so a stopped scan can resume is in collect/scan_progress.py.
"""
import sys
import threading
import time
from datetime import datetime

PER_WORKER_RESERVE = 100  # calls kept back per parallel worker, so repos already started can finish


class Pacer:
    """Call before() before each repository (or each lookup). It blocks while the allowance is low.

    The remaining allowance is estimated locally (GitHub's last answer minus the calls made since),
    so GitHub is only asked again when the estimate gets close to the reserve."""

    def __init__(self, gh, workers, sleep=time.sleep, now=time.time, log=None):
        self.gh = gh
        self.reserve = PER_WORKER_RESERVE * workers
        self.lock = threading.Lock()
        self.remaining = self.limit = self.reset = None
        self.calls_at = 0
        self.pauses, self.waited = 0, 0.0
        self._sleep, self._now = sleep, now
        self._log = log or (lambda msg: print(msg, file=sys.stderr))

    def refresh(self):
        rl = self.gh.rate_limit()
        self.remaining, self.limit, self.reset = rl["remaining"], rl["limit"], rl["reset"]
        self.calls_at = self.gh.calls
        return rl

    def estimate(self):
        return self.remaining - (self.gh.calls - self.calls_at)

    def before(self):
        with self.lock:
            if self.remaining is None or self.estimate() < 2 * self.reserve:
                self.refresh()
            while self.estimate() < self.reserve:
                wait = max(30.0, self.reset - self._now() + 5)
                self.pauses += 1
                self.waited += wait
                until = datetime.fromtimestamp(self._now() + wait).strftime("%H:%M")
                self._log(f"  API allowance low ({max(self.estimate(), 0)} of {self.limit} left). Waiting until "
                          f"{until} for GitHub's hourly reset; finished repositories are saved.")
                self._sleep(wait)
                self.refresh()

    def wait_after_refusal(self):
        """GitHub refused a call (hourly or per-minute limit): wait before trying that repository again."""
        with self.lock:
            self.refresh()
            wait = max(60.0, self.reset - self._now() + 5) if self.remaining < self.reserve else 60.0
            self.pauses += 1
            self.waited += wait
            self._log(f"  GitHub refused calls (rate limit). Waiting {wait / 60:.0f} minute(s) before retrying.")
            self._sleep(wait)
            self.refresh()
