"""Save each finished repository while a scan runs, so a scan that stops can be resumed (--resume).

Files live in out/<owner>/progress/ only while a scan is running or after it stopped; the folder is
removed when the scan completes.
"""
import json
import os
import shutil
import threading
from datetime import datetime


class Progress:
    """Finished repositories of the current scan, saved one file each in out/<owner>/progress/."""

    def __init__(self, owner_dir, resume):
        self.dir = os.path.join(owner_dir, "progress")
        self.meta_path = os.path.join(self.dir, "scan.json")
        self.done = {}
        self.started = None
        self.earlier_calls = 0  # API calls made by earlier sessions of this scan
        if resume and os.path.exists(self.meta_path):
            with open(self.meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
            self.started, self.earlier_calls = meta.get("started_at"), meta.get("api_calls", 0)
            for name in os.listdir(self.dir):
                if name.endswith(".repo.json"):
                    with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
                        f = json.load(fh)
                    self.done[f["repo"]] = f
        else:
            shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, exist_ok=True)
        if not self.started:
            self.started = datetime.now().astimezone().isoformat()
            with open(self.meta_path, "w", encoding="utf-8") as fh:
                json.dump({"started_at": self.started}, fh)
        self._lock = threading.Lock()

    def save(self, f):
        """Write one repository's facts; written to a temporary file first so a crash never leaves half a file."""
        with self._lock:
            path = os.path.join(self.dir, f"{_safe(f['repo'])}.repo.json")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(f, fh)
            os.replace(tmp, path)
            self.done[f["repo"]] = f

    def record_calls(self, calls):
        """Called when a session stops, so the finished report counts every session's calls."""
        with open(self.meta_path, "w", encoding="utf-8") as fh:
            json.dump({"started_at": self.started, "api_calls": self.earlier_calls + calls}, fh)

    def finish(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def _safe(name):
    """A file name every OS accepts, never hidden (a repository can be called .github)."""
    return "r-" + "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
