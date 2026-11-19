"""Where results are written: the out/ folder at the project root, one folder per organisation or account.

Shared by the scan, the deep dive and the incident lookup.
"""
import os
import re
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNSAFE_NAME = re.compile(r'[<>:"\\|?*\x00-\x1f]')  # characters Windows does not allow in file names


def display_path(path):
    """Path relative to the current folder when possible (fails across Windows drives)."""
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def out_dir(owner, create=True):
    """Results folder for an owner. Names are matched without regard to case, so
    'acme-corp' finds out/ACME-Corp on any operating system."""
    base = os.path.join(PROJECT_ROOT, "out")
    if os.path.isdir(base):
        for name in os.listdir(base):
            if name.lower() == owner.lower() and os.path.isdir(os.path.join(base, name)):
                return os.path.join(base, name)
    d = os.path.join(base, owner)
    if create:
        os.makedirs(d, exist_ok=True)
    return d


def make_saver(base):
    """save(path, text) writing a repo's files under base, byte for byte (zizmor reports line numbers).
    Starts from an empty folder so files deleted upstream do not linger from an earlier scan."""
    shutil.rmtree(base, ignore_errors=True)

    def save(path, text):
        parts = path.split("/")
        if any(p in ("", ".", "..") or UNSAFE_NAME.search(p) for p in parts):
            return False  # never write outside the folder; skip names Windows cannot store
        target = os.path.join(base, *parts)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return True
    return save
