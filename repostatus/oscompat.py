"""Small helpers so the same code behaves the same on Linux, macOS and Windows."""
import sys


def scan_cmd():
    """How a person starts Repo Status on this computer, for messages and reports."""
    return "scan" if sys.platform == "win32" else "./scan.sh"


def utf8_console():
    """Print non-ASCII names (people, commits) without crashing.

    Output redirected to a file or pipe on Windows uses a legacy code page by default."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
