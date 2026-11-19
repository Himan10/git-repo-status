"""Scan the text of a workflow run log for secrets that GitHub's masking missed, and for known attack
indicators (iocs.yml log_strings). Pure: text in, findings out; the log is never stored.

GitHub replaces the values of registered secrets with *** in logs. What gets past that:
  - token-shaped strings that were never registered as secrets (or were built at run time)
  - secrets that were encoded first: the tj-actions/changed-files attack printed them base64-encoded twice
Findings are masked: only the kind, the first 4 and the last 4 characters are ever shown.
"""
import base64
import binascii
import re

TOKENS = [
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("GitHub fine-grained token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("AWS access key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("npm token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("private key", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----)")),
]
BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z ")
STEP = re.compile(r"^##\[group\](?:Run )?(.+)$")
MAX_FINDINGS = 50


def mask(value):
    if value.startswith("-----BEGIN"):
        return value
    return f"{value[:4]}...{value[-4:]}" if len(value) > 12 else "****"


def _decode(blob):
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8", "strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _tokens(text):
    return [(kind, m.group(1)) for kind, rx in TOKENS for m in rx.finditer(text)]


def scan(text, log_strings=()):
    """[(line number, step, kind, masked detail)] for one job's log."""
    out, step, seen = [], None, set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = TIMESTAMP.sub("", raw)
        m = STEP.match(line)
        if m:
            step = m.group(1)[:80]
            continue
        found = [(kind, f"{kind} {mask(v)}, not masked by GitHub") for kind, v in _tokens(line)]
        for blob in BASE64.findall(line):
            once = _decode(blob)
            if not once:
                continue
            twice = _decode(re.sub(r"\s", "", once)) if BASE64.fullmatch(re.sub(r"\s", "", once) or "-") else None
            for layer, decoded in (("base64", once), ("base64 twice", twice)):
                for kind, v in _tokens(decoded or ""):
                    found.append((f"encoded {kind}", f"{kind} {mask(v)} hidden in {layer} text, which log masking misses"))
        for s in log_strings:
            if s in line:
                found.append(("attack indicator", f"'{s}' (known attack indicator, iocs.yml)"))
        for kind, detail in found:
            key = (kind, detail)
            if key not in seen:
                seen.add(key)
                out.append((n, step, kind, detail))
        if len(out) >= MAX_FINDINGS:
            break
    return out
