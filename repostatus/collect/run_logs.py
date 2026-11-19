"""Read workflow run logs for the deep dive's optional --logs check.

Each job's log is downloaded, scanned in memory (checks/log_scanner.py) and dropped straight away;
logs are never written to disk. GitHub keeps logs for 90 days by default; older ones are reported as
no longer available. Costs one call per run (its jobs) plus one per job (its log).
"""
from repostatus.checks.log_scanner import scan
from repostatus.github.api_client import ApiError

MAX_RUNS = 20
MAX_JOBS_PER_RUN = 10
MAX_LOG_CHARS = 50_000_000


def candidate_runs(f, worth_a_look):
    """The runs worth a look, then the latest run of each workflow that holds secrets: where a leak matters."""
    out, seen = [], set()
    secrets = {w["path"] for w in (f.get("actions") or {}).get("items") or [] if w.get("secrets")}
    latest = {}
    for r in (f.get("recent_runs") or {}).get("items") or []:  # newest first
        if r.get("path") in secrets and r.get("path") not in latest:
            latest[r["path"]] = r
    for r in list(worth_a_look) + list(latest.values()):
        if r.get("id") and r["id"] not in seen:
            seen.add(r["id"])
            out.append(r)
    return out[:MAX_RUNS]


def check_runs(gh, full, runs, log_strings=()):
    """[{run, job, job_url, findings, error}] for every job of the given runs."""
    results = []
    for run in runs[:MAX_RUNS]:
        jobs, err = gh.try_get(f"repos/{full}/actions/runs/{run['id']}/jobs?per_page=100")
        if err:
            results.append({"run": run, "job": None, "error": err, "findings": []})
            continue
        for job in ((jobs or {}).get("jobs") or [])[:MAX_JOBS_PER_RUN]:
            entry = {"run": run, "job": job.get("name"), "job_url": job.get("html_url"), "findings": [], "error": None}
            try:
                text = gh.get_text(f"repos/{full}/actions/jobs/{job['id']}/logs")
            except ApiError as e:
                entry["error"] = ("log no longer available (GitHub keeps logs 90 days by default)"
                                  if e.status in ("404", "410") else f"{e.status} {e.message[:80]}")
                results.append(entry)
                continue
            if len(text) > MAX_LOG_CHARS:
                entry["error"] = "log too large to scan"
            else:
                entry["findings"] = scan(text, log_strings)
            del text  # never kept
            results.append(entry)
    return results
