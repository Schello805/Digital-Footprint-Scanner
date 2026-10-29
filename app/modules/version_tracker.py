import os
import subprocess
import time
import httpx
from typing import Dict, Any, Optional

GITHUB_REPO_URL = "https://github.com/Schello805/Digital-Footprint-Scanner"
GITHUB_API_COMMITS = "https://api.github.com/repos/Schello805/Digital-Footprint-Scanner/commits/main"

# In-memory cache for GitHub API update checks (valid for 180 seconds to prevent rate limiting)
_update_cache: Dict[str, Any] = {
    "timestamp": 0,
    "data": None
}

def get_local_revision() -> Dict[str, Any]:
    """
    Returns the current local revision number and short git commit hash.
    Uses git rev-list --count HEAD if in a git repository, with a fallback to the static VERSION file.
    """
    repo_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    version_file = os.path.join(repo_dir, "VERSION")
    
    rev_count = None
    commit_hash = None

    # Method 1: Query git CLI
    try:
        count_out = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=repo_dir,
            stderr=subprocess.DEVNULL
        ).decode().strip()
        hash_out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir,
            stderr=subprocess.DEVNULL
        ).decode().strip()

        if count_out.isdigit():
            rev_count = int(count_out)
        commit_hash = hash_out
    except Exception:
        pass

    # Method 2: Fallback to static VERSION file
    if rev_count is None and os.path.exists(version_file):
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                # Parse format like "r20 (4cc4d08)" or "r20" or "20"
                parts = content.replace("r", "").replace("Rev.", "").strip().split()
                if parts and parts[0].isdigit():
                    rev_count = int(parts[0])
                if len(parts) > 1:
                    commit_hash = parts[1].strip("()")
        except Exception:
            pass

    # Default fallback
    rev_count = rev_count or 19
    commit_hash = commit_hash or "main"
    version_str = f"Rev. {rev_count} ({commit_hash})"

    return {
        "revision": rev_count,
        "commit": commit_hash,
        "version_str": version_str,
        "github_repo": GITHUB_REPO_URL
    }

async def check_for_updates() -> Dict[str, Any]:
    """
    Checks GitHub API to determine if a newer commit / revision is available on the main branch.
    Caches results for 3 minutes to avoid GitHub rate limits.
    """
    now = time.time()
    if _update_cache["data"] and (now - _update_cache["timestamp"] < 180):
        return _update_cache["data"]

    local_info = get_local_revision()
    local_commit = local_info["commit"]

    res_data = {
        "local": local_info,
        "update_available": False,
        "remote_commit": None,
        "remote_message": None,
        "remote_date": None,
        "checked_at": int(now),
        "check_error": None
    }

    try:
        headers = {
            "User-Agent": "Digital-Footprint-Scanner-UpdateChecker/1.0",
            "Accept": "application/vnd.github.v3+json"
        }
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(GITHUB_API_COMMITS, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                remote_sha = data.get("sha", "")
                remote_short = remote_sha[:7] if remote_sha else ""
                commit_info = data.get("commit", {})
                message = commit_info.get("message", "").splitlines()[0]
                date_str = commit_info.get("author", {}).get("date", "")

                res_data["remote_commit"] = remote_short
                res_data["remote_message"] = message
                res_data["remote_date"] = date_str

                # If local short hash is known and differs from remote short hash
                if local_commit != "main" and remote_short and local_commit != remote_short:
                    res_data["update_available"] = True
                else:
                    res_data["update_available"] = False
            elif resp.status_code == 403:
                res_data["check_error"] = "GitHub API Rate-Limit erreicht (später erneut versuchen)"
            else:
                res_data["check_error"] = f"GitHub API Status {resp.status_code}"
    except Exception as e:
        res_data["check_error"] = f"Verbindungsfehler zur Update-Prüfung: {str(e)}"

    _update_cache["timestamp"] = now
    _update_cache["data"] = res_data
    return res_data
