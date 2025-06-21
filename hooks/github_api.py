import requests
import os
import logging
import re

log = logging.getLogger('mkdocs')
GITHUB_REPO = "OWASP/owasp-mastg"

# GitHub API Token for Authentication
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_TOKEN_WARNING = False
GITHUB_TOKEN_LOGGED = False

def log_github_token_warning():
    log.warning("\n⚠️  GitHub Token not set. Some features will be limited.")
    log.warning("To fix this issue, please set the GITHUB_TOKEN environment variable:")
    log.warning("export GITHUB_TOKEN=your_github_token_here")
    log.warning("You can create a token at: https://github.com/settings/tokens\n")


def log_github_token_invalid_warning(e):
    if hasattr(e.response, 'status_code') and e.response.status_code == 401:
        log.warning("\n⚠️  GitHub Token is invalid or expired. Some features will be limited.")
        log.warning("To fix this issue, please update your GITHUB_TOKEN environment variable.")
        log.warning("You can create a new token at: https://github.com/settings/tokens\n")
    else:
        log.warning(f"\n⚠️  Error accessing GitHub API: {e}")

def get_issues_for_test_refactors():
    SEARCH_URL = "https://api.github.com/search/issues"
    query = (
        f'repo:{GITHUB_REPO} '
        f'in:body '
        f'is:issue '
        f'state:open '
        f'label:"MASTG Refactor"'
        f'MASTG v1->v2 MASTG-TEST-'
    )

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    issues = {}
    page = 1
    try:
        while True:

            resp = requests.get(SEARCH_URL, headers=headers, params={"q": query, "per_page": 100, "page": page})
            resp.raise_for_status()
            data = resp.json()

            for issue in data["items"]:
                match = re.search(r'MASTG-TEST-\d+', issue["title"])
                if match:
                    ID = match.group(0)
                    issues[ID] = (issue["html_url"], issue["title"])
                else:
                    log.warning(f"Could not find MASTG-TEST ID in issue title: {issue['title']}")

            # Break if there are no more pages
            if "next" not in resp.links:
                break
            page += 1
    except Exception as e:
        log.warning("⚠️ Connection Error, skipping GitHub API Requests")

    return issues

def get_latest_successful_run(workflow_file, branch="master"):
    """Get the URL to the latest successful workflow run artifacts.
    Returns None if token is missing/invalid or if no successful run is found.
    """
    global GITHUB_TOKEN_WARNING
    global GITHUB_TOKEN_LOGGED

    # Check if token exists
    if not GITHUB_TOKEN:
        if not GITHUB_TOKEN_WARNING:
            log_github_token_warning()
            GITHUB_TOKEN_WARNING = True  # Only show the warning once
        return None

    if not GITHUB_TOKEN_LOGGED:
        log.info("✅ GitHub Token detected in environment variables.")
        GITHUB_TOKEN_LOGGED = True  # Only show the log once

    # GitHub API headers
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

    # Try to fetch data from GitHub API
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/{workflow_file}/runs"
        params = {"status": "success", "branch": branch, "per_page": 1}
        response = requests.get(url, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        runs = response.json().get("workflow_runs", [])
        if runs:
            return f"{runs[0]['html_url']}#artifacts"
        else:
            return None

    except requests.exceptions.RequestException as e:
        if not GITHUB_TOKEN_WARNING:
            log_github_token_invalid_warning(e)
            GITHUB_TOKEN_WARNING = True  # Only show the warning once
        return None