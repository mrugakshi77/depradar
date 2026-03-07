import httpx
import logging
import re
from typing import Optional, Tuple
from app.core.config import settings

logger = logging.getLogger(__name__)

# Matches https://github.com/owner/repo  (with optional .git, trailing slash, or /tree/branch)
_GITHUB_URL_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git|/.*)?$"
)


def parse_github_url(url: str) -> Tuple[str, str]:
    """
    Extract (owner, repo) from a GitHub URL.
    Raises ValueError if the URL is not a valid GitHub repo URL.
    """
    m = _GITHUB_URL_RE.match(url.strip().rstrip("/"))
    if not m:
        raise ValueError(
            f"Invalid GitHub URL: '{url}'. "
            "Expected format: https://github.com/owner/repo"
        )
    return m.group(1), m.group(2)


def _build_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
    return headers


async def get_default_branch(owner: str, repo: str) -> str:
    """Hit the GitHub Repos API to find the default branch."""
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(
                f"{settings.GITHUB_API_BASE}/repos/{owner}/{repo}",
                headers=_build_headers(),
                timeout=10.0,
            )
            if r.status_code == 404:
                raise ValueError(f"Repository '{owner}/{repo}' not found or is private.")
            if r.status_code == 403:
                raise ValueError("GitHub rate limit hit. Set GITHUB_TOKEN in .env to increase limits.")
            r.raise_for_status()
            return r.json().get("default_branch", "main")
        except httpx.HTTPError as e:
            raise ValueError(f"GitHub API error: {e}")


async def fetch_requirements_from_github(
    owner: str,
    repo: str,
    ref: Optional[str],
    requirements_path: str,
) -> str:
    """
    Fetch raw requirements file content from GitHub.
    Returns the file content as a string.
    Raises ValueError with a human-readable message on any failure.
    """
    # Resolve ref to default branch if not provided
    if not ref:
        ref = await get_default_branch(owner, repo)

    # Clean path
    path = requirements_path.lstrip("/")
    raw_url = f"{settings.GITHUB_RAW_BASE}/{owner}/{repo}/{ref}/{path}"

    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(raw_url, timeout=10.0, follow_redirects=True)
            if r.status_code == 404:
                raise ValueError(
                    f"File '{path}' not found in {owner}/{repo} at ref '{ref}'. "
                    "Check the requirements_path and ref parameters."
                )
            r.raise_for_status()
            return r.text
        except httpx.HTTPError as e:
            raise ValueError(f"Failed to fetch file from GitHub: {e}")


async def check_github_reachability() -> str:
    """Returns 'ok' or an error string."""
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(
                f"{settings.GITHUB_API_BASE}/rate_limit",
                headers=_build_headers(),
                timeout=5.0,
            )
            if r.status_code == 200:
                data = r.json()
                remaining = data.get("rate", {}).get("remaining", "?")
                return f"ok ({remaining} req remaining)"
            return f"http {r.status_code}"
        except Exception as e:
            return f"error: {e}"
