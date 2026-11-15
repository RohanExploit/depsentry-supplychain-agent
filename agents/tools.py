"""Keyless live supply-chain sensors: PyPI JSON, Google OSV.dev Batch API, and GitHub."""

from __future__ import annotations

import re
from typing import Any

import requests

HEADERS = {"User-Agent": "DepSentry-SupplyChain-Agent/1.0"}
POPULAR_PYPI = [
    "requests",
    "urllib3",
    "pillow",
    "numpy",
    "pandas",
    "fastapi",
    "flask",
    "django",
    "pydantic",
    "streamlit",
    "cryptography",
    "pyyaml",
    "jinja2",
    "aiohttp",
]


def parse_requirements_text(raw_text: str) -> list[dict[str, str]]:
    """Parse pip requirements lines into structured package name + pinned version specs."""
    parsed: list[dict[str, str]] = []
    for line in raw_text.splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean or clean.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]+)?", clean)
        if not match:
            continue
        name = match.group(1).lower().replace("_", "-")
        op = match.group(2) or ""
        ver = match.group(3) or ""
        parsed.append({"name": name, "operator": op, "pinned_version": ver, "raw": clean})
    return parsed[:25]


def fetch_github_requirements(repo_slug: str, timeout: float = 5.0) -> str | None:
    """Try pulling requirements.txt directly from a public GitHub repository."""
    slug = repo_slug.strip().strip("/")
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{slug}/{branch}/requirements.txt"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=timeout)
            if resp.status_code == 200 and len(resp.text.strip()) > 3:
                return resp.text
        except Exception:
            continue
    return None


def fetch_pypi_metadata(package_name: str, timeout: float = 4.5) -> dict[str, Any]:
    """Query PyPI JSON API for latest version, license, author count, and repo URL."""
    try:
        resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        latest = info.get("version", "unknown")
        releases = data.get("releases", {})
        latest_files = releases.get(latest, [])
        upload_date = latest_files[0].get("upload_time_iso_8601", "")[:10] if latest_files else ""
        project_urls = info.get("project_urls") or {}
        gh_url = next((v for v in project_urls.values() if isinstance(v, str) and "github.com/" in v.lower()), "")
        return {
            "name": package_name,
            "latest_version": latest,
            "license": (info.get("license") or "See Classifier")[:40],
            "author": (info.get("author") or info.get("maintainer") or "Unknown")[:40],
            "release_count": len(releases),
            "latest_release_date": upload_date,
            "github_url": gh_url,
            "source": "live-pypi-json",
        }
    except Exception as exc:
        return {
            "name": package_name,
            "latest_version": "unknown",
            "license": "Unknown",
            "author": "Unknown",
            "release_count": 0,
            "latest_release_date": "",
            "github_url": "",
            "source": f"pypi-backup ({type(exc).__name__})",
        }


def query_osv_batch(packages: list[dict[str, str]], timeout: float = 6.0) -> dict[str, list[dict[str, str]]]:
    """Query Google OSV.dev batch API for real CVEs affecting package versions."""
    queries = []
    valid_names = []
    for pkg in packages:
        q: dict[str, Any] = {"package": {"name": pkg["name"], "ecosystem": "PyPI"}}
        if pkg.get("pinned_version"):
            q["version"] = pkg["pinned_version"]
        queries.append(q)
        valid_names.append(pkg["name"])

    if not queries:
        return {}
    try:
        resp = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries}, headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out: dict[str, list[dict[str, str]]] = {}
        for name, res in zip(valid_names, results):
            vulns = res.get("vulns", [])
            out[name] = [
                {"id": v.get("id", "OSV-UNKNOWN"), "modified": (v.get("modified") or "")[:10]}
                for v in vulns[:8]
            ]
        return out
    except Exception:
        return {name: [] for name in valid_names}


def levenshtein_distance(a: str, b: str) -> int:
    """Compute edit distance to flag potential PyPI typosquatting."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]
