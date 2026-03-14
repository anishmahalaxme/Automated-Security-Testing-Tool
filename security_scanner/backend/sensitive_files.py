"""
Sensitive file discovery module.

Security purpose:
- Detect exposure of common sensitive paths like /robots.txt, /.git, /.env, /admin.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin

import requests

from utils.helpers import normalize_url


SENSITIVE_PATHS = [
    "/robots.txt",
    "/.git",
    "/.env",
    "/admin",
]


def discover_sensitive_files(target_url: str, timeout: float = 5.0) -> List[Dict[str, str]]:
    """
    Attempt to access common sensitive files/paths.

    Returns a list of vulnerability dicts with severity LOW
    when an HTTP 200 is received for a sensitive path.
    """
    findings: List[Dict[str, str]] = []
    base_url = normalize_url(target_url)

    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, timeout=timeout)
        except requests.RequestException:
            continue

        if response.status_code == 200:
            findings.append(
                {
                    "type": "Sensitive File Exposed",
                    "severity": "LOW",
                    "path": path,
                    "message": f"Sensitive file exposed: {path}",
                }
            )

    return findings
