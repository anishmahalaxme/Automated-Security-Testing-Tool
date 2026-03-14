"""
Security headers checking module.

Security purpose:
- Verify presence of important HTTP security headers to mitigate attacks like XSS and clickjacking.
"""

from __future__ import annotations

from typing import Dict, List

import requests

from utils.helpers import normalize_url


REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
]


def check_security_headers(target_url: str, timeout: float = 5.0) -> List[Dict[str, str]]:
    """
    Check for presence of important HTTP security headers.

    Returns a list of vulnerability dicts with severity MEDIUM
    for each missing header.
    """
    findings: List[Dict[str, str]] = []
    url = normalize_url(target_url)

    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException:
        # If the request fails, we cannot evaluate headers
        return findings

    headers = response.headers
    for header in REQUIRED_HEADERS:
        if header not in headers:
            findings.append(
                {
                    "type": "Missing Security Header",
                    "severity": "MEDIUM",
                    "header": header,
                    "message": f"Missing security header: {header}",
                }
            )

    return findings
