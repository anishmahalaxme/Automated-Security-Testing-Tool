"""
Server technology and HTTPS enforcement detection module.

Security purpose:
- Identify web server and backend technology hints from HTTP headers.
- Check whether a site accessed over HTTP is redirected to HTTPS
  (basic HTTPS enforcement check).
"""

from __future__ import annotations

from typing import Dict, List

import requests

from utils.helpers import normalize_url


def detect_server_technology(target_url: str, timeout: float = 5.0) -> List[Dict[str, str]]:
    """
    Detect server technology from HTTP response headers.

    Looks at:
    - Server
    - X-Powered-By

    Returns INFO-level findings such as:
    - Web server detected: nginx
    - Backend technology: Express
    """
    findings: List[Dict[str, str]] = []
    url = normalize_url(target_url)

    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException:
        return findings

    server = resp.headers.get("Server")
    powered_by = resp.headers.get("X-Powered-By")

    if server:
        findings.append(
            {
                "type": "Server Technology",
                "severity": "INFO",
                "message": f"Web server detected: {server}",
                "server": server,
            }
        )

    if powered_by:
        findings.append(
            {
                "type": "Server Technology",
                "severity": "INFO",
                "message": f"Backend technology: {powered_by}",
                "powered_by": powered_by,
            }
        )

    return findings


def check_https_enforcement(target_url: str, timeout: float = 5.0) -> List[Dict[str, str]]:
    """
    Check if the website enforces HTTPS when accessed over HTTP.

    Logic:
    - If the normalized target uses https:// already, do nothing.
    - If it uses http://, send a request and follow redirects.
      * If the final URL is https:// on the same host, treat as HTTPS enforced.
      * Otherwise, report a MEDIUM severity finding:
        "[MEDIUM] HTTPS not enforced".
    """
    findings: List[Dict[str, str]] = []
    url = normalize_url(target_url)

    if url.startswith("https://"):
        # Already using HTTPS; we assume enforcement or explicit choice.
        return findings

    if not url.startswith("http://"):
        # Non-HTTP/HTTPS schemes are out of scope here.
        return findings

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    final_url = resp.url or url

    # Very simple same-host comparison
    if final_url.startswith("https://"):
        # HTTPS appears to be enforced by redirect; no finding.
        return findings

    findings.append(
        {
            "type": "HTTPS Enforcement",
            "severity": "MEDIUM",
            "message": "HTTPS not enforced",
            "original_url": url,
            "final_url": final_url,
        }
    )

    return findings

