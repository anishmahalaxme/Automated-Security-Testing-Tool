"""
Basic reflected XSS testing module.

Security purpose:
- Probe whether user-controlled input is reflected unsafely in responses,
  indicating a potential reflected XSS vulnerability.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlencode, urlparse, urlunparse

import requests

from utils.helpers import normalize_url


XSS_PAYLOAD = "<script>alert(1)</script>"


def _build_xss_url(target_url: str) -> str:
    """
    Build a URL with a simple query parameter carrying the XSS payload.
    """
    base = normalize_url(target_url)
    parsed = urlparse(base)
    query = urlencode({"xss_test": XSS_PAYLOAD})
    new_parsed = parsed._replace(query=query)
    return urlunparse(new_parsed)


def test_reflected_xss(target_url: str, timeout: float = 5.0) -> List[Dict[str, str]]:
    """
    Perform a very simple reflected XSS test.

    Sends a request with a script payload in a query parameter and checks
    whether the raw payload string is reflected in the response body.

    Returns a list with a single HIGH severity finding if detected.
    """
    findings: List[Dict[str, str]] = []
    url = _build_xss_url(target_url)

    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException:
        return findings

    if XSS_PAYLOAD in response.text:
        findings.append(
            {
                "type": "Reflected XSS",
                "severity": "HIGH",
                "parameter": "xss_test",
                "message": "Possible reflected XSS vulnerability detected",
            }
        )

    return findings
