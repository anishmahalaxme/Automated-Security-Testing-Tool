"""
IDOR (Insecure Direct Object Reference) parameter manipulation module.

Security purpose:
- Heuristically detect *possible* IDOR risks by changing numeric
  object reference parameters in the URL and observing response changes.

IMPORTANT:
- This technique cannot *confirm* IDOR vulnerabilities, especially where
  authentication/authorization is required. It only flags suspicious
  behavior that may warrant manual review.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from utils.helpers import normalize_url


IDOR_PARAM_NAMES = {
    "id",
    "user_id",
    "account_id",
    "profile_id",
    "order_id",
}


def test_idor(url: str, timeout: float = 5.0) -> List[Dict[str, str]]:
    """
    Test for *possible* IDOR risks by manipulating numeric parameters.

    Detection logic:
    - Parse query parameters from the URL.
    - For parameters with names like id, user_id, account_id, profile_id, order_id
      and numeric values:
        * Send baseline request to the original URL.
        * Increment the numeric value by +1 and send a new request.
        * If status remains 200 but response length changes, flag as a
          possible IDOR risk.

    Returns MEDIUM severity findings. These are NOT confirmations of IDOR,
    only indications that manual, authenticated testing is needed.
    """
    findings: List[Dict[str, str]] = []
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    if not parsed.query:
        return findings

    query = parse_qs(parsed.query, keep_blank_values=True)
    candidate_params = {
        name: values
        for name, values in query.items()
        if name in IDOR_PARAM_NAMES and values
    }

    if not candidate_params:
        return findings

    try:
        baseline_resp = requests.get(normalized, timeout=timeout)
    except requests.RequestException:
        # Cannot establish a baseline; skip IDOR testing
        return findings

    baseline_status = baseline_resp.status_code
    baseline_len = len(baseline_resp.text or "")

    if baseline_status != 200:
        # If the original request is not successful, we cannot reliably compare
        return findings

    for name, values in candidate_params.items():
        original_value = values[0]
        try:
            numeric_value = int(original_value)
        except (TypeError, ValueError):
            continue

        new_value = str(numeric_value + 1)

        modified_qs = query.copy()
        modified_qs[name] = [new_value]
        new_query = urlencode(modified_qs, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))

        try:
            modified_resp = requests.get(modified_url, timeout=timeout)
        except requests.RequestException:
            continue

        if modified_resp.status_code == 200:
            modified_len = len(modified_resp.text or "")

            if modified_len != baseline_len:
                findings.append(
                    {
                        "type": "Possible IDOR Risk",
                        "severity": "MEDIUM",
                        "parameter": name,
                        "tested_url": modified_url,
                        "message": f"Possible IDOR risk detected for parameter: {name}",
                    }
                )

    return findings

