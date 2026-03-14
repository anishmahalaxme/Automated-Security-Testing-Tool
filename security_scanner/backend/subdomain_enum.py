"""
Subdomain enumeration module.

Security purpose:
- Perform internal subdomain brute-force enumeration using a predefined
  wordlist of common subdomains as part of reconnaissance, to identify
  additional services and potential attack surfaces.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

import requests

from utils.helpers import normalize_url


SUBDOMAINS = [
    "www",
    "api",
    "admin",
    "dev",
    "test",
    "mail",
    "webmail",
    "blog",
    "portal",
    "dashboard",
    "app",
    "internal",
    "cdn",
    "static",
    "beta",
    "staging",
    "shop",
    "store",
    "support",
    "help",
    "auth",
    "login",
    "secure",
    "gateway",
    "m",
    "mobile",
    "img",
    "images",
    "assets",
    "files",
    "download",
    "upload",
    "backup",
    "data",
    "db",
    "database",
    "sql",
    "cache",
    "redis",
    "mongo",
    "api1",
    "api2",
    "v1",
    "v2",
    "old",
    "new",
    "stage",
    "prod",
    "production",
    "uat",
    "qa",
    "dev1",
    "dev2",
    "test1",
    "test2",
    "alpha",
    "beta2",
    "cms",
    "panel",
    "cpanel",
    "control",
    "console",
    "monitor",
    "metrics",
    "logs",
    "log",
    "status",
    "health",
    "node",
    "cluster",
    "proxy",
    "lb",
    "loadbalancer",
    "edge",
    "cdn1",
    "cdn2",
    "video",
    "media",
    "stream",
    "search",
    "analytics",
    "tracking",
    "ads",
    "mail2",
    "smtp",
    "imap",
    "pop",
    "vpn",
    "remote",
    "office",
    "intranet",
    "corp",
    "staff",
    "employee",
    "hr",
    "finance",
    "billing",
    "pay",
    "payment",
    "orders",
    "cart",
    "checkout",
]


def _extract_root_domain(hostname: str) -> str:
    """
    Extract a simple root domain from the hostname.

    NOTE: This uses a very simple heuristic (last two labels) and does
    not handle complex public suffix rules. For educational purposes,
    this is sufficient to demonstrate subdomain enumeration.
    """
    if not hostname:
        return ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def enumerate_subdomains(target_url: str, timeout: float = 2.0) -> List[Dict[str, str]]:
    """
    Perform subdomain brute-force enumeration against a target domain.

    - Extract the root domain from the target URL.
    - For each subdomain label in SUBDOMAINS:
        * Build <label>.<root-domain>
        * Probe HTTPS first (https://sub.domain)
          - If HTTPS fails, fall back to HTTP (http://sub.domain)
        * If any probe returns a status code < 400, record the subdomain.

    Findings are INFO-level reconnaissance results.
    """
    findings: List[Dict[str, str]] = []
    url = normalize_url(target_url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    root_domain = _extract_root_domain(hostname)

    if not root_domain:
        return findings

    discovered: set[str] = set()

    for label in SUBDOMAINS:
        candidate = f"{label}.{root_domain}"

        # Try HTTPS first
        https_url = f"https://{candidate}"
        try:
            resp = requests.get(https_url, timeout=timeout)
            if resp.status_code < 400:
                discovered.add(candidate)
                findings.append(
                    {
                        "type": "Subdomain Discovery",
                        "severity": "INFO",
                        "subdomain": candidate,
                        "message": f"Subdomain discovered: {candidate}",
                        "scheme": "https",
                    }
                )
                continue
        except requests.RequestException:
            pass

        # Fallback to HTTP
        http_url = f"http://{candidate}"
        try:
            resp = requests.get(http_url, timeout=timeout)
            if resp.status_code < 400 and candidate not in discovered:
                discovered.add(candidate)
                findings.append(
                    {
                        "type": "Subdomain Discovery",
                        "severity": "INFO",
                        "subdomain": candidate,
                        "message": f"Subdomain discovered: {candidate}",
                        "scheme": "http",
                    }
                )
        except requests.RequestException:
            continue

    return findings

