"""
Central scanning engine for the Automated Security Testing Software.

Responsibilities:
- Receive target URL
- Run all vulnerability modules
- Collect results and assign severity levels
- Generate structured scan summary
- Write a JSON report file under reports/scan_report.json
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from backend.headers_check import check_security_headers
from backend.idor_check import test_idor
from backend.port_scan import scan_common_ports
from backend.sensitive_files import discover_sensitive_files
from backend.server_detection import check_https_enforcement, detect_server_technology
from backend.subdomain_enum import enumerate_subdomains
from backend.xss_check import test_reflected_xss
from utils.helpers import extract_host, normalize_url


def _ensure_reports_dir() -> Path:
    root = Path(__file__).resolve().parents[1]
    reports_dir = root / "reports"
    reports_dir.mkdir(exist_ok=True)
    return reports_dir


def _write_report(report_data: Dict[str, Any]) -> Path:
    reports_dir = _ensure_reports_dir()
    report_path = reports_dir / "scan_report.json"
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    return report_path


def run_scan(target_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Execute all available security checks against the target URL.

    Returns a dict with:
    - target
    - scan_time
    - vulnerabilities (list)
    - report_path (string path to the JSON report)
    """
    normalized_target = normalize_url(target_url)
    host = extract_host(normalized_target)
    started_at = datetime.now(timezone.utc)
    scan_time = started_at.isoformat()

    vulnerabilities: List[Dict[str, Any]] = []

    # 1. Server detection (reconnaissance)
    vulnerabilities.extend(detect_server_technology(normalized_target, timeout=timeout))

    # 2. Service discovery / port scan
    vulnerabilities.extend(scan_common_ports(host))

    # 3. Subdomain enumeration
    vulnerabilities.extend(enumerate_subdomains(normalized_target, timeout=2.0))

    # 4. Security headers
    vulnerabilities.extend(check_security_headers(normalized_target, timeout=timeout))

    # 5. TLS/HTTPS enforcement check
    vulnerabilities.extend(check_https_enforcement(normalized_target, timeout=timeout))

    # 6. Sensitive files
    vulnerabilities.extend(discover_sensitive_files(normalized_target, timeout=timeout))

    # 7. Reflected XSS test
    vulnerabilities.extend(test_reflected_xss(normalized_target, timeout=timeout))

    # 8. IDOR parameter manipulation test
    vulnerabilities.extend(test_idor(normalized_target, timeout=timeout))

    finished_at = datetime.now(timezone.utc)
    duration_seconds = (finished_at - started_at).total_seconds()

    report_data: Dict[str, Any] = {
        "target": normalized_target,
        "scan_time": scan_time,
        "vulnerabilities": [
            {
                "type": v.get("type"),
                "severity": v.get("severity"),
                "details": {k: val for k, val in v.items() if k not in {"type", "severity"}},
            }
            for v in vulnerabilities
        ],
        "stats": {
            "high": sum(1 for v in vulnerabilities if v.get("severity") == "HIGH"),
            "medium": sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM"),
            "low": sum(1 for v in vulnerabilities if v.get("severity") == "LOW"),
            "total": len(vulnerabilities),
            "duration_seconds": duration_seconds,
        },
    }

    report_path = _write_report(report_data)
    result: Dict[str, Any] = {
        "target": normalized_target,
        "scan_time": scan_time,
        "vulnerabilities": vulnerabilities,
        "report_path": str(report_path),
        "duration_seconds": duration_seconds,
    }
    return result
