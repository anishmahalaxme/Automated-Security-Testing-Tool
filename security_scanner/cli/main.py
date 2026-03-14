"""
CLI entrypoint for the Automated Security Testing Software.

Responsibilities:
- Parse command-line arguments
- Display a professional banner
- Show scan progress phases
- Display vulnerability findings and a summary dashboard
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is on sys.path when running as a script
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.scanner import run_scan
from utils.helpers import color_info, color_success, color_warning, color_error, set_color_enabled


def print_banner() -> None:
    banner = (
        "=============================================================\n"
        "                   AUTOMATED SECURITY TESTING TOOL            \n"
        "============================================================="
    )
    print(color_success(banner))


def print_progress(message: str) -> None:
    print(color_info(f"[INFO] {message}"))


def print_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> None:
    severity_colors = {
        "HIGH": color_error,
        "MEDIUM": color_warning,
        "LOW": color_info,
        "INFO": color_info,
    }
    # Print informational findings (e.g. web ports) first
    info_findings = [v for v in vulnerabilities if v.get("severity", "").upper() == "INFO"]
    other_findings = [v for v in vulnerabilities if v.get("severity", "").upper() != "INFO"]

    for vuln in info_findings:
        sev = vuln.get("severity", "INFO").upper()
        msg = vuln.get("message") or vuln.get("type", "Vulnerability")
        color_fn = severity_colors.get(sev, color_info)
        print(color_fn(f"[{sev}] {msg}"))

    # Add a blank line to clearly separate INFO from real vulnerabilities
    if info_findings and other_findings:
        print()

    for vuln in other_findings:
        sev = vuln.get("severity", "LOW").upper()
        msg = vuln.get("message") or vuln.get("type", "Vulnerability")
        color_fn = severity_colors.get(sev, color_info)
        print(color_fn(f"[{sev}] {msg}"))


def print_summary(vulnerabilities: List[Dict[str, Any]], report_path: Path | None) -> None:
    high = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
    med = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
    low = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")
    # Only count HIGH/MEDIUM/LOW as vulnerabilities; INFO is informational
    total = high + med + low

    print()
    print(color_success("========== Scan Summary =========="))
    print(color_error(f"HIGH vulnerabilities: {high}"))
    print(color_warning(f"MEDIUM vulnerabilities: {med}"))
    print(color_info(f"LOW vulnerabilities: {low}"))
    print(color_info(f"\nTotal vulnerabilities found: {total}"))

    if report_path is not None:
        print()
        print(color_success(f"Report saved to: {report_path}"))


def handle_scan(target: str, timeout: float) -> None:
    print_banner()
    print()
    print(f"Target: {target}")
    print()

    # Reconnaissance
    print_progress("Starting reconnaissance...")
    print_progress("Detecting server technology...")
    print_progress("Running port scan...")
    print_progress("Enumerating subdomains...")

    print()

    # Security configuration checks
    print_progress("Running security checks...")
    print_progress("Checking security headers...")
    print_progress("Checking HTTPS enforcement...")

    print()

    # Active vulnerability tests
    print_progress("Running vulnerability tests...")
    print_progress("Testing for reflected XSS...")
    print_progress("Testing parameter manipulation (IDOR)...")
    print_progress(f"Using HTTP timeout: {timeout:.1f}s per request")

    result = run_scan(target, timeout=timeout)

    vulnerabilities: List[Dict[str, Any]] = result.get("vulnerabilities", [])
    report_path_str: str | None = result.get("report_path")
    report_path = Path(report_path_str) if report_path_str else None

    print()
    print_vulnerabilities(vulnerabilities)
    print_summary(vulnerabilities, report_path)
    print()
    print(color_success("[SUCCESS] Scan completed"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automated Security Testing Software - basic web vulnerability scanner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a security scan against a target URL",
    )
    scan_parser.add_argument(
        "target",
        help="Target URL, e.g. http://example.com",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request HTTP timeout in seconds (default: 5.0)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored CLI output",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Configure global color usage
    set_color_enabled(not getattr(args, "no_color", False))

    if args.command == "scan":
        handle_scan(args.target, timeout=args.timeout)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
