"""
Port scanning module.

Security purpose:
- Scan a small list of common ports to identify exposed services that expand the attack surface.
"""

from __future__ import annotations

import socket
from typing import Dict, List


COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    8080,  # Alternate HTTP
]

PORT_DESCRIPTIONS = {
    21: ("FTP exposed", "MEDIUM"),
    22: ("SSH service exposed", "MEDIUM"),
    23: ("Telnet service exposed", "MEDIUM"),
    25: ("SMTP service exposed", "MEDIUM"),
    80: ("HTTP service detected", "INFO"),
    110: ("POP3 service exposed", "MEDIUM"),
    143: ("IMAP service exposed", "MEDIUM"),
    443: ("HTTPS service detected", "INFO"),
    445: ("SMB file sharing exposed", "MEDIUM"),
    3306: ("MySQL database exposed", "MEDIUM"),
    3389: ("RDP service exposed", "MEDIUM"),
    5432: ("PostgreSQL database exposed", "MEDIUM"),
    8080: ("Alternate HTTP service detected", "INFO"),
}


def scan_common_ports(host: str) -> List[Dict[str, str]]:
    """
    Scan a set of common ports on the given host.

    - Treat potentially dangerous services (e.g. FTP, SSH) as MEDIUM.
    - Treat common web services (80, 443, 8080) as informational only.
    """
    findings: List[Dict[str, str]] = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                description, severity = PORT_DESCRIPTIONS.get(
                    port, ("Service detected", "INFO")
                )
                findings.append(
                    {
                        "type": "Open Port",
                        "severity": severity,
                        "port": str(port),
                        "message": f"Port {port} open ({description})",
                    }
                )
        except OSError:
            # Network error, treat as no result for this port
            pass
        finally:
            sock.close()
    return findings
