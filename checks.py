"""
checks.py — Vulnerability check modules
Author: Marhfour Mehdi
"""

import socket
import ssl
import requests
import re
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# ── Common Ports ───────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

RISKY_PORTS = {21, 23, 445, 3389, 27017}

# ── Security Headers ───────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ── Sensitive Paths ────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env",
    "/admin",
    "/admin/login",
    "/phpmyadmin",
    "/wp-admin",
    "/backup",
    "/config",
    "/.git/config",
    "/api/v1",
    "/swagger",
    "/robots.txt",
]


def check_open_ports(host):
    """Scan common ports and flag risky ones."""
    results = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                if result == 0:
                    severity = "HIGH" if port in RISKY_PORTS else "MEDIUM"
                    results.append({
                        "Check":       "Open Port",
                        "Target":      f"{host}:{port}",
                        "Detail":      f"{service} port open",
                        "Severity":    severity,
                        "Remediation": f"Close port {port} if not needed or restrict with firewall rules",
                    })
        except Exception:
            continue
    return results


def check_security_headers(url):
    """Check for missing HTTP security headers."""
    results = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        for header in SECURITY_HEADERS:
            if header not in r.headers:
                results.append({
                    "Check":       "Missing Security Header",
                    "Target":      url,
                    "Detail":      f"Header '{header}' not present",
                    "Severity":    "MEDIUM",
                    "Remediation": f"Add '{header}' to server response headers",
                })
    except Exception as e:
        results.append({
            "Check":       "HTTP Request Failed",
            "Target":      url,
            "Detail":      str(e),
            "Severity":    "INFO",
            "Remediation": "Verify target is reachable",
        })
    return results


def check_ssl(host):
    """Check SSL certificate validity and expiry."""
    results = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            expiry_str = cert["notAfter"]
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days

            if days_left < 30:
                results.append({
                    "Check":       "SSL Certificate Expiry",
                    "Target":      host,
                    "Detail":      f"Certificate expires in {days_left} days ({expiry_str})",
                    "Severity":    "HIGH" if days_left < 7 else "MEDIUM",
                    "Remediation": "Renew SSL certificate immediately",
                })
            else:
                results.append({
                    "Check":       "SSL Certificate",
                    "Target":      host,
                    "Detail":      f"Valid — expires in {days_left} days",
                    "Severity":    "LOW",
                    "Remediation": "No action needed",
                })
    except ssl.SSLError as e:
        results.append({
            "Check":       "SSL Error",
            "Target":      host,
            "Detail":      str(e),
            "Severity":    "HIGH",
            "Remediation": "Fix SSL configuration",
        })
    except Exception:
        pass
    return results


def check_sensitive_paths(url):
    """Check for exposed sensitive files and directories."""
    results = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(url + path, timeout=4, verify=False)
            if r.status_code in (200, 301, 302, 403):
                severity = "HIGH" if path in ("/.env", "/.git/config", "/backup") else "MEDIUM"
                results.append({
                    "Check":       "Exposed Path",
                    "Target":      url + path,
                    "Detail":      f"HTTP {r.status_code} — path accessible",
                    "Severity":    severity,
                    "Remediation": f"Restrict access to {path} via server config or firewall",
                })
        except Exception:
            continue
    return results