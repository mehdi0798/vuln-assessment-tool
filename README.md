# Vulnerability Assessment Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

A Python-based vulnerability assessment tool that performs automated security checks against a target host or web application. Covers port scanning, HTTP security headers, SSL certificate validation, and sensitive path exposure — generating a detailed severity report.

Built during cybersecurity studies at Al Akhawayn University, inspired by workflows using Nessus and Burp Suite during internships at Palo Alto Networks and Fortinet.

## Features
- Open port detection with risk classification
- HTTP security header analysis
- SSL certificate validity and expiry check
- Sensitive path and directory exposure detection
- Severity rating — HIGH / MEDIUM / LOW / INFO per finding
- CSV report export with remediation guidance
- Modular design — run all checks or select specific ones

## Project Structure
```
vuln-assessment-tool/
├── scanner.py       # Main entry point
├── checks.py        # Individual vulnerability check modules
├── report.py        # findings display and CSV export
└── requirements.txt
```

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Interactive mode
python scanner.py

# Scan a target
python scanner.py example.com

# Run specific checks only
python scanner.py example.com --checks ports headers

# Custom output directory
python scanner.py example.com -o my_reports/
```

## Checks Available

| Check | Flag | Description |
|-------|------|-------------|
| Port Scan | `ports` | Scans common ports and flags risky services |
| Security Headers | `headers` | Detects missing HTTP security headers |
| SSL Certificate | `ssl` | Validates cert and checks expiry date |
| Sensitive Paths | `paths` | Checks for exposed admin panels and config files |

## Example Output
```
  Vulnerability Assessment Tool v1.0
  Author : Marhfour Mehdi

[*] Target  : http://example.com
[*] Started : 2025-03-10 14:32:01
─────────────────────────────────────────────────

  [HIGH] Open Port
  Target        : example.com:23
  Detail        : Telnet port open
  Remediation   : Close port 23 if not needed

  [MEDIUM] Missing Security Header
  Target        : http://example.com
  Detail        : Header 'Content-Security-Policy' not present
  Remediation   : Add header to server response
```

## Disclaimer
For authorized security testing and educational use only.
Always obtain permission before scanning any target you do not own.

## Author
**Marhfour Mehdi** — github.com/mehdi0798