#!/usr/bin/env python3
"""
Vulnerability Assessment Tool
Author: Marhfour Mehdi
GitHub: github.com/mehdi0798
Version: 1.0
"""

import sys
import argparse
from datetime import datetime
from checks import (
    check_open_ports,
    check_security_headers,
    check_ssl,
    check_sensitive_paths,
)
from report import print_results, save_report

BANNER = """
  Vulnerability Assessment Tool v1.0
  Author : Marhfour Mehdi  |  github.com/mehdi0798
  ------------------------------------------------
  For authorized security testing only
"""


def normalize_url(target):
    """Ensure target has http/https prefix."""
    if not target.startswith(("http://", "https://")):
        return "http://" + target
    return target


def extract_host(url):
    """Extract hostname from URL."""
    return url.replace("https://", "").replace("http://", "").split("/")[0]


def run_assessment(target, checks):
    """Run selected checks against the target."""
    url  = normalize_url(target)
    host = extract_host(url)

    print(f"\n[*] Target  : {url}")
    print(f"[*] Host    : {host}")
    print(f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 65)

    results = []

    if "ports" in checks:
        print("\n[*] Checking open ports...")
        results += check_open_ports(host)

    if "headers" in checks:
        print("[*] Checking security headers...")
        results += check_security_headers(url)

    if "ssl" in checks:
        print("[*] Checking SSL certificate...")
        results += check_ssl(host)

    if "paths" in checks:
        print("[*] Checking sensitive paths...")
        results += check_sensitive_paths(url)

    # Sort by severity
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    results.sort(key=lambda x: order.get(x["Severity"], 99))

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Vulnerability Assessment Tool — by Marhfour Mehdi"
    )
    parser.add_argument("target", nargs="?", help="Target URL or IP (e.g. example.com)")
    parser.add_argument(
        "--checks",
        nargs="+",
        default=["ports", "headers", "ssl", "paths"],
        choices=["ports", "headers", "ssl", "paths"],
        help="Checks to run (default: all)"
    )
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    target = args.target
    if not target:
        print("Enter target to assess:")
        print("  Examples: example.com | 192.168.1.1 | http://testsite.local\n")
        target = input("Target: ").strip()
        if not target:
            print("[!] No target provided. Exiting.")
            sys.exit(1)

    print(f"\n[!] About to assess: {target}")
    print(f"[!] Checks: {', '.join(args.checks)}")
    if input("[?] Continue? (y/n): ").lower() != "y":
        print("[!] Assessment cancelled.")
        return

    try:
        results = run_assessment(target, args.checks)
        print_results(results)
        save_report(results, args.output)
        print("\n[✓] Assessment complete!\n")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()