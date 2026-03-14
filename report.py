"""
report.py — Vulnerability report display and CSV export
Author: Marhfour Mehdi
"""

import os
import pandas as pd
from datetime import datetime

COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[92m",
    "INFO":   "\033[96m",
    "BOLD":   "\033[1m",
    "RESET":  "\033[0m",
}


def c(level, text):
    return f"{COLORS.get(level, '')}{text}{COLORS['RESET']}"


def print_results(results):
    if not results:
        print(c("LOW", "\n[✓] No vulnerabilities found."))
        return

    print(c("BOLD", "\n" + "─" * 65))
    print(c("BOLD", "  VULNERABILITY ASSESSMENT REPORT"))
    print(c("BOLD", "─" * 65))

    for r in results:
        sev = r["Severity"]
        print(
            f"\n  {c(sev, f'[{sev}]')} {c('BOLD', r['Check'])}\n"
            f"  {'Target':<14}: {r['Target']}\n"
            f"  {'Detail':<14}: {r['Detail']}\n"
            f"  {'Remediation':<14}: {r['Remediation']}"
        )
        print(c("MEDIUM", "  " + "─" * 50))


def save_report(results, output_dir="reports"):
    if not results:
        return None

    os.makedirs(output_dir, exist_ok=True)
    df = pd.DataFrame(results)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"vuln_{timestamp}.csv")
    df.to_csv(filepath, index=False)

    print(f"\n[+] Report saved → {filepath}")
    print(f"[+] Total findings : {len(results)}")

    print("\n  SEVERITY SUMMARY")
    print("  " + "─" * 35)
    for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        count = len([r for r in results if r["Severity"] == sev])
        if count:
            print(f"  {c(sev, sev):<20} {count} finding(s)")

    return filepath