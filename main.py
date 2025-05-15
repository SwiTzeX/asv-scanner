import threading
from config import PORT_RANGES, REPORT_FILE
from core.port_scanner import pci_scan_range
from core.result_manager import results_dict
from core.report import generate_pci_compliant_report, print_summary, generate_pdf_report
from utils.passive_web import passive_web_analysis
from utils.dns_smtp_icmp import run_nsc_checks
import json
from utils.zap_scanner import active_web_scan
import sys
import os

# Ensure module path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def run_parallel_scans(target):
    threads = []

    # Initialize scan summary
    results_dict["scan_summary"] = {
        "total_ports_detected": 0,
        "hosts_scanned": 0,
        "nmap_scan_failures": 0,
        "tls_failures": 0,
        "scan_interference_detected": False,
        "notes": []
    }

    # Launch port range scans
    for pr in PORT_RANGES:
        t = threading.Thread(target=pci_scan_range, args=(target, pr))
        threads.append(t)
        t.start()

    # Passive web analysis
    t1 = threading.Thread(target=passive_web_analysis, args=(target,))
    threads.append(t1)
    t1.start()

    # OWASP ZAP scan (optional)
    if "--activescan" in sys.argv:
        print(f"📡 Running OWASP ZAP scan on {target}…")
        t2 = threading.Thread(target=active_web_scan, args=(target,))
        threads.append(t2)
        t2.start()
    else:
        print("ℹ️  Skipping OWASP ZAP active scan (enable with --activescan)")

    # NSC checks
    t3 = threading.Thread(target=run_nsc_checks, args=(target,))
    threads.append(t3)
    t3.start()

    # Wait for all threads
    for t in threads:
        t.join()

    # Interference detection logic
    summary = results_dict["scan_summary"]
    if (
        summary["total_ports_detected"] < 3 or
        summary["nmap_scan_failures"] > 0 or
        summary["tls_failures"] > 0
    ):
        summary["scan_interference_detected"] = True
        summary["notes"].append(
            "⚠ Possible scan interference detected: fewer than 3 ports found or TLS/Nmap failures."
        )

    # Produce reports
    generate_pci_compliant_report()
    print_summary()

    # Load full JSON report
    with open(REPORT_FILE) as f:
        full_report = json.load(f)

    # Promote nested sections to top-level for PDF templating
    ss = full_report.get("scanned_software", {})
    full_report["scan_summary"] = ss.pop("scan_summary", {})
    full_report["TLS Scan"]    = ss.pop("TLS Scan", {})
    full_report["NSC Checks"]   = ss.pop("NSC Checks", {})
    full_report["Web Security"] = ss.pop("Web Security", {})
    full_report["OS"]           = ss.pop("OS", {})

    # Render HTML → PDF
    generate_pdf_report(full_report)


if __name__ == "__main__":
    target = input("Enter Target IP or Domain: ")
    print(f"\n🚀 Starting PCI DSS-compliant scan on {target}...\n")
    run_parallel_scans(target)
