import threading
from scanner.config import PORT_RANGES
from scanner.core.port_scanner import pci_scan_range
from scanner.core.result_manager import results_dict
from scanner.core.report import generate_pci_compliant_report, print_summary
from scanner.utils.passive_web import passive_web_analysis
from scanner.utils.dns_smtp_icmp import run_nsc_checks
# Optional: Enable if you want active ZAP scanning
# from scanner.utils.zap_scanner import active_web_scan


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

    # Optionally: OWASP ZAP scan
    # t2 = threading.Thread(target=active_web_scan, args=(target,))
    # threads.append(t2)
    # t2.start()

    # NSC checks
    t3 = threading.Thread(target=run_nsc_checks, args=(target,))
    threads.append(t3)
    t3.start()

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

    generate_pci_compliant_report()
    print_summary()


if __name__ == "__main__":
    target = input("Enter Target IP or Domain: ")
    print(f"\n🚀 Starting PCI DSS-compliant scan on {target}...\n")
    run_parallel_scans(target)
