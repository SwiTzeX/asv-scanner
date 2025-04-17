import datetime
import json
from scanner.config import REPORT_FILE, SCAN_INTERVAL_DAYS
from scanner.core.result_manager import results_dict


def generate_pci_compliant_report():
    report = {
        "scan_metadata": {
            "date": str(datetime.datetime.now()),
            "scan_interval_days": SCAN_INTERVAL_DAYS,
            "pci_compliant": all(
                "cves" in details and (not details["cves"] or all(
                    float(cve.get("cvss_score", 0)) < 4.0 for cve in details["cves"]))
                for details in results_dict.values()
            )
        },
        "scanned_software": results_dict
    }
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)
    print(f"✅ PCI ASV scan report saved to {REPORT_FILE}")


def print_summary():
    """Print scan results summary with CVEs, TLS info, web security, and NSC checks"""
    from scanner.core.result_manager import results_dict

    print("\n" + "=" * 60)
    print("🚨 PCI DSS Scan Results - Summary 🚨")
    print("=" * 60)

    for software, details in results_dict.items():
        if software in ["TLS Scan", "scan_summary", "NSC Checks", "Web Security"]:
            continue

        ports = ", ".join(details['ports']) if 'ports' in details else "N/A"
        print(f"\n🟢 Software: {software}")
        print(f"    📌 Open TCP Ports: {ports}")

        # Show CVEs if any
        if "cves" in details and details["cves"]:
            print(f"    🚩 Vulnerabilities Found:")
            for cve in details["cves"]:
                print(f"      - [{cve['severity']}] {cve['cve_id']} (CVSS: {cve['cvss_score']})")
                print(f"        {cve['description'][:100]}...\n")
        else:
            print("    ✅ No vulnerabilities identified for this software.")

        # Show special PCI notes (e.g., unknown service)
        if "notes" in details and details["notes"]:
            print("    📌 Special Notes:")
            for note in details["notes"]:
                print(f"      ⚠ {note}")

        # Show TLS scan results if 443 is present
        if "443/tcp" in ports and "TLS Scan" in results_dict:
            tls_results = results_dict["TLS Scan"]
            print("    🔒 TLS Security Check:")
            print(f"      - Cipher: {tls_results.get('cipher', 'Unknown')}")
            print(f"      - TLS Version: {tls_results.get('tls_version', 'Unknown')}")
            print(f"      - Certificate Expiry: {tls_results.get('certificate_expiry', 'Unknown')}")
            print(f"      - PCI Compliance: {tls_results.get('pci_compliant', 'Unknown')}")
            for warning in tls_results.get("warnings", []):
                print(f"      ⚠ Warning: {warning}")

    # Web Security Block
    if "Web Security" in results_dict:
        web = results_dict["Web Security"]
        print("\n" + "=" * 60)
        print("🌐 Web Application Security")
        print("=" * 60)

        print(f"    🔒 PCI Risk: {web.get('risk_level', 'Unknown')}")
        print(f"    📦 PCI Compliance: {web.get('pci_compliant', 'Unknown')}")

        vulns = web.get("vulnerabilities", [])
        if vulns:
            print("    🚩 Web Vulnerabilities Detected:")
            for vuln in vulns:
                print(f"      - [{vuln.get('risk', 'Unknown')}] {vuln.get('name')}")
                print(f"        CWE: {vuln.get('cwe_id', 'N/A')} | WASC: {vuln.get('wasc_id', 'N/A')}")
                print(f"        {vuln.get('description', '')[:100]}...")
                print(f"        Fix: {vuln.get('solution', '')[:100]}...\n")
        else:
            print("    ✅ No web vulnerabilities identified.")

    # Scan Interference Summary
    summary = results_dict.get("scan_summary", {})
    if summary.get("scan_interference_detected"):
        print("\n" + "=" * 60)
        print("🚧 Scan Interference Detected")
        print("=" * 60)
        for note in summary.get("notes", []):
            print(f"   - {note}")

    # NSC (Network Security Controls) Summary
    nsc = results_dict.get("NSC Checks", {})
    if nsc:
        print("\n" + "=" * 60)
        print("🔐 NSC (DNS / Mail / Firewall) Security Checks")
        print("=" * 60)
        print(f"📡 DNS Zone Transfer: {nsc.get('dns_zone_transfer', 'Unknown')}")
        print(f"📧 SMTP Open Relay: {nsc.get('smtp_open_relay', 'Unknown')}")
        print(f"🌐 ICMP Firewall Exposure: {nsc.get('icmp_firewall_exposed', 'Unknown')}")
        if "notes" in nsc and nsc["notes"]:
            print("\n📝 Notes:")
            for note in nsc["notes"]:
                print(f"   - {note}")

    print("\n" + "=" * 60)

