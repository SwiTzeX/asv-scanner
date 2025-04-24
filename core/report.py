import datetime
import json
from config import REPORT_FILE, SCAN_INTERVAL_DAYS
from core.result_manager import results_dict
from utils.vuln_utils import get_medium_and_high_cves
from weasyprint import HTML
from jinja2 import Template

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
    from core.result_manager import results_dict

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



# HTML template for styled executive-summary report
_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PCI DSS Executive Summary</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 1cm; }
    header { background: #003366; color: white; padding: 20px; text-align: center; }
    h1 { margin: 0; }
    .metadata { margin: 20px 0; }
    .metadata div { margin-bottom: 5px; }
    .section { margin-top: 30px; }
    .section h2 { border-bottom: 2px solid #003366; padding-bottom: 5px; color: #003366; }
    .key-findings { display: flex; gap: 10px; margin: 20px 0; }
    .key-findings .box { background: #f2f2f2; padding: 15px; flex: 1; border: 1px solid #ccc; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    table, th, td { border: 1px solid #999; }
    th { background: #eee; padding: 6px; text-align: left; }
    td { padding: 6px; vertical-align: top; }
    footer { text-align: center; font-size: 0.9em; color: #666; margin-top: 40px; }
  </style>
</head>
<body>
  <header>
    <h1>PCI DSS Executive Summary</h1>
  </header>
  <div class="metadata">
    <div><strong>Scan Date:</strong> {{ scan["scan_metadata"]["date"] }}</div>
    <div><strong>Overall Status:</strong>
      {% if scan["scan_metadata"]["pci_compliant"] %}✅ PASS{% else %}❌ FAIL{% endif %}
    </div>
  </div>
  <div class="section">
    <h2>Key Findings</h2>
    <div class="key-findings">
      <div class="box">
        <strong>High & Medium CVEs:</strong>
        {{ len(get_medium_and_high_cves(results_dict)) }} issues
      </div>
      <div class="box">
        <strong>TLS Compliance:</strong>
        {{ scan["TLS Scan"]["pci_compliant"] }}
      </div>
    </div>
  </div>
  <div class="section">
    <h2>Detected Software & Vulnerabilities</h2>
    {% for sw, details in scan["scanned_software"].items() %}
      {% if sw not in ['scan_summary','TLS Scan','NSC Checks','Web Security','OS'] %}
        <h3>{{ sw }} ({{ details["ports"] | join(', ') }})</h3>
        {% if details["cves"] %}
          <table>
            <tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>
            {% for c in details["cves"] %}
            <tr>
              <td>{{ c["cve_id"] }}</td>
              <td>{{ c["cvss_score"] }}</td>
              <td>{{ c["severity"] }}</td>
              <td>{{ c["description"][:80] }}…</td>
            </tr>
            {% endfor %}
          </table>
        {% else %}
          <p>No vulnerabilities found.</p>
        {% endif %}
      {% endif %}
    {% endfor %}
  </div>
  <div class="section">
    <h2>TLS / SSL Findings</h2>
    <table>
      <tr><th>Target</th><td>{{ scan["TLS Scan"]["target"] }}</td></tr>
      <tr><th>Cipher</th><td>{{ scan["TLS Scan"]["cipher"] }}</td></tr>
      <tr><th>TLS Version</th><td>{{ scan["TLS Scan"]["tls_version"] }}</td></tr>
      <tr><th>Expiry</th><td>{{ scan["TLS Scan"]["certificate_expiry"] }}</td></tr>
      <tr><th>Compliance</th><td>{{ scan["TLS Scan"]["pci_compliant"] }}</td></tr>
    </table>
  </div>
  <div class="section">
    <h2>Network Security Controls (NSC)</h2>
    <table>
      <tr><th>DNS Zone Transfer</th>
          <td>{{ scan["NSC Checks"]["dns_zone_transfer"] }}</td></tr>
      <tr><th>SMTP Relay</th>
          <td>{{ scan["NSC Checks"]["smtp_open_relay"] }}</td></tr>
      <tr><th>ICMP Exposure</th>
          <td>{{ scan["NSC Checks"]["icmp_firewall_exposed"] }}</td></tr>
    </table>
  </div>
  <div class="section">
    <h2>Web Application Findings</h2>
    <p><strong>PCI Risk:</strong> {{ scan["Web Security"]["risk_level"] }}</p>
    <p><strong>Compliance:</strong> {{ scan["Web Security"]["pci_compliant"] }}</p>
  </div>
  <div class="section">
    <h2>Operating System Findings</h2>
    <p><strong>Detected OS:</strong> {{ scan["OS"]["os_name"] }}
       (Accuracy: {{ scan["OS"]["accuracy"] }}%)</p>
    <p><strong>Compliance:</strong> {{ scan["OS"]["pci_compliant"] }}</p>
  </div>
  <footer>
    Generated on {{ scan["scan_metadata"]["date"] }} by ASV Scanner
  </footer>
</body>
</html>
"""

def generate_pdf_report(scan: dict, filename: str = "executive_summary.pdf") -> None:
    """
    Render HTML → PDF via WeasyPrint.
    """
    template = Template(_HTML_TEMPLATE)
    html_out = template.render(scan=scan)
    HTML(string=html_out).write_pdf(filename)
    print(f"✅ PDF report generated: {filename}")
