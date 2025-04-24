from config import API_URL
from utils.tls_scanner import scan_ssl_tls
from utils.vuln_utils import determine_severity
from utils.cve_api import query_cve_api
from core.result_manager import results_dict, lock
import nmap3
import requests


def pci_scan_range(target, port_range):
    nmap = nmap3.Nmap()
    try:
        scan_result = nmap.scan_top_ports(target, args=f"-Pn -sS -p {port_range} --open -sV -O")

        with lock:
            results_dict["scan_summary"]["hosts_scanned"] += 1
            for host, data in scan_result.items():
                if not isinstance(data, dict):
                    continue

                # ✅ OS Detection
                osmatch = data.get("osmatch", [])
                if osmatch:
                    best_guess = osmatch[0]
                    os_name = best_guess.get("name", "Unknown")
                    os_accuracy = best_guess.get("accuracy", "0")

                    results_dict["OS"] = {
                        "os_name": os_name,
                        "accuracy": os_accuracy,
                        "pci_compliant": "Unknown",
                        "notes": []
                    }

                    # Simple EOL check
                    eol_keywords = ["Windows XP", "Windows Server 2008", "Ubuntu 14", "CentOS 6"]
                    if any(eol in os_name for eol in eol_keywords):
                        results_dict["OS"]["pci_compliant"] = "Non-Compliant"
                        results_dict["OS"]["notes"].append(
                            "❌ Detected OS appears to be End-of-Life (EOL) and unsupported by vendor."
                        )
                        results_dict["OS"]["notes"].append(
                            "Special Note to Scan Customer: The ASV scan solution has detected an operating system that may be no longer supported by the vendor. Unsupported operating systems must be marked as an automatic failure unless patched and supported per PCI DSS requirements."
                        )
                    else:
                        results_dict["OS"]["pci_compliant"] = "Compliant"

                ports = data.get("ports", [])
                results_dict["scan_summary"]["total_ports_detected"] += len(ports)
                for port_info in ports:
                    service = port_info.get("service", {})
                    product = service.get("product", "Unknown")
                    version = service.get("version", "Unknown")
                    portid = port_info.get("portid", "N/A")
                    protocol = port_info.get("protocol", "N/A")

                    software_key = f"{product} {version}"
                    if software_key not in results_dict:
                        results_dict[software_key] = {
                            "ports": [],
                            "cves": [],
                            "notes": []
                        }

                    results_dict[software_key]["ports"].append(f"{portid}/{protocol}")

                    if product == "Unknown":
                        results_dict[software_key]["notes"].append(
                            "❗ Unidentified services detected. Confirm business need or disable securely."
                        )
                    elif product and version:
                        try:
                            response = requests.get(API_URL, params={"product": product, "version": version})
                            response.raise_for_status()
                            vulnerabilities = response.json().get("vulnerabilities", [])
                            for vuln in vulnerabilities:
                                cve_id = vuln.get("cve", {}).get("CVE_data_meta", {}).get("ID", "N/A")
                                cvss_score = vuln.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "0")
                                severity = determine_severity(cvss_score)
                                description = vuln.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")

                                results_dict[software_key]["cves"].append({
                                    "cve_id": cve_id,
                                    "cvss_score": cvss_score,
                                    "severity": severity,
                                    "description": description
                                })
                        except Exception as e:
                            print(f"[⚠️] CVE API error: {e}")

                    # TLS scan if HTTPS port detected
                    if portid == "443":
                        tls_results = scan_ssl_tls(target, 443)
                        results_dict["TLS Scan"] = {
                            "target": target,
                            "cipher": tls_results.get("cipher", "Unknown"),
                            "tls_version": tls_results.get("tls_version", "Unknown"),
                            "certificate_expiry": tls_results.get("certificate_expiry", "Unknown"),
                            "pci_compliant": tls_results.get("pci_compliant", "Unknown"),
                            "warnings": tls_results.get("warnings", []),
                        }
    except Exception:
        with lock:
            results_dict["scan_summary"]["nmap_scan_failures"] += 1
        return
