from scanner.config import API_URL
from scanner.utils.tls_scanner import scan_ssl_tls
from scanner.utils.cve_api import query_cve_api
from scanner.utils.tls_scanner import determine_severity
from scanner.core.result_manager import results_dict, lock
import nmap3
import requests


def pci_scan_range(target, port_range):
    nmap = nmap3.Nmap()
    scan_result = nmap.scan_top_ports(target, args=f"-Pn -sS -p {port_range} --open -sV -O")

    with lock:
        for host, data in scan_result.items():
            if isinstance(data, dict):
                ports = data.get("ports", [])
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
