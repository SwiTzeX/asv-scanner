# utils/vuln_utils.py

def determine_severity(cvss_score):
    """Determine PCI severity label from a CVSS score."""
    try:
        cvss_score = float(cvss_score)
    except (ValueError, TypeError):
        return "Unknown"

    if cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"


def get_medium_and_high_cves(results_dict):
    """
    Extract all CVEs scored Medium or High from a scan results dict.
    Returns a list of dicts with keys: software, cve_id, cvss_score, severity, description.
    """
    culled = []
    for software, details in results_dict.items():
        for cve in details.get("cves", []):
            sev = cve.get("severity") or determine_severity(cve.get("cvss_score", 0))
            if sev in ("High", "Medium"):
                culled.append({
                    "software": software,
                    "cve_id":     cve.get("cve_id"),
                    "cvss_score": cve.get("cvss_score"),
                    "severity":   sev,
                    "description":cve.get("description"),
                })
    return culled
