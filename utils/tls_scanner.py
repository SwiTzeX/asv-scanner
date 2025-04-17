import ssl
import socket
import datetime
from scanner.core.result_manager import results_dict

# List of weak ciphers
weak_ciphers = ["RC4", "DES", "3DES", "MD5", "SHA1"]

def determine_severity(cvss_score):
    try:
        cvss_score = float(cvss_score)
    except ValueError:
        return "Unknown"

    if cvss_score >= 7.0:
        return "High"
    elif 4.0 <= cvss_score < 7.0:
        return "Medium"
    else:
        return "Low"


def scan_ssl_tls(target, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False

        with socket.create_connection((target, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                cert_cn = dict(cert['subject'][0]).get('commonName', None)
                cert_san = [entry[1] for entry in cert.get('subjectAltName', [])] if "subjectAltName" in cert else []

                hostname_mismatch = target not in cert_san and (cert_cn is None or target != cert_cn)

                expiry_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT").replace(
                    tzinfo=datetime.timezone.utc)
                cert_expired = expiry_date < datetime.datetime.now(datetime.timezone.utc)

                cipher_name = cipher[0] if cipher else "Unknown"
                weak_cipher_detected = any(weak in cipher_name for weak in weak_ciphers)

                pci_compliant = True
                warnings = []

                if hostname_mismatch:
                    warnings.append("⚠ Hostname mismatch detected")
                    pci_compliant = False
                if cert_expired:
                    warnings.append("❌ Certificate expired")
                    pci_compliant = False
                if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]:
                    warnings.append("❌ Non-compliant TLS/SSL version detected")
                    pci_compliant = False
                if weak_cipher_detected:
                    warnings.append(f"❌ Weak cipher detected: {cipher_name}")
                    pci_compliant = False

                return {
                    "cipher": cipher_name,
                    "tls_version": tls_version,
                    "certificate_expiry": expiry_date.strftime("%b %d %H:%M:%S %Y GMT"),
                    "pci_compliant": "Compliant" if pci_compliant else "Non-Compliant",
                    "warnings": warnings
                }
    except Exception as e:
        results_dict["scan_summary"]["tls_failures"] += 1
        return {"error": str(e)}
