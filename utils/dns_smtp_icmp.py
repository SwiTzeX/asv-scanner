import socket
import dns.zone
import dns.query
import smtplib
import subprocess
from core.result_manager import results_dict, lock


def check_dns_zone_transfer(target):
    try:
        socket.create_connection((target, 53), timeout=3)
    except:
        return "Not Detected", []

    try:
        zone = dns.zone.from_xfr(dns.query.xfr(target, domain=target, timeout=5))
        if zone:
            return "Vulnerable", [
                "❌ DNS zone transfer is enabled — attackers can enumerate DNS records."
            ]
    except Exception:
        pass

    return "Secure", []


def check_smtp_open_relay(target):
    try:
        socket.create_connection((target, 25), timeout=3)
    except:
        return "Not Detected", []

    try:
        server = smtplib.SMTP(target, 25, timeout=5)
        code, _ = server.helo()
        if code == 250:
            _, _ = server.mail("test@example.com")
            code, rcpt_test = server.rcpt("another@example.org")
            if rcpt_test == 250:
                return "Vulnerable", [
                    "❌ SMTP open relay detected — unauthorized destinations accepted."
                ]
        server.quit()
    except Exception:
        pass
    return "Secure", []


def check_icmp_firewall_exposure(target):
    try:
        ping = subprocess.run(["ping", "-c", "1", target], capture_output=True)
        if ping.returncode == 0:
            return "Responding", [
                "⚠️ ICMP ping response enabled — may indicate weak firewall settings."
            ]
        else:
            return "Blocked", []
    except Exception:
        return "Unknown", []


def run_nsc_checks(target):
    dns_status, dns_notes = check_dns_zone_transfer(target)
    smtp_status, smtp_notes = check_smtp_open_relay(target)
    icmp_status, icmp_notes = check_icmp_firewall_exposure(target)

    with lock:
        results_dict["NSC Checks"] = {
            "dns_zone_transfer": dns_status,
            "smtp_open_relay": smtp_status,
            "icmp_firewall_exposed": icmp_status,
            "notes": dns_notes + smtp_notes + icmp_notes
        }
