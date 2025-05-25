# utils/zap_scanner.py

import time
from urllib.parse import urlparse
from zapv2 import ZAPv2
from requests.exceptions import RequestException
from core.result_manager import results_dict, lock
from utils.proxies_checker import get_working_proxies

# Default ZAP API endpoint (always direct to your local ZAP instance)
ZAP_API = "http://127.0.0.1:8080"


def scan_with_zap(target_url: str, autoproxy: bool) -> list:
    """
    Runs OWASP ZAP spider + active scan on target_url.
    If autoproxy=True, rotate through upstream HTTP proxies.
    Otherwise do a single direct scan via your host IP.
    Returns list of alerts.
    """
    findings = []

    # Fetch proxies only if needed
    proxies = get_working_proxies() if autoproxy else [None]
    max_attempts = len(proxies)

    # Initialize the ZAP client (always points to your local ZAP API)
    zap = ZAPv2(proxies={"http": ZAP_API, "https": ZAP_API})

    # Tune ZAP speed settings
    zap.spider.set_option_thread_count(4)
    zap.spider.set_option_max_depth(5)
    zap.ascan.set_option_thread_per_host(4)
    zap.ascan.set_option_max_scans_in_ui(4)
    zap.ascan.set_option_delay_in_ms(0)

    for idx, proxy_url in enumerate(proxies, start=1):
        if proxy_url:
            host, port = proxy_url.split(":", 1)
            print(f"--> ZAP attempt {idx}/{max_attempts} via proxy {host}:{port}")
            # tell ZAP to chain upstream through this proxy
            zap.core.set_option_proxy_chain_name(host)
            zap.core.set_option_proxy_chain_port(int(port))
        else:
            print(f"--> ZAP direct scan (no upstream proxy)")
            # disable any proxy chaining
            zap.core.set_option_proxy_chain_name("")
            zap.core.set_option_proxy_chain_port(0)

        try:
            # Spider phase
            scan_id = zap.spider.scan(target_url)
            while int(zap.spider.status(scan_id)) < 100:
                time.sleep(2)
            print("✅ Spidering complete")

            # Active scan phase
            scan_id = zap.ascan.scan(target_url)
            while int(zap.ascan.status(scan_id)) < 100:
                time.sleep(5)
            print("✅ Active scan complete")

            # Gather alerts
            for alert in zap.core.alerts(baseurl=target_url):
                findings.append({
                    "risk": alert.get("risk", "N/A"),
                    "name": alert.get("name", "Unknown"),
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "cwe_id": alert.get("cweid", "N/A"),
                    "wasc_id": alert.get("wascid", "N/A"),
                })

            # if we made it this far, break out on success
            break

        except RequestException as e:
            print(f"⚠ Proxy/connect error: {e}. Rotating proxy...")
            continue
        except Exception as e:
            print(f"⚠ Unexpected ZAP error: {e}.")
            # if it's not a proxy issue, bail out
            break
    else:
        print(f"⚠ All {max_attempts} proxies failed; no ZAP scan performed.")

    return findings


def active_web_scan(target: str, autoproxy: bool) -> None:
    """
    Thread entry point: run ZAP scan and merge results into results_dict.
    """
    print(f"📡 Running ZAP scan on {target} {'with proxies' if autoproxy else 'directly'}…")
    zap_results = scan_with_zap(f"http://{target}", autoproxy)

    with lock:
        websec = results_dict.setdefault("Web Security", {})
        websec["vulnerabilities"] = zap_results

    print(f"✅ ZAP scan finished: {len(zap_results)} issue(s) found.")
