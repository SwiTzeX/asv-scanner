from zapv2 import ZAPv2
import time
from core.result_manager import results_dict, lock
from config import ZAP_PROXY

def scan_with_zap(target_url):
    zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    print(f"🔍 Starting OWASP ZAP scan on {target_url}...")

    # ——— SPEED TWEAKS ———
    # Increase spider threads (default is 2)
    zap.spider.set_option_thread_count(4)
    zap.spider.set_option_max_depth(5)        # crawl a bit deeper if needed
    zap.ascan.set_option_thread_per_host(4)
    zap.ascan.set_option_max_scans_in_ui(4)   # allow up to 4 concurrent scans in the UI
    zap.ascan.set_option_delay_in_ms(0)       # no delay between request batches

    scan_id = zap.spider.scan(target_url)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)

    print("✅ ZAP spidering complete. Running active scan...")

    scan_id = zap.ascan.scan(target_url)
    while int(zap.ascan.status(scan_id)) < 100:
        time.sleep(5)

    print("✅ ZAP active scan complete. Collecting alerts...")

    alerts = zap.core.alerts(baseurl=target_url)
    findings = []
    for alert in alerts:
        findings.append({
            "risk": alert.get("risk", "N/A"),
            "name": alert.get("name", "Unknown"),
            "description": alert.get("description", "No description"),
            "solution": alert.get("solution", "No recommended solution"),
            "cwe_id": alert.get("cweid", "Unknown"),
            "wasc_id": alert.get("wascid", "Unknown")
        })

    return findings


def active_web_scan(target):
    print(f"📡 Running ZAP scan on {target}...")
    zap_results = scan_with_zap(f"http://{target}")

    with lock:
        # Ensure we don’t wipe out passive-scan data
        websec = results_dict.setdefault("Web Security", {})
        # Append/replace just the vulnerabilities key
        websec["vulnerabilities"] = zap_results

    print(f"✅ ZAP scan finished: {len(zap_results)} issue(s) found.")
