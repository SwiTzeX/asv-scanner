import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from core.result_manager import results_dict, lock

def is_external_script(script_url, base_domain):
    try:
        parsed_script = urlparse(script_url)
        parsed_base = urlparse(base_domain)
        return parsed_script.netloc and parsed_script.netloc != parsed_base.netloc
    except:
        return False


def passive_web_analysis(target):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    print(f"🔍 Crawling {target} for web vulnerabilities and external scripts...")

    try:
        url = f"http://{target}"
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        found_links = {a["href"] for a in soup.find_all("a", href=True)}
        found_scripts = {script["src"] for script in soup.find_all("script", src=True)}

        external_scripts = [script for script in found_scripts if is_external_script(script, url)]
        is_payment_page = any(kw in url.lower() for kw in ["checkout", "payment", "pay", "cart"])

        with lock:
            results_dict["Web Security"] = results_dict.get("Web Security", {})
            results_dict["Web Security"].update({
                "found_links": list(found_links),
                "found_scripts": list(found_scripts),
                "external_scripts": external_scripts,
                "payment_page": is_payment_page,
            })

            if external_scripts and is_payment_page:
                results_dict["Web Security"]["pci_compliant"] = "Non-Compliant"
                results_dict["Web Security"]["risk_level"] = "High"
                results_dict["Web Security"]["notes"] = [
                    f"❌ External script on payment page: {script}" for script in external_scripts
                ]
            elif external_scripts:
                results_dict["Web Security"]["pci_compliant"] = "Review"
                results_dict["Web Security"]["risk_level"] = "Medium"
                results_dict["Web Security"]["notes"] = [
                    f"⚠ External script (non-payment page): {script}" for script in external_scripts
                ]
            else:
                results_dict["Web Security"]["pci_compliant"] = "Compliant"
                results_dict["Web Security"]["risk_level"] = "Low"

        print(f"✅ Crawling done: {len(found_links)} links, {len(found_scripts)} scripts.")
        if external_scripts:
            print(f"⚠️  Detected {len(external_scripts)} external script(s)")

    except Exception as e:
        print(f"[⚠️] Web crawling failed: {e}")
