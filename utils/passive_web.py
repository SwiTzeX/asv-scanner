import random
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from core.result_manager import results_dict, lock
from requests.exceptions import ProxyError, ConnectionError
from utils.proxies_checker import get_working_proxies

def is_external_script(script_url, base_domain):
    try:
        parsed_script = urlparse(script_url)
        parsed_base = urlparse(base_domain)
        return parsed_script.netloc and parsed_script.netloc != parsed_base.netloc
    except:
        return False

def passive_web_analysis(target: str, autoproxy: bool):
    """
    Crawls target for links & scripts.
    If autoproxy=True, rotates through working proxies (up to 6 attempts).
    Otherwise uses direct host IP.
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    url = f"http://{target}"
    response = None

    # prepare proxy list
    if autoproxy:
        proxies_list = get_working_proxies()
        print(f"[*] Fetched {len(proxies_list)} working proxies for passive crawl")
        if len(proxies_list) == 0:
        	proxies_list = [None]
        	print("[*] Passive crawl without proxy")
    else:
        proxies_list = [None]
        print("[*] Passive crawl without proxy")

    # try up to 6 attempts
    for attempt in range(6):
        proxy = random.choice(proxies_list)
        if proxy:
            print(f"--> Passive crawl attempt {attempt+1}/6 via proxy {proxy}")
            proxy_cfg = {"http": proxy, "https": proxy}
        else:
            print(f"--> Passive crawl attempt direct (no proxy)")
            proxy_cfg = None

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=10,
                proxies=proxy_cfg
            )
            response.raise_for_status()
            break
        except (ProxyError, ConnectionError) as e:
            print(f"⚠ Proxy/connect error: {e}. Rotating proxy...")
        except Exception as e:
            print(f"[⚠️] Web crawling failed on attempt {attempt+1}: {e}")
            return

    if response is None:
        print("[⚠️] All passive crawl attempts failed")
        return

    # parse out links & scripts
    soup = BeautifulSoup(response.text, "html.parser")
    found_links   = {a["href"]   for a in soup.find_all("a", href=True)}
    found_scripts = {s["src"]    for s in soup.find_all("script", src=True)}
    external_scripts = [s for s in found_scripts if is_external_script(s, url)]
    is_payment_page  = any(kw in url.lower() for kw in ["checkout","payment","pay","cart"])

    with lock:
        websec = results_dict.setdefault("Web Security", {})
        websec.update({
            "found_links":       list(found_links),
            "found_scripts":     list(found_scripts),
            "external_scripts":  external_scripts,
            "payment_page":      is_payment_page,
        })

        if external_scripts and is_payment_page:
            websec["pci_compliant"] = "Non-Compliant"
            websec["risk_level"]    = "High"
            websec["notes"]        = [
                f"❌ External script on payment page: {s}" for s in external_scripts
            ]
        elif external_scripts:
            websec["pci_compliant"] = "Review"
            websec["risk_level"]    = "Medium"
            websec["notes"]        = [
                f"⚠ External script (non-payment page): {s}" for s in external_scripts
            ]
        else:
            websec["pci_compliant"] = "Compliant"
            websec["risk_level"]    = "Low"

    print(f"✅ Crawling done: {len(found_links)} links, {len(found_scripts)} scripts.")
    if external_scripts:
        print(f"⚠️  Detected {len(external_scripts)} external script(s)")
