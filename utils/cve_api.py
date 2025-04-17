import requests
from config import API_URL

def query_cve_api(product, version):
    try:
        response = requests.get(API_URL, params={"product": product, "version": version})
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[⚠️] Error querying CVE API: {e}")
        return {}
