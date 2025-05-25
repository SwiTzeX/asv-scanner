import asyncio
import aiohttp
import requests

# URL to fetch the list of HTTP proxies
PROXIES_URL = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text&timeout=20000"
# Maximum concurrent proxy checks\ n
MAX_CONCURRENT_TASKS = 100

async def _check_proxy(proxy: str) -> str | None:
    """
    Test a single proxy by sending GETs to two endpoints.
    Returns proxy string if working, else None.
    """
    headers = {'User-Agent': 'Mozilla/5.0'}
    test_urls = ["https://google.com", "https://www.tapology.com"]
    proxy_url = f"http://{proxy}"
    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in test_urls:
            try:
                async with session.get(url, proxy=proxy_url, headers=headers) as resp:
                    if resp.status != 200:
                        return None
            except:
                return None
    return proxy

async def _fetch_proxies() -> list[str]:
    """
    Fetch raw proxy list text, split into lines.
    """
    try:
        resp = requests.get(PROXIES_URL, timeout=10)
        resp.raise_for_status()
        return [line.strip() for line in resp.text.splitlines() if line.strip()]
    except requests.RequestException:
        return []

async def _gather_working_proxies(max_proxies: int) -> list[str]:
    """
    Concurrently check proxies, return up to max_proxies working ones.
    """
    all_proxies = await _fetch_proxies()
    working: list[str] = []
    sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

    async def bound_check(p):
        async with sem:
            return await _check_proxy(p)

    tasks = [bound_check(p) for p in all_proxies]
    for fut in asyncio.as_completed(tasks):
        proxy = await fut
        if proxy:
            working.append(proxy)
            if len(working) >= max_proxies:
                break
    return working


def get_working_proxies(max_proxies: int = 5) -> list[str]:
    """
    Synchronous entrypoint: fetch and test proxies, print summary.
    """
    working = asyncio.run(_gather_working_proxies(max_proxies))
    print(f"Found {len(working)} working proxies.")
    return working


