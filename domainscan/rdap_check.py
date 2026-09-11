import json
import os
import time

from domainscan.helpers import BROWSER_UA


BOOTSTRAP_BASE = "https://data.iana.org/rdap/"
CACHE_TTL = 86400


def cache_dir():
    path = os.path.join(os.path.expanduser("~"), ".domainscan")
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass
    return path


def bootstrap(kind, cache_path=None):
    if cache_path:
        path = cache_path
    else:
        path = os.path.join(cache_dir(), "rdap-" + kind + ".json")
    cached = read_cache(path)
    try:
        fresh = cached and time.time() - os.path.getmtime(path) < CACHE_TTL
    except Exception:
        fresh = False
    if fresh:
        return cached
    try:
        data = fetch_bootstrap(kind)
    except Exception:
        return cached
    if data:
        write_cache(path, data)
        return data
    return cached


def read_cache(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def write_cache(path, data):
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
    except Exception:
        pass


def fetch_bootstrap(kind):
    import requests
    response = requests.get(BOOTSTRAP_BASE + kind + ".json", timeout=10, headers={"User-Agent": BROWSER_UA})
    response.raise_for_status()
    return response.json()


def find_services(data, kind, key):
    services = (data or {}).get("services", []) or []
    if kind == "dns":
        wanted = str(key).lower().rstrip(".")
        for ranges, urls in services:
            lowers = [str(item).lower().rstrip(".") for item in ranges or []]
            if wanted in lowers:
                return list(urls or [])
        return []
    if kind == "asn":
        try:
            number = int(key)
        except Exception:
            return []
        for ranges, urls in services:
            if not ranges or len(ranges) < 2:
                continue
            try:
                low = int(ranges[0])
                high = int(ranges[1])
            except Exception:
                continue
            if low <= number <= high:
                return list(urls or [])
        return []
    import ipaddress
    try:
        address = ipaddress.ip_address(str(key))
    except Exception:
        return []
    for ranges, urls in services:
        for cidr in ranges or []:
            try:
                if address in ipaddress.ip_network(str(cidr), strict=False):
                    return list(urls or [])
            except Exception:
                continue
    return []


def rdap_get(url):
    import requests
    headers = {"User-Agent": BROWSER_UA, "Accept": "application/rdap+json, application/json"}
    response = requests.get(url, timeout=12, headers=headers)
    response.raise_for_status()
    return response.json()
