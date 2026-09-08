from concurrent.futures import ThreadPoolExecutor

from domainscan import dns_check
from domainscan.helpers import short


ALT_TLDS = ["com", "net", "org", "io", "co", "info", "biz", "online"]


def collect(apex, enabled=True):
    rows = []
    if not enabled:
        rows.append(("Typosquat check", "Skipped (disabled in options)"))
        return {"rows": rows}
    if not apex or "." not in apex:
        rows.append(("Typosquat check", "Requires a domain name"))
        return {"rows": rows}
    if not dns_check.HAS_DNSPYTHON:
        rows.append(("Typosquat check", "Skipped (dnspython not installed)"))
        return {"rows": rows}
    variants = generate_variants(apex)
    rows.append(("Variants tested", str(len(variants))))
    resolver = dns_check.make_resolver()
    hits = probe_variants(resolver, variants)
    if not hits:
        rows.append(("Registered lookalikes", "None of the tested variants resolve"))
        return {"rows": rows}
    rows.append(("Registered lookalikes", str(len(hits)) + " variants resolve (review for phishing)"))
    for index, (name, addresses) in enumerate(hits[:15], 1):
        rows.append(("Lookalike " + str(index), name + " -> " + short(", ".join(addresses[:3]), 120)))
    return {"rows": rows}


def generate_variants(apex):
    parts = apex.lower().split(".")
    if len(parts) < 2:
        return []
    name = ".".join(parts[:-1])
    tld = parts[-1]
    variants = []
    for index in range(len(name)):
        if name[index] in ("-", "."):
            continue
        variants.append(name[:index] + name[index + 1:])
    for index in range(len(name)):
        variants.append(name[:index] + name[index] + name[index:])
    for index in range(len(name) - 1):
        if name[index] == name[index + 1]:
            continue
        variants.append(name[:index] + name[index + 1] + name[index] + name[index + 2:])
    replacements = {"a": "e", "e": "a", "i": "l", "l": "i", "o": "0", "0": "o", "m": "n", "n": "m", "s": "z"}
    for index, char in enumerate(name):
        if char in replacements:
            variants.append(name[:index] + replacements[char] + name[index + 1:])
    variants.append(name + "s")
    variants.append(name + "-online")
    variants.append(name.replace(".", ""))
    variants.append(name.replace("-", ""))
    cleaned = sorted(set(item.strip(".-") for item in variants if item.strip(".-") and item != name))
    results = [item + "." + tld for item in cleaned]
    for alt in ALT_TLDS:
        if alt != tld:
            results.append(name + "." + alt)
    return results[:40]


def probe_variants(resolver, variants):
    hits = []

    def check(name):
        try:
            result = dns_check.query(resolver, name, "A")
        except Exception:
            return None
        if result["records"]:
            return (name, result["records"])
        return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for item in pool.map(check, variants):
            if item:
                hits.append(item)
    return sorted(hits)
