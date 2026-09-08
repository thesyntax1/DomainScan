import re
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
    rows.extend(hit_title_rows([name for name, _ in hits[:3]]))
    return {"rows": rows}


def hit_title_rows(names):
    import requests
    rows = []
    for name in names:
        try:
            response = requests.get("http://" + name + "/", timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            text = response.text or ""
        except Exception:
            rows.append(("Lookalike page " + short(name, 60), "No HTTP response"))
            continue
        match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()
            rows.append(("Lookalike page " + short(name, 60), short(title or "(empty title)", 120)))
        else:
            rows.append(("Lookalike page " + short(name, 60), "HTTP " + str(response.status_code) + ", no title"))
    return rows


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
    variants.extend(homoglyph_variants(name))
    cleaned = sorted(set(item.strip(".-") for item in variants if item.strip(".-") and item != name))
    results = [item + "." + tld for item in cleaned]
    for alt in ALT_TLDS:
        if alt != tld:
            results.append(name + "." + alt)
    return results[:40]


HOMOGLYPH_SWAPS = {
    "a": "\u0430",
    "c": "\u0441",
    "e": "\u0435",
    "i": "\u0456",
    "o": "\u043e",
    "p": "\u0440",
    "s": "\u0455",
    "x": "\u0445",
    "y": "\u0443",
}


def homoglyph_variants(name):
    results = []
    for index, char in enumerate(name):
        if char in HOMOGLYPH_SWAPS and len(results) < 8:
            spoofed = name[:index] + HOMOGLYPH_SWAPS[char] + name[index + 1:]
            try:
                results.append(spoofed.encode("idna").decode("ascii"))
            except Exception:
                continue
    return results


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
