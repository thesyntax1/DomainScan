import re
import socket
import ipaddress
import urllib.parse
import datetime


BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DomainScan/1.0"

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


def parse_target(raw):
    text = (raw or "").strip()
    if not text:
        raise ValueError("Empty target")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    host = (parts.hostname or "").strip().strip(".")
    if not host:
        raise ValueError("Invalid target")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except Exception:
        ascii_host = host
    try:
        unicode_host = ascii_host.encode("ascii").decode("idna")
    except Exception:
        unicode_host = ascii_host
    try:
        ipaddress.ip_address(ascii_host)
        is_ip = True
    except ValueError:
        is_ip = False
    scheme = parts.scheme.lower() if parts.scheme else "https"
    if scheme not in ("http", "https"):
        scheme = "https"
    try:
        explicit_port = parts.port
    except ValueError:
        explicit_port = None
    if explicit_port:
        port = explicit_port
    elif scheme == "http":
        port = 80
    else:
        port = 443
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    base_url = scheme + "://" + ascii_host
    if explicit_port:
        base_url = base_url + ":" + str(explicit_port)
    return {
        "input": (raw or "").strip(),
        "host": ascii_host,
        "unicode_host": unicode_host,
        "scheme": scheme,
        "port": port,
        "explicit_port": explicit_port,
        "path": path,
        "is_ip": is_ip,
        "base_url": base_url,
    }


def split_domain(host, is_ip):
    if is_ip:
        return {"registrable": host, "subdomain": "", "suffix": "", "tld": ""}
    try:
        import tldextract
        ext = tldextract.extract(host)
        if ext.suffix:
            if ext.domain:
                registrable = ext.domain + "." + ext.suffix
            else:
                registrable = host
            return {
                "registrable": registrable,
                "subdomain": ext.subdomain,
                "suffix": ext.suffix,
                "tld": ext.suffix.split(".")[-1],
            }
    except Exception:
        pass
    labels = host.split(".")
    if len(labels) >= 2:
        suffix = labels[-1]
        registrable = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
    else:
        suffix = host
        registrable = host
        subdomain = ""
    return {"registrable": registrable, "subdomain": subdomain, "suffix": suffix, "tld": suffix}


def describe_target(info):
    host = info["host"]
    labels = host.split(".")
    rows = []
    rows.append(("Input", info["input"]))
    rows.append(("Normalized URL", info["base_url"] + info["path"]))
    rows.append(("Scheme", info["scheme"]))
    rows.append(("Host", host))
    if info["unicode_host"] != host:
        rows.append(("Unicode host", info["unicode_host"]))
        rows.append(("Punycode", host))
    if info["explicit_port"]:
        rows.append(("Port", str(info["port"]) + " (explicit)"))
    else:
        rows.append(("Port", str(info["port"]) + " (default)"))
    rows.append(("Path", info["path"]))
    if info["is_ip"]:
        rows.append(("Host type", "IP address"))
    else:
        rows.append(("Host type", "Domain name"))
    rows.append(("Host length", str(len(host)) + " characters"))
    rows.append(("Label count", str(len(labels))))
    if not info["is_ip"]:
        parts = split_domain(host, info["is_ip"])
        rows.append(("Registrable domain", parts["registrable"]))
        if parts["subdomain"]:
            rows.append(("Subdomain", parts["subdomain"]))
            rows.append(("Subdomain depth", str(len(parts["subdomain"].split(".")))))
        else:
            rows.append(("Subdomain", "(none, apex domain)"))
            rows.append(("Subdomain depth", "0"))
        rows.append(("Public suffix", parts["suffix"]))
        rows.append(("Top level domain", parts["tld"]))
    return rows


def short(text, limit=300):
    cleaned = re.sub(r"\s+", " ", str(text).strip())
    if len(cleaned) > limit:
        return cleaned[:limit - 3] + "..."
    return cleaned


def now_utc():
    moment = datetime.datetime.now(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def export_json(path, result):
    import json
    data = {
        "tool": "DomainScan",
        "version": result["meta"]["version"],
        "scanned_at": result["meta"]["scanned_at"],
        "duration_seconds": result["meta"]["duration_seconds"],
        "target": result["target"],
        "sections": {},
    }
    for section, items in result["sections"].items():
        data["sections"][section] = [{"item": key, "value": value} for key, value in items]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def export_csv(path, result):
    import csv
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Section", "Item", "Value"])
        for section, items in result["sections"].items():
            for key, value in items:
                writer.writerow([section, key, value])


def export_txt(path, result):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("DomainScan report\n")
        handle.write("Target: " + result["target"]["host"] + "\n")
        handle.write("Scanned at: " + result["meta"]["scanned_at"] + "\n")
        handle.write("Duration: " + str(result["meta"]["duration_seconds"]) + " seconds\n\n")
        for section, items in result["sections"].items():
            handle.write("======== " + section + " ========\n")
            for key, value in items:
                handle.write(key + ": " + value + "\n")
            handle.write("\n")


def murmur3_32(data, seed=0):
    if isinstance(data, str):
        data = data.encode("utf-8")
    length = len(data)
    value = seed & 0xFFFFFFFF
    blocks = length // 4
    for i in range(blocks):
        key = data[i * 4] | (data[i * 4 + 1] << 8) | (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24)
        key = (key * 0xCC9E2D51) & 0xFFFFFFFF
        key = ((key << 15) | (key >> 17)) & 0xFFFFFFFF
        key = (key * 0x1B873593) & 0xFFFFFFFF
        value ^= key
        value = ((value << 13) | (value >> 19)) & 0xFFFFFFFF
        value = (value * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[blocks * 4:]
    key = 0
    if len(tail) >= 3:
        key ^= tail[2] << 16
    if len(tail) >= 2:
        key ^= tail[1] << 8
    if len(tail) >= 1:
        key ^= tail[0]
        key = (key * 0xCC9E2D51) & 0xFFFFFFFF
        key = ((key << 15) | (key >> 17)) & 0xFFFFFFFF
        key = (key * 0x1B873593) & 0xFFFFFFFF
        value ^= key
    value ^= length
    value ^= value >> 16
    value = (value * 0x85EBCA6B) & 0xFFFFFFFF
    value ^= value >> 13
    value = (value * 0xC2B2AE35) & 0xFFFFFFFF
    value ^= value >> 16
    return value


def favicon_hash(raw):
    import base64
    encoded = base64.encodebytes(raw or b"")
    digest = murmur3_32(encoded)
    if digest >= 0x80000000:
        digest -= 0x100000000
    return digest
