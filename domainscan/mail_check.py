import base64
import re
import socket
import time

from domainscan import dns_check
from domainscan.helpers import short


DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail",
    "dkim", "dkim1", "everly", "s1", "s2", "cm", "mandrill",
    "protonmail", "zoho",
]


def collect(host, apex, dns_data):
    rows = []
    if apex:
        name = apex
    else:
        name = host
    rows.append(("Mail domain", name))
    mx_records = dns_data.get("mx_apex") or dns_data.get("mx") or []
    txt_records = dns_data.get("txt_apex") or dns_data.get("txt") or []
    resolver = None
    if dns_check.HAS_DNSPYTHON:
        resolver = dns_check.make_resolver()
    rows.extend(describe_mx(mx_records, resolver))
    rows.extend(describe_spf(txt_records))
    if resolver is None:
        rows.append(("DMARC/DKIM", "Skipped (dnspython not installed)"))
        return {"rows": rows}
    rows.extend(describe_dmarc(resolver, name))
    rows.extend(describe_dkim(resolver, name))
    rows.extend(describe_bimi_mtasts(resolver, name))
    rows.extend(describe_tlsrpt(resolver, name))
    rows.extend(describe_autoconfig(resolver, name))
    rows.extend(describe_mta_sts_policy(name))
    return {"rows": rows}


def describe_mx(records, resolver=None):
    rows = []
    if not records:
        rows.append(("MX records", "None (domain cannot receive mail)"))
        return rows
    parsed = []
    for record in records:
        bits = record.split()
        if len(bits) >= 2:
            parsed.append((bits[0], bits[1].rstrip(".")))
        else:
            parsed.append(("", record.rstrip(".")))
    if len(parsed) == 1 and not parsed[0][1]:
        rows.append(("MX records", "Null MX (domain accepts no mail)"))
        return rows
    rows.append(("MX count", str(len(parsed))))
    ordered = sorted(parsed, key=lambda item: int(item[0]) if item[0].isdigit() else 999)
    for index, (preference, target) in enumerate(ordered, 1):
        if preference:
            rows.append(("MX " + str(index), "Preference " + preference + ", " + target))
        else:
            rows.append(("MX " + str(index), target))
        addresses = []
        try:
            addresses = socket.gethostbyname_ex(target)[2]
            rows.append(("MX " + str(index) + " addresses", ", ".join(addresses[:4])))
        except Exception:
            rows.append(("MX " + str(index) + " addresses", "Does not resolve"))
        if addresses:
            rows.append(("MX " + str(index) + " PTR", mx_ptr(addresses[0])))
        rows.append(("MX " + str(index) + " SMTP", smtp_probe(target)))
        rows.append(("MX " + str(index) + " STARTTLS", smtp_starttls(target)))
        if resolver is not None and index <= 3:
            rows.append(("MX " + str(index) + " DANE", dane_status(resolver, target)))
    return rows


def dane_status(resolver, target):
    try:
        result = dns_check.query(resolver, "_25._tcp." + target, "TLSA")
    except Exception:
        return "Lookup failed"
    if result["records"]:
        return "TLSA published (" + str(len(result["records"])) + " records)"
    return "No TLSA record"


def mx_ptr(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return "No PTR record"


def smtp_probe(target):
    started = time.perf_counter()
    try:
        sock = socket.create_connection((target, 25), timeout=4)
    except Exception:
        return "Port 25 unreachable or filtered"
    elapsed = int((time.perf_counter() - started) * 1000)
    banner = ""
    try:
        sock.settimeout(3)
        data = sock.recv(256).decode("utf-8", "ignore").strip()
        if data:
            banner = data.splitlines()[0]
    except Exception:
        banner = ""
    finally:
        try:
            sock.close()
        except Exception:
            pass
    if banner:
        return "Reachable (" + str(elapsed) + " ms), banner: " + short(banner, 120)
    return "Reachable (" + str(elapsed) + " ms)"


def read_smtp(sock, timeout=6):
    sock.settimeout(timeout)
    chunks = b""
    try:
        while len(chunks) < 4096:
            data = sock.recv(1024)
            if not data:
                break
            chunks += data
            lines = chunks.decode("utf-8", "ignore").splitlines()
            if lines and re.match(r"^\d{3} ", lines[-1]):
                break
    except Exception:
        pass
    return chunks.decode("utf-8", "ignore")


def smtp_starttls(target, port=25):
    try:
        sock = socket.create_connection((target, port), timeout=6)
    except Exception:
        return "Unreachable"
    try:
        banner = read_smtp(sock)
        if not banner.startswith("220"):
            return "Unexpected banner"
        sock.sendall(b"EHLO domainscan\r\n")
        greeting = read_smtp(sock)
        try:
            sock.sendall(b"QUIT\r\n")
        except Exception:
            pass
        if "starttls" in greeting.lower():
            return "Offered"
        return "Not offered"
    except Exception:
        return "Check failed"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def describe_spf(txt_records):
    rows = []
    spf = [item for item in txt_records if item.lower().startswith("v=spf1")]
    if not spf:
        rows.append(("SPF", "No SPF record published"))
        rows.append(("SPF protection", "Missing (sender address is easy to spoof)"))
        return rows
    value = spf[0]
    rows.append(("SPF record", short(value, 300)))
    if len(spf) > 1:
        rows.append(("SPF note", "Multiple SPF records found (invalid per RFC 7208)"))
    tokens = value.split()[1:]
    rows.append(("SPF mechanism count", str(len(tokens))))
    for index, token in enumerate(tokens, 1):
        rows.append(("SPF mechanism " + str(index), short(token, 160) + " (" + spf_meaning(token) + ")"))
    lookups = spf_lookups(tokens)
    rows.append(("SPF DNS lookups", str(lookups) + " of max 10"))
    if lookups > 10:
        rows.append(("SPF lookup limit", "Exceeded (receivers return permerror)"))
    issues = spf_issues(value, tokens, lookups)
    if issues:
        rows.append(("SPF issues", "; ".join(issues)))
    else:
        rows.append(("SPF issues", "None found"))
    policy = "No default policy"
    for token in tokens:
        if token.lower().endswith("all"):
            if token[:1] in "+-~?":
                qualifier = token[:1]
            else:
                qualifier = "+"
            meaning = {"+": "Pass (permissive)", "-": "Fail (strict)", "~": "SoftFail", "?": "Neutral"}.get(qualifier, "Pass")
            policy = meaning + " [" + token + "]"
    rows.append(("SPF default policy", policy))
    return rows


def spf_lookups(tokens):
    count = 0
    for token in tokens:
        if token[:1] in "+-~?":
            body = token[1:]
        else:
            body = token
        low = body.lower()
        if low.startswith(("include:", "redirect=", "exists:")):
            count += 1
        elif low in ("a", "mx", "ptr") or low.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            count += 1
    return count


def spf_issues(value, tokens, lookups):
    issues = []
    has_all = any(token.lower().endswith("all") for token in tokens)
    if not has_all:
        issues.append("no default all rule")
    if lookups > 10:
        issues.append("too many DNS lookups")
    if "redirect=" in value.lower() and len(tokens) > 1:
        issues.append("redirect combined with other mechanisms")
    for token in tokens:
        body = token[1:] if token[:1] in "+-~?" else token
        if body.lower() == "ptr" or body.lower().startswith("ptr:"):
            issues.append("ptr mechanism is slow and deprecated")
            break
    if "+all" in [token.lower() for token in tokens] or value.lower().split()[-1:] == ["all"]:
        issues.append("ends with permissive all")
    return issues


def spf_meaning(token):
    if token[:1] in "+-~?":
        body = token[1:]
    else:
        body = token
    low = body.lower()
    if low.startswith("include:"):
        return "include third party"
    if low.startswith("ip4:") or low.startswith("ip6:"):
        return "allow IP range"
    if low.startswith("redirect="):
        return "redirect lookup"
    if low.startswith("exp="):
        return "explanation"
    if low == "a":
        return "allow domain A records"
    if low.startswith("a:") or low.startswith("a/"):
        return "allow host A records"
    if low == "mx":
        return "allow MX hosts"
    if low.startswith("mx:") or low.startswith("mx/"):
        return "allow host MX"
    if low == "ptr":
        return "reverse DNS check"
    if low.startswith("exists:"):
        return "exists check"
    if low == "all":
        return "default rule"
    if "=" in body:
        return "modifier"
    return "mechanism"


def describe_dmarc(resolver, name):
    rows = []
    try:
        result = dns_check.query(resolver, "_dmarc." + name, "TXT")
    except Exception:
        rows.append(("DMARC", "Lookup failed"))
        return rows
    records = [dns_check.clean_txt(item) for item in result["records"]]
    dmarc = [item for item in records if "v=dmarc1" in item.lower()]
    if not dmarc:
        rows.append(("DMARC", "No DMARC record at _dmarc." + name))
        rows.append(("DMARC protection", "Missing"))
        return rows
    value = dmarc[0]
    rows.append(("DMARC record", short(value, 300)))
    tags = {}
    for part in value.split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    policy = tags.get("p", "").lower()
    if policy == "none":
        rows.append(("DMARC policy", "None (monitor only)"))
    elif policy == "quarantine":
        rows.append(("DMARC policy", "Quarantine (spam folder)"))
    elif policy == "reject":
        rows.append(("DMARC policy", "Reject (block)"))
    else:
        rows.append(("DMARC policy", policy or "Not specified"))
    for key in ("rua", "ruf", "pct", "sp", "adkim", "aspf", "fo", "ri"):
        if tags.get(key):
            rows.append(("DMARC " + key, short(tags[key], 200)))
    return rows


def describe_dkim(resolver, name):
    rows = []
    checked = []
    found = []
    for selector in DKIM_SELECTORS:
        try:
            result = dns_check.query(resolver, selector + "._domainkey." + name, "TXT")
        except Exception:
            continue
        checked.append(selector)
        records = [dns_check.clean_txt(item) for item in result["records"]]
        dkim = [item for item in records if "v=dkim1" in item.lower() or "p=" in item.lower()]
        if dkim:
            found.append((selector, dkim[0]))
    rows.append(("DKIM selectors checked", str(len(checked)) + " (" + ", ".join(checked) + ")"))
    if not found:
        rows.append(("DKIM", "No DKIM keys found on common selectors"))
        return rows
    rows.append(("DKIM keys found", str(len(found))))
    for selector, value in found:
        rows.append(("DKIM " + selector, short(value, 220)))
        bits = dkim_key_bits(value)
        if bits:
            rows.append(("DKIM " + selector + " key", "~" + str(bits) + "-bit RSA"))
    return rows


def dkim_key_bits(value):
    match = re.search(r"p=([A-Za-z0-9+/=\s]+)", value)
    if not match:
        return 0
    key = re.sub(r"\s+", "", match.group(1))
    if not key:
        return 0
    try:
        raw = base64.b64decode(key)
        return len(raw) * 8
    except Exception:
        return 0


def describe_bimi_mtasts(resolver, name):
    rows = []
    try:
        bimi = dns_check.query(resolver, "default._bimi." + name, "TXT")
        records = [dns_check.clean_txt(item) for item in bimi["records"]]
        if records:
            rows.append(("BIMI", short(records[0], 200)))
        else:
            rows.append(("BIMI", "No BIMI record"))
    except Exception:
        rows.append(("BIMI", "Lookup failed"))
    try:
        sts = dns_check.query(resolver, "_mta-sts." + name, "TXT")
        records = [dns_check.clean_txt(item) for item in sts["records"]]
        if records:
            rows.append(("MTA-STS", short(records[0], 200)))
        else:
            rows.append(("MTA-STS", "No MTA-STS DNS record"))
    except Exception:
        rows.append(("MTA-STS", "Lookup failed"))
    return rows


def describe_tlsrpt(resolver, name):
    rows = []
    try:
        result = dns_check.query(resolver, "_smtp._tls." + name, "TXT")
        records = [dns_check.clean_txt(item) for item in result["records"]]
    except Exception:
        rows.append(("TLS-RPT", "Lookup failed"))
        return rows
    if records:
        rows.append(("TLS-RPT", short(records[0], 220)))
    else:
        rows.append(("TLS-RPT", "No TLS-RPT record"))
    return rows


def describe_mta_sts_policy(name, base_url=None):
    import requests
    from domainscan.helpers import BROWSER_UA
    rows = []
    if base_url:
        url = base_url + "/.well-known/mta-sts.txt"
    else:
        url = "https://mta-sts." + name + "/.well-known/mta-sts.txt"
    try:
        response = requests.get(url, timeout=8, headers={"User-Agent": BROWSER_UA})
    except Exception:
        rows.append(("MTA-STS policy", "Fetch failed"))
        return rows
    if response.status_code != 200:
        rows.append(("MTA-STS policy", "Not published (HTTP " + str(response.status_code) + ")"))
        return rows
    rows.append(("MTA-STS policy", "Published"))
    for field in ("version", "mode", "max_age"):
        match = re.search(r"^" + field + r":\s*(.+)$", response.text or "", re.IGNORECASE | re.MULTILINE)
        if match:
            rows.append(("MTA-STS " + field, short(match.group(1).strip(), 120)))
    mx_list = re.findall(r"^mx:\s*(.+)$", response.text or "", re.IGNORECASE | re.MULTILINE)
    rows.append(("MTA-STS MX patterns", str(len(mx_list))))
    for index, pattern in enumerate(mx_list[:5], 1):
        rows.append(("MTA-STS MX " + str(index), short(pattern.strip(), 120)))
    return rows


def describe_autoconfig(resolver, name):
    rows = []
    for prefix in ("autodiscover", "autoconfig"):
        try:
            result = dns_check.query(resolver, prefix + "." + name, "A")
            records = result["records"]
        except Exception:
            records = []
        if records:
            rows.append((prefix + "." + name, ", ".join(records)))
        else:
            rows.append((prefix + "." + name, "No A record"))
    return rows
