import base64
import re
import socket
import time

from domainscan import dns_check
from domainscan.helpers import short


DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "everly"]


def collect(host, apex, dns_data):
    rows = []
    if apex:
        name = apex
    else:
        name = host
    rows.append(("Mail domain", name))
    mx_records = dns_data.get("mx_apex") or dns_data.get("mx") or []
    txt_records = dns_data.get("txt_apex") or dns_data.get("txt") or []
    rows.extend(describe_mx(mx_records))
    rows.extend(describe_spf(txt_records))
    if dns_check.HAS_DNSPYTHON:
        resolver = dns_check.make_resolver()
        rows.extend(describe_dmarc(resolver, name))
        rows.extend(describe_dkim(resolver, name))
        rows.extend(describe_bimi_mtasts(resolver, name))
    else:
        rows.append(("DMARC/DKIM", "Skipped (dnspython not installed)"))
    return {"rows": rows}


def describe_mx(records):
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
        try:
            resolved = socket.gethostbyname_ex(target)[2]
            rows.append(("MX " + str(index) + " addresses", ", ".join(resolved[:4])))
        except Exception:
            rows.append(("MX " + str(index) + " addresses", "Does not resolve"))
        rows.append(("MX " + str(index) + " SMTP", smtp_probe(target)))
    return rows


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
