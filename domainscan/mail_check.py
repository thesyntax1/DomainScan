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
    spf_rows = describe_spf(txt_records, resolver, name)
    rows.extend(spf_rows)
    if resolver is None:
        rows.append(("DMARC/DKIM", "Skipped (dnspython not installed)"))
        return {"rows": rows}
    rows.extend(describe_dmarc(resolver, name))
    rows.extend(describe_dkim(resolver, name))
    rows.extend(describe_bimi_mtasts(resolver, name))
    rows.extend(describe_tlsrpt(resolver, name))
    rows.extend(describe_autoconfig(resolver, name))
    mx_hosts = []
    for record in mx_records:
        bits = record.split()
        if len(bits) >= 2:
            mx_hosts.append(bits[1].rstrip(".").lower())
    rows.extend(describe_mta_sts_policy(name, mx_hosts=mx_hosts))
    rows.extend(spoof_rows(spf_rows, rows))
    return {"rows": rows}


def spoof_rows(spf_rows, all_rows):
    rows = []
    flat = {str(key).lower(): str(text) for key, text in list(spf_rows) + list(all_rows)}
    spf = flat.get("spf default policy", "").lower()
    dmarc = flat.get("dmarc policy", "").lower()
    dkim = "dkim keys found" in flat
    if "fail (strict)" in spf and "reject" in dmarc:
        rows.append(("Spoofability", "Protected (strict SPF with DMARC reject)"))
    elif "reject" in dmarc or "quarantine" in dmarc:
        rows.append(("Spoofability", "Mostly protected (DMARC enforced, harden SPF to -all)"))
    elif "monitor only" in dmarc or "softfail" in spf or "neutral" in spf:
        rows.append(("Spoofability", "Spoofable (weak policy, upgrade to DMARC reject)"))
    elif dkim:
        rows.append(("Spoofability", "Spoofable (DKIM alone does not stop spoofing)"))
    else:
        rows.append(("Spoofability", "Easily spoofable (no effective authentication)"))
    return rows


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
    rows.extend(mx_health(parsed, resolver))
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
            ptr = mx_ptr(addresses[0])
            rows.append(("MX " + str(index) + " PTR", ptr))
            rows.append(("MX " + str(index) + " FCrDNS", mx_forward_confirm(ptr, addresses[0])))
        rows.append(("MX " + str(index) + " SMTP", smtp_probe(target)))
        rows.append(("MX " + str(index) + " STARTTLS", smtp_starttls(target)))
        if index <= 2:
            rows.extend(smtp_ehlo_rows(target, index))
        if index == 1:
            rows.extend(smtp_tls_cert_rows(target))
            rows.extend(smtp_vrfy_rows(target))
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


def mx_forward_confirm(ptr, ip):
    if not ptr or ptr == "No PTR record":
        return "Skipped (no PTR)"
    try:
        forward = socket.gethostbyname_ex(ptr)[2]
    except Exception:
        return "Reverse name does not resolve forward"
    if ip in forward:
        return "Confirmed (forward matches)"
    return "Mismatch (forward gives " + ", ".join(forward[:3]) + ")"


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


def mx_health(parsed, resolver):
    rows = []
    prefs = [pref for pref, _ in parsed if pref]
    if len(prefs) != len(set(prefs)):
        rows.append(("MX preferences", "Duplicate preference values (load-balanced)"))
    for _, target in parsed[:4]:
        if not target:
            continue
        if resolver is not None:
            try:
                cname = dns_check.query(resolver, target, "CNAME")
                if cname["records"]:
                    rows.append(("MX alias: " + target, "Points to CNAME (violates RFC 2181)"))
            except Exception:
                pass
        try:
            addresses = socket.gethostbyname_ex(target)[2]
        except Exception:
            addresses = []
        for address in addresses:
            if is_private_ip(address):
                rows.append(("MX address: " + target, address + " is private (unreachable from internet)"))
    return rows


def is_private_ip(address):
    try:
        parts = [int(bit) for bit in address.split(".")]
    except Exception:
        return False
    if len(parts) != 4:
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


def smtp_ehlo_rows(target, index):
    rows = []
    prefix = "MX " + str(index)
    try:
        sock = socket.create_connection((target, 25), timeout=6)
    except Exception:
        return rows
    try:
        banner = read_smtp(sock)
        if not banner.startswith("220"):
            return rows
        sock.sendall(b"EHLO domainscan\r\n")
        greeting = read_smtp(sock)
        try:
            sock.sendall(b"QUIT\r\n")
        except Exception:
            pass
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return rows
    try:
        sock.close()
    except Exception:
        pass
    extensions = parse_ehlo(greeting)
    if not extensions:
        return rows
    rows.append((prefix + " ESMTP", str(len(extensions)) + " extensions"))
    interesting = [item for item in extensions if item.split()[0] in ("STARTTLS", "AUTH", "SIZE", "8BITMIME", "PIPELINING", "DSN", "SMTPUTF8", "CHUNKING")]
    for item in interesting[:8]:
        rows.append((prefix + " ESMTP " + item.split()[0], short(item, 120)))
    auth = [item for item in extensions if item.startswith("AUTH")]
    if auth:
        rows.append((prefix + " AUTH mechs", short(auth[0].replace("AUTH", "").strip(), 120)))
    return rows


def parse_ehlo(greeting):
    extensions = []
    lines = (greeting or "").splitlines()
    for line in lines[1:]:
        match = re.match(r"^\d{3}[ -](.+)$", line.strip())
        if not match:
            continue
        text = match.group(1).strip()
        if text and text not in extensions:
            extensions.append(text)
    return extensions


def smtp_tls_cert_rows(target):
    try:
        import shutil
        import subprocess
        if not shutil.which("openssl"):
            return []
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", target + ":25", "-starttls", "smtp", "-showcerts"],
            input="", capture_output=True, text=True, timeout=10)
    except Exception:
        return [("MX 1 TLS cert", "STARTTLS probe failed")]
    output = proc.stdout or ""
    if "BEGIN CERTIFICATE" not in output:
        return []
    rows = [("MX 1 TLS cert", "Certificate presented over STARTTLS")]
    match = re.search(r"^\s*(?:\d+\s+)?s:(.+)$", output, re.MULTILINE)
    if match:
        rows.append(("MX 1 cert subject", short(match.group(1).strip(), 160)))
    return rows


def smtp_vrfy_rows(target):
    rows = []
    try:
        sock = socket.create_connection((target, 25), timeout=6)
    except Exception:
        return rows
    try:
        banner = read_smtp(sock)
        if not banner.startswith("220"):
            return rows
        sock.sendall(b"EHLO domainscan\r\n")
        read_smtp(sock)
        sock.sendall(b"VRFY root\r\n")
        vrfy = read_smtp(sock)
        sock.sendall(b"EXPN root\r\n")
        expn = read_smtp(sock)
        try:
            sock.sendall(b"QUIT\r\n")
        except Exception:
            pass
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return rows
    try:
        sock.close()
    except Exception:
        pass
    rows.append(("MX 1 VRFY", vrfy_verdict(vrfy, "VRFY")))
    rows.append(("MX 1 EXPN", vrfy_verdict(expn, "EXPN")))
    return rows


def vrfy_verdict(reply, command):
    first = (reply or "").splitlines()
    code = first[0][:3] if first else ""
    if code in ("250", "251", "252"):
        return command + " accepted (user enumeration possible)"
    if code in ("502", "504", "500"):
        return command + " disabled (good)"
    if code:
        return command + " answered " + code
    return command + " gave no answer"


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


def describe_spf(txt_records, resolver=None, name=""):
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
    if resolver is not None and name:
        rows.extend(spf_chain_rows(resolver, name, tokens, value))
    return rows


def spf_chain_rows(resolver, name, tokens, value):
    rows = []
    targets = []
    for token in tokens:
        body = token[1:] if token[:1] in "+-~?" else token
        low = body.lower()
        if low.startswith("include:"):
            targets.append(("include", body[8:]))
        elif low.startswith("redirect="):
            targets.append(("redirect", body[9:]))
    if not targets:
        return rows
    seen = {name.lower()}
    total = spf_lookups(tokens)
    for kind, target in targets[:5]:
        target = target.strip().rstrip(".")
        if not target or target.lower() in seen:
            rows.append(("SPF " + kind + " " + target, "Skipped (loop)"))
            continue
        seen.add(target.lower())
        try:
            result = dns_check.query(resolver, target, "TXT")
            records = [dns_check.clean_txt(item) for item in result["records"]]
        except Exception:
            rows.append(("SPF " + kind + " " + short(target, 80), "DNS lookup failed"))
            continue
        nested = [item for item in records if item.lower().startswith("v=spf1")]
        if not nested:
            rows.append(("SPF " + kind + " " + short(target, 80), "Target has no SPF record (permerror)"))
            continue
        nested_tokens = nested[0].split()[1:]
        nested_count = spf_lookups(nested_tokens)
        total += nested_count
        rows.append(("SPF " + kind + " " + short(target, 80), str(nested_count) + " further lookups, ends " + short(nested_tokens[-1] if nested_tokens else "?", 40)))
    rows.append(("SPF total lookups", str(total) + " across chain (limit 10)"))
    if total > 10:
        rows.append(("SPF chain verdict", "Chain exceeds 10 lookups (receivers return permerror)"))
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
    if len(dmarc) > 1:
        rows.append(("DMARC note", "Multiple DMARC records (invalid, receivers ignore)"))
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
    if policy in ("quarantine", "reject") and tags.get("pct", "100") != "100":
        rows.append(("DMARC coverage", "Only " + tags.get("pct") + "% of mail enforced"))
    rows.extend(dmarc_external_auth(resolver, name, tags.get("rua", "")))
    return rows


def dmarc_external_auth(resolver, name, rua):
    rows = []
    if not rua:
        return rows
    for mailbox in rua.split(","):
        mailbox = mailbox.strip()
        if "@" not in mailbox:
            continue
        host = mailbox.rsplit("@", 1)[1].strip().rstrip("!").rstrip(".")
        if not host or host.lower() == name.lower() or host.lower().endswith("." + name.lower()):
            continue
        try:
            result = dns_check.query(resolver, name + "._report._dmarc." + host, "TXT")
            records = [dns_check.clean_txt(item) for item in result["records"]]
        except Exception:
            records = []
        if any("v=dmarc1" in item.lower() for item in records):
            rows.append(("DMARC auth " + host, "External reports authorized"))
        else:
            rows.append(("DMARC auth " + host, "Missing authorization (reports rejected)"))
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
            if bits < 1024:
                rows.append(("DKIM " + selector + " strength", "Under 1024 bits (weak, upgrade key)"))
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
            rows.extend(bimi_logo_rows(records[0]))
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


def bimi_logo_rows(record):
    rows = []
    match = re.search(r"l=([^;\s]+)", record or "")
    if not match:
        return rows
    url = match.group(1).strip()
    rows.append(("BIMI logo", short(url, 200)))
    if not url.lower().startswith("https://"):
        rows.append(("BIMI logo URL", "Not HTTPS (invalid)"))
        return rows
    import requests
    from domainscan.helpers import BROWSER_UA
    try:
        response = requests.head(url, timeout=8, headers={"User-Agent": BROWSER_UA}, allow_redirects=True)
        if response.status_code == 405:
            response = requests.get(url, timeout=8, headers={"User-Agent": BROWSER_UA}, stream=True)
            response.close()
        rows.append(("BIMI logo fetch", "HTTP " + str(response.status_code) + ", " + short(response.headers.get("Content-Type", "?"), 60)))
        rows.extend(bimi_svg_rows(url))
    except Exception as exc:
        rows.append(("BIMI logo fetch", "Failed (" + exc.__class__.__name__ + ")"))
    if "a=" in record:
        rows.append(("BIMI authority", short(re.search(r"a=([^;\s]+)", record).group(1), 160)))
    return rows


def bimi_svg_rows(url):
    import requests
    from domainscan.helpers import BROWSER_UA
    rows = []
    try:
        response = requests.get(url, timeout=8, headers={"User-Agent": BROWSER_UA})
    except Exception:
        return rows
    if response.status_code != 200:
        return rows
    body = response.content or b""
    rows.append(("BIMI logo size", str(len(body)) + " bytes"))
    text = body[:4000].decode("utf-8", "ignore").lower()
    if "<svg" not in text:
        rows.append(("BIMI logo format", "Not an SVG document (invalid)"))
        return rows
    problems = []
    if "<script" in text:
        problems.append("contains script")
    bare = re.sub(r'xmlns(?::\w+)?="[^"]*"', "", text)
    if "http://" in bare:
        problems.append("references plain HTTP")
    if len(body) > 32768:
        problems.append("over 32 KB profile limit")
    if problems:
        rows.append(("BIMI logo format", "SVG but " + ", ".join(problems)))
    else:
        rows.append(("BIMI logo format", "Valid SVG Tiny profile candidate"))
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


def describe_mta_sts_policy(name, base_url=None, mx_hosts=None):
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
    mode_match = re.search(r"^mode:\s*(.+)$", response.text or "", re.IGNORECASE | re.MULTILINE)
    if mode_match:
        mode = mode_match.group(1).strip().lower()
        if mode == "enforce":
            rows.append(("MTA-STS verdict", "Enforcing (unsigned mail rejected)"))
        else:
            rows.append(("MTA-STS verdict", "Testing only (no enforcement)"))
    age_match = re.search(r"^max_age:\s*(\d+)", response.text or "", re.IGNORECASE | re.MULTILINE)
    if age_match:
        days = int(age_match.group(1)) // 86400
        rows.append(("MTA-STS max age", age_match.group(1) + " seconds (~" + str(days) + " days)"))
    for field in ("version", "mode", "max_age"):
        match = re.search(r"^" + field + r":\s*(.+)$", response.text or "", re.IGNORECASE | re.MULTILINE)
        if match:
            rows.append(("MTA-STS " + field, short(match.group(1).strip(), 120)))
    mx_list = re.findall(r"^mx:\s*(.+)$", response.text or "", re.IGNORECASE | re.MULTILINE)
    rows.append(("MTA-STS MX patterns", str(len(mx_list))))
    for index, pattern in enumerate(mx_list[:5], 1):
        rows.append(("MTA-STS MX " + str(index), short(pattern.strip(), 120)))
    rows.extend(mta_sts_mx_match(mx_list, mx_hosts or []))
    return rows


def mta_sts_mx_match(patterns, mx_hosts):
    import fnmatch
    rows = []
    if not patterns or not mx_hosts:
        return rows
    uncovered = []
    for host in mx_hosts:
        matched = False
        for pattern in patterns:
            clean = pattern.strip().lower()
            if fnmatch.fnmatch(host, clean):
                matched = True
                break
        if not matched:
            uncovered.append(host)
    if uncovered:
        rows.append(("MTA-STS coverage", str(len(uncovered)) + " MX hosts not matched: " + short(", ".join(uncovered[:4]), 180)))
    else:
        rows.append(("MTA-STS coverage", "All MX hosts match policy patterns"))
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
