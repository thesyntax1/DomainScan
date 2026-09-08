import datetime
import ipaddress
import re
import socket

from domainscan import dns_check, rdap_check
from domainscan.helpers import BROWSER_UA, short


STATUS_MEANINGS = {
    "addperiod": "recently registered",
    "autorenewperiod": "expired, in grace period",
    "clientdeleteprohibited": "registrar locked against deletion",
    "clienthold": "registrar hold, DNS disabled",
    "clientrenewprohibited": "registrar locked against renewal",
    "clienttransferprohibited": "registrar locked against transfer",
    "clientupdateprohibited": "registrar locked against updates",
    "inactive": "not delegated",
    "linked": "associated with another object",
    "ok": "active",
    "pendingcreate": "creation in progress",
    "pendingdelete": "deletion in progress",
    "pendingrenew": "renewal in progress",
    "pendingrestore": "restoration in progress",
    "pendingtransfer": "transfer in progress",
    "pendingupdate": "update in progress",
    "redemptionperiod": "expired, restorable for a fee",
    "renewperiod": "recently renewed",
    "serverdeleteprohibited": "registry locked against deletion",
    "serverhold": "registry hold, DNS disabled",
    "serverrenewprohibited": "registry locked against renewal",
    "servertransferprohibited": "registry locked against transfer",
    "serverupdateprohibited": "registry locked against updates",
}


def collect(domain, host):
    rows = []
    if domain:
        target = domain
    else:
        target = host
    rows.append(("WHOIS query", target))
    try:
        ipaddress.ip_address(target)
        return collect_ip(rows, target)
    except ValueError:
        return collect_domain(rows, target)


def collect_domain(rows, target):
    payload, base, urls = fetch_domain_rdap(target)
    if urls:
        rows.append(("TLD RDAP", ", ".join(urls[:3])))
    if payload:
        if base:
            rows.append(("RDAP server", base))
        rows.extend(parse_rdap(payload))
        nameservers = extract_nameservers(rows)
        rows.extend(describe_nameservers(target, nameservers))
        rows.extend(contact_count_rows(rows))
        return {"rows": rows, "nameservers": nameservers}
    rows.append(("RDAP status", "RDAP lookup failed"))
    try:
        text, servers, iana_text = fetch_whois(target)
    except Exception as exc:
        rows.append(("WHOIS status", "WHOIS lookup failed (" + exc.__class__.__name__ + ")"))
        return {"rows": rows, "nameservers": []}
    rows.append(("WHOIS servers", ", ".join(servers)))
    rows.extend(parse_whois_text(text))
    if iana_text:
        rows.extend(parse_iana_tld(iana_text))
    rows.append(("Raw WHOIS lines", str(len(text.splitlines()))))
    if len(text) > 6000:
        rows.append(("Raw WHOIS", text[:6000] + "... (truncated)"))
    else:
        rows.append(("Raw WHOIS", text))
    nameservers = extract_nameservers(rows)
    rows.extend(describe_nameservers(target, nameservers))
    rows.extend(contact_count_rows(rows))
    return {"rows": rows, "nameservers": nameservers}


def collect_ip(rows, target):
    try:
        version = ipaddress.ip_address(target).version
    except Exception:
        version = 4
    if version == 6:
        kind = "ipv6"
    else:
        kind = "ipv4"
    try:
        data = rdap_check.bootstrap(kind)
        urls = rdap_check.find_services(data, kind, target)
    except Exception:
        urls = []
    payload = None
    base = ""
    for candidate in urls or []:
        try:
            payload = rdap_check.rdap_get(candidate.rstrip("/") + "/ip/" + target)
            base = candidate
            break
        except Exception:
            continue
    if not payload:
        rows.append(("IP WHOIS", "RIR lookup failed"))
        return {"rows": rows, "nameservers": []}
    rows.append(("RDAP server", base))
    rows.extend(parse_ip_rdap(payload))
    rows.extend(contact_count_rows(rows))
    return {"rows": rows, "nameservers": []}


def resolve_whois_target(raw):
    from domainscan import helpers
    info = helpers.parse_target(raw)
    if info["is_ip"]:
        return {"kind": "ip", "query": info["host"], "note": ""}
    parts = helpers.split_domain(info["host"], False)
    if parts["subdomain"]:
        return {"kind": "domain", "query": parts["registrable"], "note": "Using registrable domain " + parts["registrable"]}
    return {"kind": "domain", "query": info["host"], "note": ""}


def fetch_domain_rdap(target):
    tld = target.rsplit(".", 1)[-1].lower()
    try:
        data = rdap_check.bootstrap("dns")
        urls = rdap_check.find_services(data, "dns", tld)
    except Exception:
        urls = []
    for base in urls or []:
        try:
            payload = rdap_check.rdap_get(base.rstrip("/") + "/domain/" + target)
            return payload, base, urls
        except Exception:
            continue
    try:
        payload = fetch_rdap_proxy(target)
        return payload, "https://rdap.org (proxy)", urls or []
    except Exception:
        return None, "", urls or []


def fetch_rdap_proxy(domain):
    import requests
    url = "https://rdap.org/domain/" + domain
    headers = {"User-Agent": BROWSER_UA, "Accept": "application/json"}
    response = requests.get(url, timeout=12, headers=headers)
    response.raise_for_status()
    return response.json()


def status_meaning(code):
    clean = (code or "").split()[0].lower() if (code or "").split() else ""
    return STATUS_MEANINGS.get(clean, "")


def with_meaning(value):
    meaning = status_meaning(value)
    if meaning:
        return short(value, 140) + " (" + meaning + ")"
    return short(value, 160)


def extract_nameservers(rows):
    names = []
    for key, value in rows:
        if re.fullmatch(r"Nameserver \d+", key or ""):
            clean = (value or "").strip().rstrip(".")
            if clean and clean not in names:
                names.append(clean)
    return names


def describe_nameservers(domain, nameservers, resolver=None):
    rows = []
    if not nameservers:
        return rows
    if resolver is None:
        if not dns_check.HAS_DNSPYTHON:
            rows.append(("NS resolution", "Skipped (dnspython not installed)"))
            return rows
        resolver = dns_check.make_resolver()
    for clean in nameservers[:8]:
        name = clean.rstrip(".")
        note = ""
        if domain and (name.lower() == domain.lower() or name.lower().endswith("." + domain.lower())):
            note = " (in-bailiwick, needs glue)"
        try:
            result = dns_check.query(resolver, name, "A")
            records = result["records"]
        except Exception:
            records = []
        if records:
            rows.append(("NS check: " + name, "Resolves to " + ", ".join(records[:4]) + note))
        else:
            rows.append(("NS check: " + name, "Does not resolve (possible lame delegation)" + note))
    return rows


def contact_count_rows(rows):
    emails = [key for key, value in rows if (key or "").lower().endswith("email") and "@" in (value or "")]
    if emails:
        return [("Contact emails found", str(len(emails)))]
    return []


def parse_iana_tld(text):
    rows = []
    org = first_match(text, [r"^\s*organisation:\s*(.+)$"])
    if org:
        rows.append(("TLD manager", short(org, 160)))
    server = first_match(text, [r"^\s*whois:\s*(\S+)$"])
    if server:
        rows.append(("TLD whois server", server))
    status = first_match(text, [r"^\s*status:\s*(.+)$"])
    if status:
        rows.append(("TLD status", short(status, 120)))
    return rows


def parse_rdap(data):
    rows = []
    rows.append(("WHOIS source", "RDAP"))
    handle = data.get("handle", "")
    if handle:
        rows.append(("Registry handle", short(handle, 120)))
    name = data.get("ldhName", "")
    if name:
        rows.append(("Domain name", str(name)))
    port43 = data.get("port43", "")
    if port43:
        rows.append(("WHOIS server", str(port43)))
    for link in data.get("links", []) or []:
        if link.get("rel", "") == "related" and "rdap" in str(link.get("type", "")).lower():
            rows.append(("Registrar RDAP", short(link.get("href", ""), 200)))
            break
    statuses = data.get("status", []) or []
    if statuses:
        rows.append(("Status count", str(len(statuses))))
        for index, status in enumerate(statuses, 1):
            rows.append(("Status " + str(index), with_meaning(status)))
    else:
        rows.append(("Status", "None listed"))
    created = ""
    expires = ""
    for event in data.get("events", []) or []:
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action or date:
            rows.append(("Date " + short(action or "event", 40), short(date, 60)))
        if action == "registration":
            created = date
        elif action == "expiration":
            expires = date
    rows.extend(age_rows(created, expires))
    nameservers = data.get("nameservers", []) or []
    if nameservers:
        rows.append(("Nameserver count", str(len(nameservers))))
        for index, server in enumerate(nameservers, 1):
            rows.append(("Nameserver " + str(index), short(server.get("ldhName", ""), 160)))
            addresses = (server.get("ipAddresses", {}) or {}).get("v4", []) or []
            for address in addresses:
                rows.append(("Nameserver " + str(index) + " IPv4", str(address)))
    secure = data.get("secureDNS", {}) or {}
    if "delegationSigned" in secure:
        if secure["delegationSigned"]:
            rows.append(("DNSSEC delegation", "Signed"))
        else:
            rows.append(("DNSSEC delegation", "Unsigned"))
    entities = data.get("entities", []) or []
    contact_rows = []
    for entity in entities:
        contact_rows.extend(parse_entity(entity, ""))
    rows.extend(contact_rows)
    if not contact_rows:
        rows.append(("Registrant contact", "Redacted for privacy or not disclosed"))
    return rows


def parse_ip_rdap(data):
    rows = []
    rows.append(("WHOIS source", "IP RDAP (RIR)"))
    handle = data.get("handle", "")
    if handle:
        rows.append(("Resource handle", short(handle, 120)))
    name = data.get("name", "")
    if name:
        rows.append(("Net name", short(name, 120)))
    country = data.get("country", "")
    if country:
        rows.append(("Net country", str(country)))
    kind = data.get("type", "")
    if kind:
        rows.append(("Resource type", short(kind, 80)))
    parent = data.get("parentHandle", "")
    if parent:
        rows.append(("Parent handle", short(parent, 120)))
    start = data.get("startAddress", "")
    end = data.get("endAddress", "")
    if start or end:
        rows.append(("Address range", str(start) + " - " + str(end)))
    for block in data.get("cidr0_cidrs", []) or []:
        if block.get("v4prefix"):
            rows.append(("CIDR", str(block["v4prefix"])))
        if block.get("v6prefix"):
            rows.append(("CIDR", str(block["v6prefix"])))
    statuses = data.get("status", []) or []
    if statuses:
        rows.append(("Status count", str(len(statuses))))
        for index, status in enumerate(statuses, 1):
            rows.append(("Status " + str(index), short(status, 120)))
    for event in data.get("events", []) or []:
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action or date:
            rows.append(("Date " + short(action or "event", 40), short(date, 60)))
    remarks = data.get("remarks", []) or []
    shown = 0
    for remark in remarks:
        if shown >= 3:
            break
        lines = remark.get("description", []) or []
        text = " ".join(str(line) for line in lines).strip()
        if text:
            shown += 1
            rows.append(("Remark " + str(shown), short(text, 220)))
    entities = data.get("entities", []) or []
    contact_rows = []
    for entity in entities:
        contact_rows.extend(parse_entity(entity, ""))
    rows.extend(contact_rows)
    if not contact_rows:
        rows.append(("Contacts", "None disclosed"))
    return rows


def parse_entity(entity, prefix):
    rows = []
    roles = entity.get("roles", []) or []
    if roles:
        title = prefix + "/".join(roles)
    else:
        title = prefix + "contact"
    title = title[:1].upper() + title[1:]
    handle = entity.get("handle", "")
    if handle:
        rows.append((title + " handle", short(handle, 120)))
    contact = parse_vcard(entity.get("vcardArray", []))
    for key in ("name", "org", "email", "phone", "country"):
        if contact.get(key):
            rows.append((title + " " + key, short(contact[key], 160)))
    for sub in entity.get("entities", []) or []:
        rows.extend(parse_entity(sub, title + " "))
    return rows


def parse_vcard(vcard_array):
    info = {}
    try:
        items = vcard_array[1]
    except Exception:
        return info
    for entry in items or []:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        field = str(entry[0]).lower()
        raw_value = entry[3]
        if field == "adr":
            if isinstance(raw_value, list):
                bits = [str(bit).strip() for bit in raw_value if str(bit).strip()]
                if bits and "country" not in info:
                    info["country"] = bits[-1]
            continue
        if isinstance(raw_value, list):
            value = ", ".join(str(bit) for bit in raw_value if bit)
        else:
            value = str(raw_value)
        value = value.strip()
        if not value:
            continue
        if field == "fn" and "name" not in info:
            info["name"] = value
        elif field == "org" and "org" not in info:
            info["org"] = value
        elif field == "email" and "email" not in info:
            info["email"] = value
        elif field == "tel" and "phone" not in info:
            info["phone"] = value
    return info


def parse_date_flexible(text):
    cleaned = (text or "").strip()
    if not cleaned:
        return None
    try:
        candidate = cleaned
        if "T" in candidate and candidate[-1:] in ("Z", "z"):
            candidate = candidate[:-1] + "+00:00"
        return datetime.datetime.fromisoformat(candidate)
    except Exception:
        pass
    candidate = re.sub(r"\s+", " ", cleaned)
    patterns = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y %H:%M:%S %Z",
        "%Y.%m.%d",
        "%Y/%m/%d",
        "%b %d %Y",
        "%d %b %Y",
    ]
    for pattern in patterns:
        try:
            return datetime.datetime.strptime(candidate, pattern)
        except Exception:
            continue
    return None


def age_rows(created_text, expires_text):
    rows = []
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    created = parse_date_flexible(created_text)
    expires = parse_date_flexible(expires_text)
    if created:
        if created.tzinfo:
            created = created.replace(tzinfo=None)
        days = (now - created).days
        rows.append(("Domain age", str(days) + " days (" + str(round(days / 365.25, 1)) + " years)"))
    if expires:
        if expires.tzinfo:
            expires = expires.replace(tzinfo=None)
        left = (expires - now).days
        if left < 0:
            rows.append(("Domain expiry", "Expired " + str(abs(left)) + " days ago"))
        else:
            rows.append(("Domain expiry", "Expires in " + str(left) + " days"))
            if left < 30:
                rows.append(("Expiry urgency", "Expiring soon"))
    return rows


def whois_query(server, text, timeout=8):
    sock = socket.create_connection((server, 43), timeout=timeout)
    try:
        sock.sendall((text + "\r\n").encode("utf-8", "ignore"))
        sock.settimeout(timeout)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except Exception:
        return raw.decode("latin-1", "ignore")


def fetch_whois(domain):
    servers = []
    tld = domain.rsplit(".", 1)[-1]
    referral = ""
    iana_text = ""
    try:
        iana_text = whois_query("whois.iana.org", tld)
        match = re.search(r"whois:\s*(\S+)", iana_text)
        if match:
            referral = match.group(1).strip()
    except Exception:
        referral = ""
    if not referral:
        if tld in ("com", "net"):
            referral = "whois.verisign-grs.com"
        else:
            raise RuntimeError("No WHOIS server found for TLD")
    servers.append(referral)
    text = whois_query(referral, domain)
    second = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.IGNORECASE)
    if not second:
        second = re.search(r"^\s*Whois Server:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
    if second:
        registrar_server = second.group(1).strip()
        if registrar_server not in servers:
            try:
                detail = whois_query(registrar_server, domain)
            except Exception:
                detail = ""
            if len(detail) > 200:
                text = detail
                servers.append(registrar_server)
    return text, servers, iana_text


def first_match(text, patterns):
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(match.lastindex).strip()
            if value:
                return value
    return ""


def all_matches(text, patterns, limit=12):
    found = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            value = match.group(match.lastindex).strip()
            known = [item.lower() for item in found]
            if value and value.lower() not in known:
                found.append(value)
    return found[:limit]


def parse_whois_text(text):
    rows = []
    rows.append(("WHOIS source", "Port 43 WHOIS"))
    rows.append(("Raw record size", str(len(text)) + " characters"))
    fields = [
        ("Registrar", [r"^\s*registrar:\s*(.+)$"]),
        ("Registrar URL", [r"^\s*registrar url:\s*(.+)$", r"^\s*registrar website:\s*(.+)$"]),
        ("Registrar IANA ID", [r"^\s*registrar iana id:\s*(.+)$"]),
        ("Creation date", [r"^\s*creation date:\s*(.+)$", r"^\s*created:\s*(.+)$", r"^\s*registered on:\s*(.+)$", r"^\s*registration time:\s*(.+)$"]),
        ("Updated date", [r"^\s*updated date:\s*(.+)$", r"^\s*last updated:\s*(.+)$", r"^\s*last modified:\s*(.+)$"]),
        ("Expiry date", [r"^\s*registry expiry date:\s*(.+)$", r"^\s*registrar registration expiration date:\s*(.+)$", r"^\s*expiry date:\s*(.+)$", r"^\s*expiration date:\s*(.+)$", r"^\s*expire:\s*(.+)$"]),
        ("Registrant org", [r"^\s*registrant (organization|org):\s*(.+)$"]),
        ("Registrant country", [r"^\s*registrant country:\s*(.+)$"]),
        ("Registrant email", [r"^\s*registrant email:\s*(\S+)$"]),
        ("Admin email", [r"^\s*admin email:\s*(\S+)$"]),
        ("Tech email", [r"^\s*tech email:\s*(\S+)$"]),
        ("Abuse email", [r"^\s*registrar abuse contact email:\s*(\S+)$", r"^\s*abuse email:\s*(\S+)$"]),
        ("Abuse phone", [r"^\s*registrar abuse contact phone:\s*(.+)$", r"^\s*abuse phone:\s*(.+)$"]),
        ("DNSSEC", [r"^\s*dnssec:\s*(.+)$"]),
    ]
    values = {}
    for label, patterns in fields:
        value = first_match(text, patterns)
        if value:
            values[label] = value
            rows.append((label, short(value, 180)))
    rows.extend(age_rows(values.get("Creation date", ""), values.get("Expiry date", "")))
    statuses = all_matches(text, [r"^\s*domain status:\s*(.+)$", r"^\s*status:\s*(.+)$"])
    if statuses:
        rows.append(("Status count", str(len(statuses))))
        for index, status in enumerate(statuses, 1):
            rows.append(("Status " + str(index), with_meaning(status)))
    nameservers = all_matches(text, [r"^\s*name server:\s*(\S+)$", r"^\s*nserver:\s*(\S+)$"])
    if nameservers:
        rows.append(("Nameserver count", str(len(nameservers))))
        for index, server in enumerate(nameservers, 1):
            rows.append(("Nameserver " + str(index), short(server, 160)))
    if not values.get("Registrant org", "") and "redacted" in text.lower():
        rows.append(("Registrant contact", "Redacted for privacy"))
    return rows
