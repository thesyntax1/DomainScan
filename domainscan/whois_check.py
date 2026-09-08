import datetime
import re
import socket

from domainscan.helpers import BROWSER_UA, short


def collect(domain, host):
    rows = []
    if domain:
        target = domain
    else:
        target = host
    rows.append(("WHOIS query", target))
    try:
        data = fetch_rdap(target)
    except Exception as exc:
        data = None
        rows.append(("RDAP status", "RDAP lookup failed (" + exc.__class__.__name__ + ")"))
    if data:
        rows.extend(parse_rdap(data))
        return {"rows": rows}
    try:
        text, servers = fetch_whois(target)
    except Exception as exc:
        rows.append(("WHOIS status", "WHOIS lookup failed (" + exc.__class__.__name__ + ")"))
        return {"rows": rows}
    rows.append(("WHOIS servers", ", ".join(servers)))
    rows.extend(parse_whois_text(text))
    return {"rows": rows}


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


def fetch_rdap(domain):
    import requests
    url = "https://rdap.org/domain/" + domain
    headers = {"User-Agent": BROWSER_UA, "Accept": "application/json"}
    response = requests.get(url, timeout=12, headers=headers)
    response.raise_for_status()
    return response.json()


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
    statuses = data.get("status", []) or []
    if statuses:
        rows.append(("Status count", str(len(statuses))))
        for index, status in enumerate(statuses, 1):
            rows.append(("Status " + str(index), short(status, 160)))
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
    return text, servers


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
            rows.append(("Status " + str(index), short(status, 160)))
    nameservers = all_matches(text, [r"^\s*name server:\s*(\S+)$", r"^\s*nserver:\s*(\S+)$"])
    if nameservers:
        rows.append(("Nameserver count", str(len(nameservers))))
        for index, server in enumerate(nameservers, 1):
            rows.append(("Nameserver " + str(index), short(server, 160)))
    if not values.get("Registrant org", "") and "redacted" in text.lower():
        rows.append(("Registrant contact", "Redacted for privacy"))
    return rows
