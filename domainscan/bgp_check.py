from domainscan.helpers import BROWSER_UA, fetch_json, short


def collect(ips):
    rows = []
    unique = []
    for ip in ips or []:
        if ip and ip not in unique:
            unique.append(ip)
    if not unique:
        rows.append(("BGP", "No IP addresses to check"))
        return {"rows": rows}
    for ip in unique[:2]:
        rows.extend(describe_ip(ip))
    if len(unique) > 2:
        rows.append(("BGP note", "Showing first 2 of " + str(len(unique)) + " addresses"))
    return {"rows": rows}


def describe_ip(ip):
    rows = [("BGP target", ip)]
    info = fetch_ip_info(ip)
    if not info:
        rows.append(("BGP " + ip, "Lookup failed"))
        return rows
    asn = parse_ip_info(info, ip, rows)
    prefix = info.get("prefix", "")
    if prefix:
        rows.extend(prefix_rows(prefix, ip))
    if asn and prefix:
        rows.extend(rpki_rows(asn, prefix, ip))
    if asn:
        detail = fetch_asn_info(asn)
        if detail:
            parse_asn_info(detail, asn, rows)
        peers = fetch_asn_peers(asn)
        if peers is not None:
            parse_peers(peers, asn, rows)
        rows.extend(asn_enrichment(asn))
    return rows


def asn_enrichment(asn):
    rows = []
    entry = fetch_peeringdb(asn)
    if entry:
        rows.append(("AS" + str(asn) + " PeeringDB", "Listed"))
        for key, label in (("name", "name"), ("aka", "aka"), ("website", "website"),
                            ("policy_general", "peering policy"), ("info_traffic", "traffic level"),
                            ("info_type", "network type"), ("irr_as_set", "AS-SET")):
            if entry.get(key):
                rows.append(("AS" + str(asn) + " " + label, short(str(entry[key]), 140)))
        return rows
    return asn_rdap_rows(asn)


def fetch_peeringdb(asn):
    try:
        data = fetch_json("https://www.peeringdb.com/api/net.json?asn=" + str(asn), timeout=10)
    except Exception:
        return None
    entries = data.get("data", []) or []
    if entries:
        return entries[0]
    return None


def asn_rdap_rows(asn):
    from domainscan import rdap_check, whois_check
    rows = []
    try:
        data = rdap_check.bootstrap("asn")
        urls = rdap_check.find_services(data, "asn", str(asn))
    except Exception:
        return rows
    payload = None
    for base in urls or []:
        try:
            payload = rdap_check.rdap_get(base.rstrip("/") + "/autnum/" + str(asn))
            break
        except Exception:
            continue
    if not payload:
        return rows
    rows.append(("AS" + str(asn) + " RDAP", "Record found"))
    if payload.get("name"):
        rows.append(("AS" + str(asn) + " name", short(payload["name"], 120)))
    if payload.get("country"):
        rows.append(("AS" + str(asn) + " country", str(payload["country"])))
    for entity in (payload.get("entities", []) or [])[:2]:
        for key, value in whois_check.parse_entity(entity, "")[:4]:
            rows.append(("AS" + str(asn) + " " + key.lower(), value))
    return rows


def prefix_rows(prefix, ip):
    rows = []
    try:
        data = fetch_json("https://api.bgpview.io/prefix/" + prefix, timeout=10)
    except Exception:
        return rows
    if data.get("status") != "ok":
        return rows
    info = data.get("data", {}) or {}
    for key, label in (("rir_allocation", "RIR allocation"), ("name", "Prefix name"),
                       ("description_short", "Prefix use"), ("country_code", "Prefix country")):
        if info.get(key):
            rows.append((ip + " " + label, short(str(info[key]), 140)))
    return rows


def rpki_rows(asn, prefix, ip):
    rows = []
    try:
        data = fetch_json("https://rpki.cloudflare.com/api/v1/validity/" + str(asn) + "/" + prefix, timeout=10)
    except Exception:
        return rows
    validity = (data.get("validity", {}) or {}).get("state", "")
    if validity == "valid":
        rows.append((ip + " RPKI", "Valid (route is authorized)"))
    elif validity == "invalid":
        rows.append((ip + " RPKI", "INVALID (possible hijack or misconfiguration)"))
    elif validity:
        rows.append((ip + " RPKI", validity))
    return rows


def fetch_ip_info(ip):
    try:
        data = fetch_json("https://api.bgpview.io/ip/" + ip, timeout=10)
    except Exception:
        return None
    if data.get("status") != "ok":
        return None
    return data.get("data", {})


def parse_ip_info(info, ip, rows):
    prefix = info.get("prefix", "")
    asn = info.get("asn", "")
    name = info.get("name", "")
    country = info.get("country_code", "")
    if prefix:
        rows.append((ip + " prefix", short(prefix, 60)))
    if asn:
        rows.append((ip + " origin ASN", "AS" + str(asn)))
    if name:
        rows.append((ip + " AS holder", short(name, 120)))
    if country:
        rows.append((ip + " AS country", str(country)))
    description = info.get("description", "")
    if description:
        rows.append((ip + " prefix use", short(description, 120)))
    if prefix:
        size = prefix_size(prefix)
        if size:
            rows.append((ip + " prefix size", size))
    if asn:
        return asn
    return 0


def prefix_size(prefix):
    import ipaddress
    try:
        network = ipaddress.ip_network(str(prefix), strict=False)
    except Exception:
        return ""
    bits = network.max_prefixlen - network.prefixlen
    if network.version == 6:
        return "2^" + str(bits) + " addresses"
    total = 2 ** bits
    if total == 1:
        return "1 address"
    return str(total) + " addresses"


def fetch_asn_info(asn):
    try:
        data = fetch_json("https://api.bgpview.io/asn/" + str(asn), timeout=10)
    except Exception:
        return None
    if data.get("status") != "ok":
        return None
    return data.get("data", {})


def parse_asn_info(detail, asn, rows):
    v4 = detail.get("ipv4_prefixes", []) or []
    v6 = detail.get("ipv6_prefixes", []) or []
    rows.append(("AS" + str(asn) + " IPv4 prefixes", str(len(v4))))
    rows.append(("AS" + str(asn) + " IPv6 prefixes", str(len(v6))))
    return rows


def fetch_asn_peers(asn):
    try:
        data = fetch_json("https://api.bgpview.io/asn/" + str(asn) + "/peers", timeout=10)
    except Exception:
        return None
    if data.get("status") != "ok":
        return None
    return data.get("data", [])


def parse_peers(peers, asn, rows):
    peers = peers or []
    rows.append(("AS" + str(asn) + " peer count", str(len(peers))))
    for index, peer in enumerate(peers[:5], 1):
        text = "AS" + str(peer.get("asn", "?")) + " " + str(peer.get("name", "")).strip()
        country = peer.get("country_code", "")
        if country:
            text = text + " (" + str(country) + ")"
        rows.append(("AS" + str(asn) + " peer " + str(index), short(text, 120)))
    return rows
