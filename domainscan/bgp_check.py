from domainscan.helpers import BROWSER_UA, short


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
    if asn:
        detail = fetch_asn_info(asn)
        if detail:
            parse_asn_info(detail, asn, rows)
        peers = fetch_asn_peers(asn)
        if peers is not None:
            parse_peers(peers, asn, rows)
    return rows


def fetch_ip_info(ip):
    import requests
    try:
        response = requests.get("https://api.bgpview.io/ip/" + ip, timeout=10, headers={"User-Agent": BROWSER_UA})
        data = response.json()
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
    if asn:
        return asn
    return 0


def fetch_asn_info(asn):
    import requests
    try:
        response = requests.get("https://api.bgpview.io/asn/" + str(asn), timeout=10, headers={"User-Agent": BROWSER_UA})
        data = response.json()
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
    import requests
    try:
        response = requests.get("https://api.bgpview.io/asn/" + str(asn) + "/peers", timeout=10, headers={"User-Agent": BROWSER_UA})
        data = response.json()
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
