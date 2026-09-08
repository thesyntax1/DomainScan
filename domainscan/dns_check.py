import socket

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


HOST_TYPES = ["A", "AAAA", "CNAME"]
DOMAIN_TYPES = ["MX", "NS", "TXT", "SOA", "CAA"]


def make_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 8.0
    return resolver


def query(resolver, name, rtype):
    try:
        answer = resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return {"records": [], "ttl": 0, "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"records": [], "ttl": 0, "error": "NoAnswer"}
    except dns.exception.Timeout:
        return {"records": [], "ttl": 0, "error": "Timeout"}
    except Exception as exc:
        return {"records": [], "ttl": 0, "error": exc.__class__.__name__}
    try:
        ttl = answer.rrset.ttl
    except Exception:
        ttl = 0
    return {"records": [item.to_text() for item in answer], "ttl": ttl, "error": ""}


def clean_txt(text):
    chunks = [chunk.strip() for chunk in text.split('"')]
    chunks = [chunk for chunk in chunks if chunk]
    if chunks:
        return " ".join(chunks)
    return text


def query_type(resolver, name, rtype, rows, tag):
    try:
        result = query(resolver, name, rtype)
    except Exception as exc:
        rows.append((rtype + " records" + tag, "Lookup failed (" + exc.__class__.__name__ + ")"))
        return []
    if result["error"] == "NXDOMAIN":
        rows.append((rtype + " records" + tag, "NXDOMAIN (name does not exist)"))
        return []
    if result["error"] or not result["records"]:
        rows.append((rtype + " records" + tag, "None found"))
        return []
    rows.append((rtype + " record count" + tag, str(len(result["records"]))))
    if result["ttl"]:
        rows.append((rtype + " TTL" + tag, str(result["ttl"]) + " seconds"))
    cleaned = []
    for index, record in enumerate(result["records"], 1):
        if rtype == "TXT":
            value = clean_txt(record)
        else:
            value = record
        rows.append((rtype + " record " + str(index) + tag, value))
        cleaned.append(value)
    return cleaned


def collect(host, apex):
    rows = []
    data = {
        "a": [], "aaaa": [], "cname": [],
        "mx": [], "mx_apex": [], "ns": [], "ns_apex": [],
        "txt": [], "txt_apex": [], "soa": [], "soa_apex": [],
        "caa": [], "caa_apex": [], "ds": [], "dnskey": [],
    }
    if not HAS_DNSPYTHON:
        return collect_fallback(host, rows, data)
    resolver = make_resolver()
    if resolver.nameservers:
        rows.append(("DNS resolver", ", ".join(resolver.nameservers)))
    else:
        rows.append(("DNS resolver", "system default"))
    data["a"] = query_type(resolver, host, "A", rows, "")
    data["aaaa"] = query_type(resolver, host, "AAAA", rows, "")
    data["cname"] = query_type(resolver, host, "CNAME", rows, "")
    if data["cname"]:
        rows.append(("CNAME target", data["cname"][0]))
    for rtype in DOMAIN_TYPES:
        key = rtype.lower()
        data[key] = query_type(resolver, host, rtype, rows, "")
        if apex and apex != host:
            data[key + "_apex"] = query_type(resolver, apex, rtype, rows, " (apex)")
        else:
            data[key + "_apex"] = list(data[key])
    if apex and apex != host:
        data["ds"] = query_type(resolver, apex, "DS", rows, " (apex)")
        data["dnskey"] = query_type(resolver, apex, "DNSKEY", rows, " (apex)")
    else:
        data["ds"] = query_type(resolver, host, "DS", rows, "")
        data["dnskey"] = query_type(resolver, host, "DNSKEY", rows, "")
    for service in ("_https._tcp", "_http._tcp"):
        query_type(resolver, service + "." + host, "SRV", rows, " (" + service + ")")
    if data["ds"] or data["dnskey"]:
        rows.append(("DNSSEC", "Signed (DS/DNSKEY records published)"))
    else:
        rows.append(("DNSSEC", "No DS/DNSKEY records found"))
    return {"rows": rows, "data": data}


def collect_fallback(host, rows, data):
    rows.append(("DNS library", "dnspython not installed, system resolver used (limited)"))
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as exc:
        rows.append(("DNS status", "Resolution failed (" + exc.__class__.__name__ + ")"))
        return {"rows": rows, "data": data}
    addresses = sorted(set(item[4][0] for item in infos))
    for address in addresses:
        if ":" in address:
            data["aaaa"].append(address)
        else:
            data["a"].append(address)
    rows.append(("IP address count", str(len(addresses))))
    for index, address in enumerate(addresses, 1):
        rows.append(("IP address " + str(index), address))
    return {"rows": rows, "data": data}
