import socket

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


HOST_TYPES = ["A", "AAAA", "CNAME"]
DOMAIN_TYPES = ["MX", "NS", "TXT", "SOA", "CAA"]
EXTRA_HOST_TYPES = ["HTTPS", "SVCB", "SSHFP", "NAPTR", "LOC"]


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


def follow_cname(resolver, host, cap=5):
    chain = []
    current = host
    for _ in range(cap):
        try:
            result = query(resolver, current, "CNAME")
        except Exception:
            break
        if not result["records"]:
            break
        target = result["records"][0].rstrip(".")
        if not target or target in chain:
            break
        chain.append(target)
        current = target
    return chain


def parse_soa(records):
    rows = []
    if not records:
        return rows
    parts = records[0].split()
    if len(parts) < 7:
        rows.append(("SOA details", records[0]))
        return rows
    rows.append(("SOA primary NS", parts[0]))
    rows.append(("SOA contact", parts[1].rstrip(".").replace(".", "@", 1)))
    rows.append(("SOA serial", parts[2]))
    rows.append(("SOA refresh", parts[3] + " seconds"))
    rows.append(("SOA retry", parts[4] + " seconds"))
    rows.append(("SOA expire", parts[5] + " seconds"))
    rows.append(("SOA minimum TTL", parts[6] + " seconds"))
    return rows


def parse_caa(records):
    rows = []
    if not records:
        rows.append(("CAA policy", "No CAA records (any CA may issue)"))
        return rows
    count = 0
    for record in records:
        parts = record.split(None, 2)
        if len(parts) < 3:
            continue
        count += 1
        tag = parts[1].lower()
        value = parts[2].strip().strip('"')
        rows.append(("CAA policy " + str(count), tag + " " + value + " (flags " + parts[0] + ")"))
    if count:
        rows.append(("CAA restricts issuance", "Yes (" + str(count) + " policies)"))
    return rows


def compare_resolvers(host, system_a):
    rows = []
    system_set = set(system_a or [])
    for ip in ("1.1.1.1", "8.8.8.8"):
        try:
            custom = dns.resolver.Resolver(configure=False)
            custom.nameservers = [ip]
            custom.timeout = 3.0
            custom.lifetime = 6.0
            result = query(custom, host, "A")
            addresses = result["records"]
        except Exception:
            addresses = []
        if addresses:
            rows.append(("A via " + ip, ", ".join(sorted(addresses))))
        else:
            rows.append(("A via " + ip, "No answer"))
    others = []
    for key, value in rows:
        if value != "No answer":
            others.append(set(value.split(", ")))
    if not system_set:
        rows.append(("Resolver agreement", "No system answer to compare"))
    elif others and all(item == system_set for item in others):
        rows.append(("Resolver agreement", "All resolvers agree"))
    elif others:
        rows.append(("Resolver agreement", "Resolvers disagree (CDN or geo-DNS likely)"))
    else:
        rows.append(("Resolver agreement", "Public resolvers unreachable"))
    return rows


def axfr_status(ns_ip, apex):
    try:
        import dns.query
        generator = dns.query.xfr(ns_ip, apex, timeout=5)
        count = 0
        for message in generator:
            count += 1
            if count > 50:
                break
        if count >= 50:
            return "Allowed (large zone, truncated)"
        if count:
            return "Allowed (" + str(count) + " messages)"
        return "Empty response"
    except Exception:
        return "Refused or failed"


def check_axfr(resolver, nameservers, apex):
    rows = []
    if not nameservers:
        rows.append(("Zone transfer", "No nameservers found"))
        return rows
    tried = 0
    for ns in nameservers[:3]:
        target = ns.rstrip(".")
        try:
            result = query(resolver, target, "A")
            addresses = result["records"]
        except Exception:
            addresses = []
        if not addresses:
            rows.append(("AXFR " + target, "Nameserver has no A record"))
            continue
        tried += 1
        rows.append(("AXFR " + target, axfr_status(addresses[0], apex)))
    if not tried:
        rows.append(("Zone transfer", "Could not reach any nameserver"))
    return rows


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
        chain = follow_cname(resolver, host)
        if len(chain) > 1:
            rows.append(("CNAME chain", " -> ".join([host] + chain)))
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
    for rtype in EXTRA_HOST_TYPES:
        query_type(resolver, host, rtype, rows, "")
    query_type(resolver, "_443._tcp." + host, "TLSA", rows, " (_443._tcp)")
    if apex and apex != host:
        query_type(resolver, apex, "NSEC3PARAM", rows, " (apex)")
    else:
        query_type(resolver, host, "NSEC3PARAM", rows, "")
    rows.extend(parse_soa(data["soa_apex"] or data["soa"]))
    rows.extend(parse_caa(data["caa_apex"] or data["caa"]))
    rows.extend(compare_resolvers(host, data["a"]))
    if apex:
        zone = apex
    else:
        zone = host
    rows.extend(check_axfr(resolver, data["ns_apex"] or data["ns"], zone))
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
