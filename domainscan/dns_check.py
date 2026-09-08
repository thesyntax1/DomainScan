import socket

from domainscan.helpers import short

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


HOST_TYPES = ["A", "AAAA", "CNAME"]
DOMAIN_TYPES = ["MX", "NS", "TXT", "SOA", "CAA"]
EXTRA_HOST_TYPES = ["HTTPS", "SVCB", "SSHFP", "NAPTR", "LOC", "DNAME"]


DNSKEY_ALGORITHMS = {
    "1": "RSAMD5",
    "5": "RSASHA1",
    "7": "RSASHA1-NSEC3",
    "8": "RSASHA256",
    "10": "RSASHA512",
    "12": "ECC-GOST",
    "13": "ECDSAP256SHA256",
    "14": "ECDSAP384SHA384",
    "15": "Ed25519",
    "16": "Ed448",
}


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
        rows.extend(caa_detail_rows(records))
    return rows


def caa_detail_rows(records):
    rows = []
    tags = {}
    critical = 0
    for record in records:
        parts = record.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            flags = int(parts[0])
        except Exception:
            flags = 0
        if flags & 128:
            critical += 1
        tags.setdefault(parts[1].lower(), []).append(parts[2].strip().strip('"'))
    if "issuewild" not in tags and "issue" in tags:
        rows.append(("CAA wildcards", "No issuewild tag (issue rules also cover wildcards)"))
    elif "issuewild" in tags:
        rows.append(("CAA wildcards", "Restricted: " + short(", ".join(tags["issuewild"][:3]), 160)))
    if "issuemail" in tags or "issuevmc" in tags:
        rows.append(("CAA mail/VMC", "S/MIME or VMC issuance restricted"))
    if "validationmethods" in tags:
        rows.append(("CAA validation", short(", ".join(tags["validationmethods"][:4]), 160)))
    if "accounturi" in tags:
        rows.append(("CAA accounts", str(len(tags["accounturi"])) + " ACME account bindings"))
    if critical:
        rows.append(("CAA critical flag", str(critical) + " records marked critical (unknown tags must fail closed)"))
    return rows


def ds_link_rows(resolver, zone):
    rows = []
    if not HAS_DNSPYTHON:
        return rows
    import dns.dnssec
    import dns.rdatatype
    try:
        ds_answer = resolver.resolve(zone, dns.rdatatype.DS, lifetime=6)
        key_answer = resolver.resolve(zone, dns.rdatatype.DNSKEY, lifetime=6)
    except Exception:
        return rows
    ds_digests = set()
    for rdata in ds_answer:
        try:
            ds_digests.add(bytes(rdata.digest).hex().lower())
        except Exception:
            continue
    if not ds_digests:
        return rows
    matched = False
    checked = 0
    for key in key_answer:
        for ds in ds_answer:
            checked += 1
            try:
                candidate = dns.dnssec.make_ds(ds_answer.canonical_name, key, str(ds.digest_type))
            except Exception:
                continue
            if bytes(candidate.digest).hex().lower() in ds_digests and int(candidate.key_tag) == int(ds.key_tag):
                matched = True
                break
        if matched:
            break
    if not checked:
        return rows
    if matched:
        rows.append(("DS linkage", "Verified (a DS digest matches a published DNSKEY)"))
    else:
        rows.append(("DS linkage", "BROKEN (no DS digest matches any DNSKEY)"))
    return rows


def rrsig_expiry_rows(resolver, zone):
    rows = []
    if not HAS_DNSPYTHON:
        return rows
    import datetime
    import dns.rdatatype
    try:
        answer = resolver.resolve(zone, dns.rdatatype.RRSIG, lifetime=6)
    except Exception:
        return rows
    expiries = []
    for rdata in answer:
        try:
            stamp = datetime.datetime.fromtimestamp(rdata.expiration, datetime.timezone.utc)
            expiries.append((dns.rdatatype.to_text(rdata.type_covered), stamp))
        except Exception:
            continue
    if not expiries:
        return rows
    expiries.sort(key=lambda item: item[1])
    now = datetime.datetime.now(datetime.timezone.utc)
    nearest_kind, nearest = expiries[0]
    days = (nearest - now).days
    if days < 0:
        rows.append(("RRSIG expiry", "EXPIRED signatures present (" + nearest_kind + " lapsed " + str(abs(days)) + " days ago)"))
    elif days < 7:
        rows.append(("RRSIG expiry", nearest_kind + " signatures expire in " + str(days) + " days (re-sign soon)"))
    else:
        rows.append(("RRSIG expiry", "Signatures valid, earliest expiry " + nearest.strftime("%Y-%m-%d") + " (" + str(days) + " days)"))
    return rows


def parse_ds(records):
    rows = []
    for record in records or []:
        parts = record.split()
        if len(parts) < 4:
            continue
        digest_names = {"1": "SHA-1", "2": "SHA-256", "4": "SHA-384"}
        rows.append(("DS key " + parts[0], "algorithm " + DNSKEY_ALGORITHMS.get(parts[1], parts[1]) + ", digest " + digest_names.get(parts[2], parts[2])))
    return rows


def parse_dnskey(records):
    rows = []
    for record in records or []:
        parts = record.split()
        if len(parts) < 4:
            continue
        flags = parts[0]
        if flags == "257":
            role = "KSK (key signing)"
        elif flags == "256":
            role = "ZSK (zone signing)"
        else:
            role = "flags " + flags
        rows.append(("DNSKEY " + role, "algorithm " + DNSKEY_ALGORITHMS.get(parts[2], parts[2])))
    return rows


def soa_timer_rows(records):
    rows = []
    if not records:
        return rows
    parts = records[0].split()
    if len(parts) < 7:
        return rows
    try:
        refresh = int(parts[3])
        retry = int(parts[4])
        expire = int(parts[5])
        minimum = int(parts[6])
    except Exception:
        return rows
    issues = []
    if retry >= refresh:
        issues.append("retry should be smaller than refresh")
    if expire < 604800:
        issues.append("expire under 7 days risks outages")
    if refresh < 3600:
        issues.append("refresh under 1h causes extra load")
    if minimum > 86400:
        issues.append("minimum TTL over 24h slows changes")
    if issues:
        rows.append(("SOA timers", "Review: " + "; ".join(issues)))
    else:
        rows.append(("SOA timers", "Sane values"))
    return rows


def parse_tlsa(records):
    rows = []
    usages = {"0": "CA constraint", "1": "service certificate constraint", "2": "trust anchor assertion", "3": "domain-issued certificate"}
    selectors = {"0": "full certificate", "1": "public key"}
    matchings = {"0": "exact", "1": "SHA-256", "2": "SHA-512"}
    for record in records or []:
        parts = record.split()
        if len(parts) < 4:
            continue
        rows.append(("TLSA usage " + parts[0], usages.get(parts[0], "unknown") + ", " + selectors.get(parts[1], parts[1]) + ", " + matchings.get(parts[2], parts[2])))
    return rows


def parse_sshfp(records):
    rows = []
    algos = {"1": "RSA", "2": "DSA", "3": "ECDSA", "4": "Ed25519", "6": "Ed448"}
    fptypes = {"1": "SHA-1", "2": "SHA-256"}
    for record in records or []:
        parts = record.split()
        if len(parts) < 3:
            continue
        detail = algos.get(parts[0], "algo " + parts[0]) + ", " + fptypes.get(parts[1], "type " + parts[1])
        rows.append(("SSHFP key", detail + " (" + parts[2][:32] + "...)"))
        if parts[1] == "1":
            rows.append(("SSHFP warning", "SHA-1 fingerprint (weak)"))
    return rows


def parse_srv(records):
    rows = []
    for record in records or []:
        parts = record.split()
        if len(parts) < 4:
            continue
        rows.append(("SRV service", parts[3].rstrip(".") + " port " + parts[2] + " (priority " + parts[0] + ")"))
    return rows


def parse_naptr(records):
    rows = []
    for record in records or []:
        cleaned = record.replace('"', "")
        rows.append(("NAPTR rule", cleaned[:160]))
    return rows


def parse_https_svcb(https_records, svcb_records):
    rows = []
    for record in (https_records or []) + (svcb_records or []):
        rows.append(("HTTPS/SVCB", describe_svcb(record)))
    return rows


def describe_svcb(record):
    parts = (record or "").split()
    if len(parts) < 2:
        return (record or "")[:160]
    details = []
    if parts[0] == "0":
        details.append("alias to " + parts[1].rstrip("."))
    else:
        details.append("priority " + parts[0])
    text = " ".join(parts[2:])
    for key in ("alpn=", "port=", "ipv4hint=", "ipv6hint=", "dohpath="):
        if key in text:
            value = text.split(key, 1)[1].split()[0].strip(",").strip('"')
            details.append(key.rstrip("=") + " " + value)
    target = parts[1].rstrip(".")
    if target and target != ".":
        details.append("target " + target)
    return ", ".join(details)[:200]


def parse_loc(records):
    rows = []
    for record in records or []:
        coords = decode_loc(record)
        if coords:
            lat, lon = coords
            rows.append(("LOC coordinates", str(round(lat, 5)) + ", " + str(round(lon, 5))))
            rows.append(("LOC map", "https://www.openstreetmap.org/?mlat=" + str(lat) + "&mlon=" + str(lon) + "&zoom=14"))
        else:
            rows.append(("LOC record", (record or "")[:160]))
    return rows


def decode_loc(record):
    import re
    pattern = r"(\d+)\s+(?:(\d+)\s+)?(?:([\d.]+)\s+)?([NS])\s+(\d+)\s+(?:(\d+)\s+)?(?:([\d.]+)\s+)?([EW])"
    match = re.search(pattern, record or "")
    if not match:
        return None
    try:
        lat = float(match.group(1)) + float(match.group(2) or 0) / 60 + float(match.group(3) or 0) / 3600
        lon = float(match.group(5)) + float(match.group(6) or 0) / 60 + float(match.group(7) or 0) / 3600
    except Exception:
        return None
    if match.group(4) == "S":
        lat = -lat
    if match.group(8) == "W":
        lon = -lon
    return (lat, lon)


def ns_diversity(resolver, nameservers, zone):
    rows = []
    if not nameservers:
        return rows
    clean = sorted(set(ns.rstrip(".") for ns in nameservers))
    rows.append(("NS count", str(len(clean))))
    if len(clean) < 2:
        rows.append(("NS redundancy", "Single nameserver (no redundancy)"))
    else:
        rows.append(("NS redundancy", "OK (" + str(len(clean)) + " servers)"))
    subnets = {}
    for ns in clean[:6]:
        try:
            result = query(resolver, ns, "A")
            addresses = result["records"]
        except Exception:
            addresses = []
        for address in addresses:
            prefix = ".".join(address.split(".")[:3])
            subnets.setdefault(prefix, []).append(ns)
        if zone and (ns.lower() == zone.lower() or ns.lower().endswith("." + zone.lower())) and not addresses:
            rows.append(("NS glue: " + ns, "In-bailiwick but no A record (missing glue)"))
    if subnets:
        rows.append(("NS subnets", str(len(subnets)) + " distinct /24 networks"))
        if len(subnets) == 1 and len(clean) > 1:
            rows.append(("NS diversity", "All nameservers share one /24 (single point of failure)"))
    return rows


def recursion_rows(resolver, nameservers):
    rows = []
    if not nameservers:
        return rows
    tested = 0
    for ns in sorted(set(nameservers))[:3]:
        target = ns.rstrip(".")
        try:
            result = query(resolver, target, "A")
            addresses = result["records"]
        except Exception:
            addresses = []
        if not addresses:
            continue
        tested += 1
        if is_recursive(addresses[0]):
            rows.append(("Recursion " + target, "Open resolver (answers for other zones)"))
        else:
            rows.append(("Recursion " + target, "Closed (authoritative only)"))
    if not tested:
        rows.append(("Recursion test", "No nameserver addresses to test"))
    return rows


def is_recursive(ns_ip):
    try:
        import dns.resolver
        custom = dns.resolver.Resolver(configure=False)
        custom.nameservers = [ns_ip]
        custom.timeout = 3.0
        custom.lifetime = 5.0
        answer = custom.resolve("example.net", "A")
        return len(list(answer)) > 0
    except Exception:
        return False


def doh_compare(host, system_a, rows):
    try:
        answers = doh_query(host, "A")
    except Exception:
        rows.append(("DNS-over-HTTPS", "DoH query failed"))
        return []
    if not answers:
        rows.append(("DNS-over-HTTPS", "No answer via Cloudflare DoH"))
        return []
    rows.append(("A via DoH", ", ".join(sorted(answers))))
    local = set(system_a or [])
    if local and set(answers) == local:
        rows.append(("DoH agreement", "DoH answer matches local resolver"))
    elif local:
        rows.append(("DoH agreement", "DoH answer differs (CDN or geo-DNS likely)"))
    return answers


def doh_query(name, rtype, timeout=8):
    import requests
    from domainscan.helpers import BROWSER_UA
    url = "https://cloudflare-dns.com/dns-query"
    params = {"name": name, "type": rtype}
    headers = {"User-Agent": BROWSER_UA, "Accept": "application/dns-json"}
    response = requests.get(url, params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    found = []
    for item in data.get("Answer", []) or []:
        if str(item.get("type", "")) in ("1", "28") or rtype in ("A", "AAAA"):
            value = str(item.get("data", "")).strip()
            if value and value not in found:
                found.append(value)
    return found


def adbit_rows(name):
    rows = []
    for ip, label in (("8.8.8.8", "Google"), ("1.1.1.1", "Cloudflare")):
        state = adbit_query(ip, name)
        if state is None:
            rows.append(("DNSSEC validation (" + label + ")", "Query failed"))
        elif state:
            rows.append(("DNSSEC validation (" + label + ")", "AD flag set (signature validates)"))
        else:
            rows.append(("DNSSEC validation (" + label + ")", "No AD flag (unsigned or bogus)"))
    return rows


def adbit_query(ip, name):
    try:
        import dns.flags
        import dns.resolver
        custom = dns.resolver.Resolver(configure=False)
        custom.nameservers = [ip]
        custom.timeout = 3.0
        custom.lifetime = 5.0
        answer = custom.resolve(name, "DS")
        list(answer)
        return bool(answer.response.flags & dns.flags.AD)
    except Exception:
        return None


def nsec_walk_rows(resolver, zone, cap=40):
    rows = []
    if not HAS_DNSPYTHON:
        return rows
    import dns.rdatatype
    names = []
    current = zone.rstrip(".") + "."
    seen = {current.lower()}
    try:
        for _ in range(cap):
            answer = resolver.resolve(current, dns.rdatatype.NSEC, lifetime=5)
            found = None
            for rdata in answer:
                nxt = str(rdata.next).rstrip(".") + "."
                if nxt.lower().endswith(zone.rstrip(".").lower() + ".") or nxt.lower() == zone.rstrip(".").lower() + ".":
                    found = nxt
                    break
                if found is None:
                    found = nxt
            if found is None:
                break
            if found.lower() in seen:
                break
            seen.add(found.lower())
            names.append(found.rstrip("."))
            current = found
    except Exception:
        pass
    if names:
        rows.append(("NSEC walk", str(len(names)) + " names enumerated (zone is walkable)"))
        for index, name in enumerate(names[:12], 1):
            rows.append(("Walked name " + str(index), name))
    else:
        rows.append(("NSEC walk", "Could not walk (server refused or walk wrapped)"))
    return rows


def nsec_mode_rows(nsec, nsec3):
    rows = []
    if nsec:
        rows.append(("NSEC mode", "NSEC with opt-out off (zone is enumerable)"))
    elif nsec3:
        rows.append(("NSEC mode", "NSEC3 (hashed, resists enumeration)"))
    else:
        rows.append(("NSEC mode", "No NSEC/NSEC3 records (unsigned or hidden)"))
    return rows


def ns_identity_rows(resolver, nameservers):
    rows = []
    if not nameservers:
        return rows
    for ns in sorted(set(nameservers))[:3]:
        target = ns.rstrip(".")
        try:
            result = query(resolver, target, "A")
            addresses = result["records"]
        except Exception:
            addresses = []
        if not addresses:
            continue
        nsid = nsid_query(addresses[0])
        if nsid:
            rows.append(("NSID " + target, nsid))
        version = version_query(addresses[0])
        if version:
            rows.append(("NS version " + target, version))
    if not rows:
        rows.append(("NS identity", "Servers hide NSID and version (good)"))
    return rows


def nsid_query(ns_ip, timeout=4):
    try:
        import dns.edns
        import dns.message
        import dns.query
        import dns.rdatatype
        request = dns.message.make_query("example.com", dns.rdatatype.A)
        request.use_edns(ednsflags=0, options=[dns.edns.GenericOption(3, b"")])
        response = dns.query.udp(request, ns_ip, timeout=timeout)
        for option in response.options:
            if option.otype == 3 and option.data:
                try:
                    return bytes(option.data).decode("utf-8", "ignore").strip() or "(binary NSID)"
                except Exception:
                    return "(binary NSID)"
    except Exception:
        pass
    return ""


def version_query(ns_ip, timeout=4):
    try:
        import dns.message
        import dns.query
        import dns.rdataclass
        import dns.rdatatype
        request = dns.message.make_query("version.bind", dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
        response = dns.query.udp(request, ns_ip, timeout=timeout)
        for rrset in response.answer:
            for item in rrset:
                text = item.to_text().strip('"')
                if text:
                    return text[:120]
    except Exception:
        pass
    return ""


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
        "srv": [], "tlsa": [], "sshfp": [], "naptr": [],
        "https": [], "svcb": [], "loc": [], "doh": [],
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
        found = query_type(resolver, service + "." + host, "SRV", rows, " (" + service + ")")
        if found:
            data["srv"].extend(found)
    for rtype in EXTRA_HOST_TYPES:
        found = query_type(resolver, host, rtype, rows, "")
        if found:
            data[rtype.lower()].extend(found)
    tlsa_found = query_type(resolver, "_443._tcp." + host, "TLSA", rows, " (_443._tcp)")
    if tlsa_found:
        data["tlsa"].extend(tlsa_found)
    if apex and apex != host:
        nsec3 = query_type(resolver, apex, "NSEC3PARAM", rows, " (apex)")
        nsec = query_type(resolver, apex, "NSEC", rows, " (apex)")
    else:
        nsec3 = query_type(resolver, host, "NSEC3PARAM", rows, "")
        nsec = query_type(resolver, host, "NSEC", rows, "")
    rows.extend(nsec_mode_rows(nsec, nsec3))
    if nsec:
        if apex and apex != host:
            rows.extend(nsec_walk_rows(resolver, apex))
        else:
            rows.extend(nsec_walk_rows(resolver, host))
    rows.extend(parse_soa(data["soa_apex"] or data["soa"]))
    rows.extend(soa_timer_rows(data["soa_apex"] or data["soa"]))
    rows.extend(parse_caa(data["caa_apex"] or data["caa"]))
    rows.extend(parse_ds(data["ds"]))
    rows.extend(parse_dnskey(data["dnskey"]))
    if apex and apex != host:
        rows.extend(ds_link_rows(resolver, apex))
        rows.extend(rrsig_expiry_rows(resolver, apex))
    else:
        rows.extend(ds_link_rows(resolver, host))
        rows.extend(rrsig_expiry_rows(resolver, host))
    rows.extend(parse_tlsa(data["tlsa"]))
    rows.extend(parse_sshfp(data["sshfp"]))
    rows.extend(parse_srv(data["srv"]))
    rows.extend(parse_naptr(data["naptr"]))
    rows.extend(parse_https_svcb(data["https"], data["svcb"]))
    rows.extend(parse_loc(data["loc"]))
    rows.extend(compare_resolvers(host, data["a"]))
    data["doh"] = doh_compare(host, data["a"], rows)
    rows.extend(adbit_rows(apex or host))
    if apex:
        zone = apex
    else:
        zone = host
    rows.extend(check_axfr(resolver, data["ns_apex"] or data["ns"], zone))
    rows.extend(ns_diversity(resolver, data["ns_apex"] or data["ns"], zone))
    rows.extend(recursion_rows(resolver, data["ns_apex"] or data["ns"]))
    rows.extend(ns_identity_rows(resolver, data["ns_apex"] or data["ns"]))
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
