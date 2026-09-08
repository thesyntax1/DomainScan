from domainscan import dns_check


LISTS = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("PSBL", "psbl.surriel.com"),
    ("UCEPROTECT", "dnsbl-1.uceprotect.net"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("Abuseat CBL", "cbl.abuseat.org"),
]

DOMAIN_LISTS = [
    ("SURBL multi", "multi.surbl.org"),
    ("Spamhaus DBL", "dbl.spamhaus.org"),
    ("SEM URI", "uribl.spameatingmonkey.net"),
]

SPAMHAUS_CODES = {
    "127.0.0.2": "SBL",
    "127.0.0.3": "CSS",
    "127.0.0.4": "XBL",
    "127.0.0.9": "DROP/EDROP",
    "127.0.0.10": "PBL",
    "127.0.0.11": "PBL",
}


def collect(ips, resolver=None, domain=""):
    rows = []
    if domain and "." in domain:
        rows.extend(domain_blocklists(domain, resolver))
    unique = []
    for ip in ips or []:
        if ip and ip not in unique:
            unique.append(ip)
    v4 = [ip for ip in unique if ":" not in ip]
    v6 = [ip for ip in unique if ":" in ip]
    if not v4:
        rows.append(("DNSBL", "No IPv4 addresses to check"))
        if v6:
            rows.append(("DNSBL note", "IPv6 blocklists not checked"))
        return {"rows": rows}
    if not dns_check.HAS_DNSPYTHON and resolver is None:
        rows.append(("DNSBL", "Skipped (dnspython not installed)"))
        return {"rows": rows}
    if resolver is None:
        resolver = dns_check.make_resolver()
    shown = v4[:3]
    if len(v4) > 3:
        rows.append(("DNSBL note", "Checking first 3 of " + str(len(v4)) + " addresses"))
    listed = 0
    checked = 0
    for ip in shown:
        reversed_ip = ".".join(ip.split(".")[::-1])
        for short_name, zone in LISTS:
            checked += 1
            try:
                result = dns_check.query(resolver, reversed_ip + "." + zone, "A")
                records = result["records"]
            except Exception:
                records = []
            label = ip + " on " + short_name
            if records:
                listed += 1
                rows.append((label, "Listed (" + describe_codes(records, short_name) + ")"))
            else:
                rows.append((label, "Clean"))
    rows.append(("DNSBL listings", str(listed) + " of " + str(checked) + " checks"))
    return {"rows": rows}


def domain_blocklists(domain, resolver):
    rows = []
    if not dns_check.HAS_DNSPYTHON and resolver is None:
        rows.append(("Domain blocklists", "Skipped (dnspython not installed)"))
        return rows
    if resolver is None:
        try:
            resolver = dns_check.make_resolver()
        except Exception:
            rows.append(("Domain blocklists", "Resolver unavailable"))
            return rows
    listed = 0
    for short_name, zone in DOMAIN_LISTS:
        try:
            result = dns_check.query(resolver, domain + "." + zone, "A")
            records = result["records"]
        except Exception:
            records = []
        if records:
            listed += 1
            rows.append((domain + " on " + short_name, "Listed (" + ", ".join(records[:3]) + ")"))
        else:
            rows.append((domain + " on " + short_name, "Clean"))
    rows.append(("Domain listings", str(listed) + " of " + str(len(DOMAIN_LISTS))))
    return rows


def describe_codes(records, short_name):
    if short_name != "Spamhaus ZEN":
        return ", ".join(records)
    parts = []
    for record in records:
        meaning = SPAMHAUS_CODES.get(record, "")
        if meaning:
            parts.append(record + " " + meaning)
        else:
            parts.append(record)
    return ", ".join(parts)
