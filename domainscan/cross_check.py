import re

from domainscan import dns_check, http_check
from domainscan.helpers import short


def collect(info, apex, dns_data, web, whois_ns, timeout=8):
    rows = []
    rows.extend(ns_consistency((dns_data.get("ns_apex") or dns_data.get("ns") or []), whois_ns or []))
    rows.extend(dnssec_completeness(dns_data))
    rows.extend(null_mx_spf_note(dns_data))
    soa_records = dns_data.get("soa_apex") or dns_data.get("soa") or []
    if soa_records:
        rows.append(("SOA serial", soa_serial_verdict(soa_records[0])))
    rows.extend(cookie_security(web.get("cookies", []) or [], info.get("scheme", "") == "https"))
    if not dns_check.HAS_DNSPYTHON:
        rows.append(("Live cross-checks", "Skipped (dnspython not installed)"))
        return {"rows": rows}
    resolver = dns_check.make_resolver()
    if apex:
        rows.extend(spf_include_status(resolver, apex))
        rows.extend(dmarc_rua_status(resolver, apex))
        rows.extend(www_status(resolver, info, apex, timeout))
        mx_records = dns_data.get("mx_apex") or dns_data.get("mx") or []
        rows.extend(spf_mx_note(resolver, apex, mx_records))
    try:
        cert, _, _, _, _ = http_check.fetch_cert(info["host"], 443)
        names = [info["host"]]
        if apex and not info.get("is_ip"):
            candidate = "www." + apex
            if candidate not in names:
                names.append(candidate)
        rows.extend(tls_coverage_rows(cert, names))
        issuer = http_check.cert_names(cert.get("issuer", [])).get("organizationName", "")
        rows.extend(caa_issuer_rows(issuer, dns_data.get("caa_apex") or dns_data.get("caa") or []))
    except Exception:
        rows.append(("Certificate cross-check", "TLS fetch failed"))
    return {"rows": rows}


def null_mx_spf_note(dns_data):
    mx_records = dns_data.get("mx_apex") or dns_data.get("mx") or []
    txt_records = dns_data.get("txt_apex") or dns_data.get("txt") or []
    if not mx_records:
        return []
    first = mx_records[0].split()
    null_mx = len(mx_records) == 1 and len(first) == 2 and first[1].rstrip(".") == ""
    if not null_mx:
        return []
    has_spf = any(item.lower().startswith("v=spf1") for item in txt_records)
    if has_spf:
        return [("Null MX vs SPF", "Null MX rejects all mail; SPF record is harmless but redundant")]
    return [("Null MX vs SPF", "Null MX set, no SPF (consistent, domain sends no mail)")]


def caa_issuer_rows(issuer_org, caa_records):
    rows = []
    tags = []
    for record in caa_records or []:
        match = re.match(r'^\s*\d+\s+issue\s+"?([^";\s]+)"?', record or "", re.IGNORECASE)
        if match and match.group(1) != ";":
            tags.append(match.group(1).lower())
    if not tags:
        return [("CAA vs issuer", "No CAA issue tags (any CA may issue)")]
    issuer = re.sub(r"[^a-z0-9]", "", (issuer_org or "").lower())
    known = {
        "letsencrypt": "letsencrypt.org",
        "digicert": "digicert.com",
        "sectigo": "sectigo.com",
        "comodo": "comodoca.com",
        "globalsign": "globalsign.com",
        "godaddy": "godaddy.com",
        "zerossl": "zerossl.com",
        "amazon": "amazon.com",
        "google": "pki.goog",
        "cloudflare": "cloudflare.com",
        "entrust": "entrust.net",
        "geotrust": "geotrust.com",
        "thawte": "thawte.com",
        "rapidssl": "rapidssl.com",
    }
    expected = ""
    for key, tag in known.items():
        if key in issuer:
            expected = tag
            break
    if expected and any(expected in tag or tag in expected for tag in tags):
        rows.append(("CAA vs issuer", "Consistent (" + issuer_org + " allowed by CAA)"))
    elif expected:
        rows.append(("CAA vs issuer", "Mismatch: cert from " + issuer_org + " but CAA allows " + ", ".join(tags[:4])))
    else:
        rows.append(("CAA vs issuer", "Issuer " + (issuer_org or "unknown") + " not in known CA map"))
    return rows


def normalize_names(names):
    return sorted(set((name or "").strip().rstrip(".").lower() for name in names if (name or "").strip()))


def ns_consistency(dns_ns, whois_ns):
    left = normalize_names(dns_ns)
    right = normalize_names(whois_ns)
    if not left and not right:
        return [("NS consistency", "No nameservers on either side")]
    if not right:
        return [("NS consistency", "No WHOIS nameservers to compare")]
    if not left:
        return [("NS consistency", "No DNS nameservers to compare")]
    if left == right:
        return [("NS consistency", "Match (" + str(len(left)) + " nameservers)")]
    rows = [("NS consistency", "Mismatch between DNS and WHOIS")]
    only_dns = [name for name in left if name not in right][:3]
    only_whois = [name for name in right if name not in left][:3]
    if only_dns:
        rows.append(("DNS-only NS", ", ".join(only_dns)))
    if only_whois:
        rows.append(("WHOIS-only NS", ", ".join(only_whois)))
    return rows


def dnssec_completeness(dns_data):
    has_ds = bool(dns_data.get("ds"))
    has_key = bool(dns_data.get("dnskey"))
    if has_ds and has_key:
        return [("DNSSEC chain", "Complete (DS and DNSKEY published)")]
    if has_ds:
        return [("DNSSEC chain", "DS without DNSKEY (incomplete)")]
    if has_key:
        return [("DNSSEC chain", "DNSKEY without DS (incomplete)")]
    return [("DNSSEC chain", "Unsigned (neither DS nor DNSKEY)")]


def soa_serial_verdict(record):
    parts = (record or "").split()
    if len(parts) < 3:
        return short(record, 120)
    serial = parts[2]
    if len(serial) >= 8 and serial[:8].isdigit():
        year = serial[0:4]
        month = serial[4:6]
        day = serial[6:8]
        if "1990" <= year <= "2035" and "01" <= month <= "12" and "01" <= day <= "31":
            return "Date-based (" + year + "-" + month + "-" + day + ", rev " + serial[8:] + ")"
    return "Counter (" + serial + ")"


def parse_spf_includes(value):
    found = []
    for token in (value or "").split():
        low = token.lower()
        if low.startswith("include:"):
            found.append(token.split(":", 1)[1])
        elif low.startswith("redirect="):
            found.append(token.split("=", 1)[1])
    return found


def spf_include_status(resolver, apex):
    rows = []
    try:
        result = dns_check.query(resolver, apex, "TXT")
        records = [dns_check.clean_txt(item) for item in result["records"]]
    except Exception:
        return [("SPF includes", "Lookup failed")]
    values = [item for item in records if item.lower().startswith("v=spf1")]
    if not values:
        return [("SPF includes", "No SPF record, nothing to verify")]
    includes = parse_spf_includes(values[0])
    if not includes:
        return [("SPF includes", "SPF has no includes")]
    rows.append(("SPF includes", str(len(includes)) + " targets to verify"))
    for target in includes[:5]:
        try:
            check = dns_check.query(resolver, target, "TXT")
            nested = [dns_check.clean_txt(item) for item in check["records"]]
            valid = any(item.lower().startswith("v=spf1") for item in nested)
        except Exception:
            valid = False
        if valid:
            rows.append(("SPF include " + target, "Target publishes SPF"))
        else:
            rows.append(("SPF include " + target, "Target has no SPF (misconfigured)"))
    return rows


def parse_dmarc_rua(value):
    hosts = []
    for part in (value or "").split(";"):
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        if key.strip().lower() not in ("rua", "ruf"):
            continue
        for mailbox in val.split(","):
            mailbox = mailbox.strip()
            if "@" in mailbox:
                host = mailbox.rsplit("@", 1)[1].strip().rstrip("!").rstrip(".")
                if host and host not in hosts:
                    hosts.append(host)
    return hosts


def dmarc_rua_status(resolver, apex):
    rows = []
    try:
        result = dns_check.query(resolver, "_dmarc." + apex, "TXT")
        records = [dns_check.clean_txt(item) for item in result["records"]]
    except Exception:
        return [("DMARC reports", "Lookup failed")]
    values = [item for item in records if "v=dmarc1" in item.lower()]
    if not values:
        return [("DMARC reports", "No DMARC record, nothing to verify")]
    hosts = parse_dmarc_rua(values[0])
    if not hosts:
        return [("DMARC reports", "No rua/ruf mailbox configured")]
    for host in hosts[:3]:
        try:
            check = dns_check.query(resolver, host, "MX")
            valid = bool(check["records"])
        except Exception:
            valid = False
        if valid:
            rows.append(("Report mailbox " + host, "Accepts mail (has MX)"))
        else:
            rows.append(("Report mailbox " + host, "No MX record (reports will bounce)"))
    return rows


def spf_mx_note(resolver, apex, mx_records):
    try:
        result = dns_check.query(resolver, apex, "TXT")
        records = [dns_check.clean_txt(item) for item in result["records"]]
    except Exception:
        return [("SPF vs MX", "Lookup failed")]
    values = [item for item in records if item.lower().startswith("v=spf1")]
    if not values:
        return [("SPF vs MX", "No SPF record")]
    tokens = values[0].split()[1:]
    authorizes = any(token.lower().lstrip("+-~?").split("/")[0].split(":")[0] == "mx" for token in tokens)
    if not mx_records:
        return [("SPF vs MX", "Domain has no MX records")]
    if authorizes:
        return [("SPF vs MX", "SPF authorizes the MX hosts")]
    return [("SPF vs MX", "SPF does not reference MX (review if MX sends mail)")]


def http_probe(url, timeout=6):
    import requests
    from domainscan.helpers import BROWSER_UA
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": BROWSER_UA})
        return {"status": response.status_code, "final": response.url, "error": ""}
    except Exception as exc:
        return {"status": 0, "final": "", "error": exc.__class__.__name__}


def www_status(resolver, info, apex, timeout):
    rows = []
    www = "www." + apex
    try:
        result = dns_check.query(resolver, www, "A")
        www_ips = result["records"]
    except Exception:
        www_ips = []
    if www_ips:
        rows.append(("www A", ", ".join(www_ips[:4])))
    else:
        rows.append(("www A", "No A record"))
    try:
        apex_result = dns_check.query(resolver, apex, "A")
        apex_ips = apex_result["records"]
    except Exception:
        apex_ips = []
    if www_ips and apex_ips:
        if set(www_ips) == set(apex_ips):
            rows.append(("www vs apex", "Same addresses"))
        else:
            rows.append(("www vs apex", "Different addresses"))
    scheme = info.get("scheme", "https")
    probe = http_probe(scheme + "://" + www + "/", timeout)
    if probe["status"]:
        rows.append(("www HTTP", str(probe["status"]) + " -> " + short(probe["final"], 160)))
    else:
        rows.append(("www HTTP", "No response (" + probe["error"] + ")"))
    return rows


def tls_coverage_rows(cert, names):
    rows = []
    sans = cert.get("subjectAltName", []) or []
    common = ""
    for entry in cert.get("subject", []) or []:
        for key, value in entry:
            if key == "commonName":
                common = value
    for name in names:
        covered, pattern = http_check.host_covered(name, sans, common)
        if covered:
            rows.append(("Cert covers " + name, "Yes (" + pattern + ")"))
        else:
            rows.append(("Cert covers " + name, "No"))
    return rows


def cookie_security(cookies, is_https):
    rows = []
    if not is_https:
        return [("Cookie transport", "Site is plain HTTP")]
    if not cookies:
        return [("Cookie transport", "No cookies set")]
    missing = [cookie.get("name", "?") for cookie in cookies if not cookie.get("secure")]
    if not missing:
        rows.append(("Secure cookies", "All " + str(len(cookies)) + " cookies use Secure"))
    else:
        rows.append(("Secure cookies", str(len(missing)) + " of " + str(len(cookies)) + " missing Secure: " + ", ".join(missing[:5])))
    return rows
