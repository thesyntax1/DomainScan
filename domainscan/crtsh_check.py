import datetime

from domainscan.helpers import BROWSER_UA, fetch_json, short


def collect(apex, timeout=12):
    rows = []
    if not apex or "." not in apex:
        rows.append(("Certificate history", "Requires a domain name"))
        return {"rows": rows}
    try:
        entries = fetch_crtsh(apex, timeout)
    except Exception as exc:
        rows.append(("Certificate history", "crt.sh query failed (" + exc.__class__.__name__ + ")"))
        entries = []
    if entries:
        rows.extend(summarize(entries, apex))
    spotter = []
    try:
        spotter = fetch_certspotter(apex, timeout)
        rows.extend(spotter_rows(spotter, apex))
    except Exception as exc:
        rows.append(("Cert Spotter", "Query failed (" + exc.__class__.__name__ + ")"))
    if not entries and not spotter:
        rows.append(("Certificates found", "None in CT logs"))
    return {"rows": rows}


def fetch_certspotter(apex, timeout):
    url = "https://api.certspotter.com/v1/issuances"
    params = {"domain": apex, "expand": "dns_names,issuer"}
    return fetch_json(url, params=params, timeout=timeout) or []


def spotter_rows(issuances, apex):
    rows = []
    if not issuances:
        rows.append(("Cert Spotter", "No issuances found"))
        return rows
    rows.append(("Cert Spotter issuances", str(len(issuances))))
    issuers = {}
    names = set()
    for item in issuances:
        issuer = ((item.get("issuer", {}) or {}).get("name", "")) or "Unknown"
        issuers[issuer] = issuers.get(issuer, 0) + 1
        for dns_name in item.get("dns_names", []) or []:
            clean = str(dns_name).strip().lower().rstrip(".")
            if clean:
                names.add(clean)
    for issuer, count in sorted(issuers.items(), key=lambda item: -item[1])[:5]:
        rows.append(("Spotter issuer: " + short(issuer, 70), str(count)))
    rows.append(("Spotter names", str(len(names))))
    outside = sorted(name for name in names if not name.endswith(apex.lower()) and apex.lower() not in name.lstrip("*."))
    if outside:
        rows.append(("Spotter outside names", str(len(outside)) + ": " + short(", ".join(outside[:5]), 180)))
    return rows


def fetch_crtsh(apex, timeout):
    url = "https://crt.sh/?q=%25." + apex + "&output=json"
    data = fetch_json(url, timeout=timeout)
    if isinstance(data, dict) and data.get("error"):
        return []
    return data or []


def summarize(entries, apex):
    rows = []
    rows.append(("Certificates found", str(len(entries)) + " in CT logs"))
    issuers = {}
    for entry in entries:
        name = parse_issuer(entry.get("issuer_name", ""))
        issuers[name] = issuers.get(name, 0) + 1
    rows.append(("Distinct issuers", str(len(issuers))))
    for name, count in sorted(issuers.items(), key=lambda item: -item[1])[:6]:
        rows.append(("Issuer: " + short(name, 70), str(count) + " certs"))
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    expired = 0
    not_before_dates = []
    not_after_dates = []
    for entry in entries:
        before = parse_date(entry.get("not_before", ""))
        after = parse_date(entry.get("not_after", ""))
        if before:
            not_before_dates.append(before)
        if after:
            not_after_dates.append(after)
            if after < now:
                expired += 1
    if not_before_dates:
        rows.append(("Oldest issuance", min(not_before_dates).strftime("%Y-%m-%d")))
    if not_after_dates:
        rows.append(("Latest expiry", max(not_after_dates).strftime("%Y-%m-%d")))
    rows.append(("Expired certificates", str(expired) + " of " + str(len(entries))))
    precerts = [entry for entry in entries if is_precert(entry)]
    rows.append(("Precertificates", str(len(precerts))))
    wildcards = set()
    names = set()
    for entry in entries:
        for line in str(entry.get("name_value", "")).splitlines():
            clean = line.strip().lower()
            if not clean:
                continue
            names.add(clean)
            if clean.startswith("*."):
                wildcards.add(clean)
    rows.append(("Distinct names seen", str(len(names))))
    if wildcards:
        rows.append(("Wildcard certificates", ", ".join(sorted(wildcards)[:5])))
    else:
        rows.append(("Wildcard certificates", "None"))
    outside = sorted(name for name in names if not name.endswith(apex.lower()) and apex.lower() not in name)
    if outside:
        rows.append(("Names outside " + apex, str(len(outside)) + " (possible shared cert)"))
        rows.append(("Outside name sample", short(", ".join(outside[:5]), 200)))
    return rows


def parse_issuer(text):
    for part in str(text or "").split(","):
        if "CN" in part and "=" in part:
            return part.split("=", 1)[1].strip() or "Unknown"
    cleaned = str(text or "").strip()
    if cleaned:
        return short(cleaned, 70)
    return "Unknown"


def parse_date(text):
    cleaned = str(text or "").strip()
    if not cleaned:
        return None
    for pattern in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(cleaned[:19], pattern)
        except Exception:
            continue
    return None


def is_precert(entry):
    extensions = str(entry.get("extensions", "")).lower()
    if "poison" in extensions or "precert" in extensions:
        return True
    serial = str(entry.get("serial_number", "")).lower()
    return "precert" in serial
