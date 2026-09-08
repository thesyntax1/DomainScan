import urllib.parse

from domainscan.helpers import BROWSER_UA, short


def collect(host, timeout=10):
    rows = []
    if not host:
        rows.append(("Web archive", "No host to query"))
        return {"rows": rows}
    try:
        captures = fetch_cdx(host, timeout)
    except Exception as exc:
        rows.append(("Web archive", "CDX query failed (" + exc.__class__.__name__ + ")"))
        return {"rows": rows}
    if not captures:
        rows.append(("Archived captures", "None found"))
        return {"rows": rows}
    rows.extend(summarize(captures))
    rows.extend(subdomain_rows(host, timeout))
    return {"rows": rows}


def subdomain_rows(host, timeout):
    import requests
    rows = []
    params = {
        "url": host,
        "matchType": "domain",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 2000,
    }
    try:
        response = requests.get("https://web.archive.org/cdx/search/cdx", params=params, headers={"User-Agent": BROWSER_UA}, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return rows
    if not data or len(data) < 2:
        return rows
    subs = set()
    for row in data[1:]:
        if not row or not row[0]:
            continue
        name = (urllib.parse.urlsplit(row[0]).hostname or "").lower()
        if name and name != host.lower() and name.endswith("." + host.lower()):
            subs.add(name)
    if subs:
        rows.append(("Archived subdomains", str(len(subs))))
        for index, name in enumerate(sorted(subs)[:8], 1):
            rows.append(("Archived subdomain " + str(index), name))
    return rows


def fetch_cdx(host, timeout):
    import requests
    params = {
        "url": host + "/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": 500,
    }
    headers = {"User-Agent": BROWSER_UA}
    response = requests.get("https://web.archive.org/cdx/search/cdx", params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if not data or len(data) < 2:
        return []
    return data[1:]


def summarize(captures):
    rows = []
    stamps = sorted(row[0] for row in captures if row and row[0])
    rows.append(("Archived URLs", str(len(captures)) + " unique URLs"))
    total = 0
    counted = 0
    for row in captures:
        if len(row) > 5 and row[5] and row[5] != "-":
            try:
                total += int(row[5])
                counted += 1
            except Exception:
                continue
    if counted:
        rows.append(("Archived bytes", format_bytes(total) + " across " + str(counted) + " captures"))
    if stamps:
        rows.append(("First capture", format_stamp(stamps[0])))
        rows.append(("Latest capture", format_stamp(stamps[-1])))
        rows.append(("Archive span", span_years(stamps[0], stamps[-1])))
    types = {}
    for row in captures:
        if len(row) > 3 and row[3]:
            mime = row[3].split(";")[0].strip()
            types[mime] = types.get(mime, 0) + 1
    if types:
        rows.append(("Archived content types", str(len(types))))
        for mime, count in sorted(types.items(), key=lambda item: -item[1])[:6]:
            rows.append(("Archive type: " + short(mime, 60), str(count) + " URLs"))
    interesting = find_interesting(captures)
    if interesting:
        rows.append(("Interesting archived paths", str(len(interesting))))
        for index, target in enumerate(interesting[:10], 1):
            rows.append(("Archived path " + str(index), short(target, 200)))
    else:
        rows.append(("Interesting archived paths", "None spotted"))
    samples = [row[1] for row in captures if len(row) > 1 and row[1]][:5]
    for index, target in enumerate(samples, 1):
        rows.append(("Sample archived URL " + str(index), short(target, 200)))
    return rows


def format_bytes(total):
    value = float(total)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return str(int(value)) + " B"
            return str(round(value, 1)) + " " + unit
        value = value / 1024
    return str(total) + " B"


def format_stamp(stamp):
    text = str(stamp)
    if len(text) >= 14:
        return text[0:4] + "-" + text[4:6] + "-" + text[6:8] + " " + text[8:10] + ":" + text[10:12]
    return text


def span_years(first, last):
    try:
        years = int(str(last)[0:4]) - int(str(first)[0:4])
    except Exception:
        return "Unknown"
    if years <= 0:
        return "Under a year"
    return "About " + str(years) + " years"


def find_interesting(captures):
    keywords = ("admin", "login", "backup", ".bak", ".old", ".zip", ".sql", "test", "dev", "staging", "api", "debug", "config", "private", "internal", ".env", "swagger", "graphql")
    found = []
    for row in captures:
        if len(row) < 2 or not row[1]:
            continue
        path = urllib.parse.urlsplit(row[1]).path.lower()
        if any(keyword in path for keyword in keywords) and row[1] not in found:
            found.append(row[1])
    return found
