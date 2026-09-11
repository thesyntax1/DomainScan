from domainscan.helpers import BROWSER_UA, short


def collect(host, fetch_url):
    rows = []
    rows.extend(latest_snapshot(fetch_url))
    rows.extend(first_capture(host))
    rows.extend(active_years(host))
    return {"rows": rows}


def latest_snapshot(fetch_url):
    import requests
    try:
        url = "https://archive.org/wayback/available?url=" + fetch_url
        response = requests.get(url, timeout=10, headers={"User-Agent": BROWSER_UA})
        data = response.json()
    except Exception:
        return [("Web archive", "Lookup failed")]
    return parse_available(data)


def parse_available(data):
    rows = []
    snapshots = (data or {}).get("archived_snapshots", {}) or {}
    closest = snapshots.get("closest", {}) or {}
    if not closest.get("url"):
        rows.append(("Web archive", "No snapshots found"))
        return rows
    stamp = format_timestamp(str(closest.get("timestamp", "")))
    status = closest.get("status", "")
    if status:
        rows.append(("Latest snapshot", stamp + " (HTTP " + str(status) + ")"))
    else:
        rows.append(("Latest snapshot", stamp))
    rows.append(("Snapshot URL", short(closest.get("url", ""), 220)))
    return rows


def first_capture(host):
    import requests
    try:
        url = "https://web.archive.org/cdx/search/cdx"
        params = {"url": host, "output": "json", "fl": "timestamp,original,statuscode", "filter": "statuscode:200", "limit": "1"}
        response = requests.get(url, params=params, timeout=12, headers={"User-Agent": BROWSER_UA})
        data = response.json()
    except Exception:
        return [("First capture", "Lookup failed")]
    return parse_first(data)


def parse_first(data):
    if not data or len(data) < 2:
        return [("First capture", "None found")]
    entry = data[1]
    stamp = format_timestamp(str(entry[0])) if len(entry) > 0 else ""
    original = str(entry[1]) if len(entry) > 1 else ""
    if original:
        return [("First capture", stamp + " " + short(original, 160))]
    return [("First capture", stamp)]


def active_years(host):
    import requests
    try:
        url = "https://web.archive.org/cdx/search/cdx"
        params = {"url": host, "output": "json", "fl": "timestamp", "collapse": "year", "limit": "50"}
        response = requests.get(url, params=params, timeout=12, headers={"User-Agent": BROWSER_UA})
        data = response.json()
    except Exception:
        return [("Archived years", "Lookup failed")]
    return parse_years(data)


def parse_years(data):
    years = []
    for entry in data or []:
        if not entry:
            continue
        stamp = str(entry[0])
        if len(stamp) >= 4 and stamp[:4].isdigit() and stamp[:4] not in years:
            years.append(stamp[:4])
    if not years:
        return [("Archived years", "None found")]
    rows = [("Archived years", str(len(years)))]
    rows.append(("Active years", ", ".join(sorted(years))))
    return rows


def format_timestamp(stamp):
    digits = "".join(char for char in stamp if char.isdigit())
    if len(digits) < 14:
        return stamp or "Unknown date"
    return digits[0:4] + "-" + digits[4:6] + "-" + digits[6:8] + " " + digits[8:10] + ":" + digits[10:12] + ":" + digits[12:14]
