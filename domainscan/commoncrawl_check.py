import urllib.parse

from domainscan.helpers import BROWSER_UA, short


def collect(host, timeout=15):
    rows = []
    if not host:
        rows.append(("Common Crawl", "No host to query"))
        return {"rows": rows}
    try:
        indexes = fetch_indexes(timeout)
    except Exception as exc:
        rows.append(("Common Crawl", "Index list failed (" + exc.__class__.__name__ + ")"))
        return {"rows": rows}
    if not indexes:
        rows.append(("Common Crawl", "No indexes available"))
        return {"rows": rows}
    rows.append(("Crawl indexes", str(len(indexes)) + " (using newest " + str(min(len(indexes), 2)) + ")"))
    captures = []
    for index in indexes[:2]:
        try:
            found = fetch_captures(index, host, timeout)
            captures.extend(found)
            rows.append((index + " captures", str(len(found))))
        except Exception as exc:
            rows.append((index, "Query failed (" + exc.__class__.__name__ + ")"))
    if not captures:
        rows.append(("Common Crawl URLs", "None found"))
        return rows
    rows.extend(summarize(captures))
    return {"rows": rows}


def fetch_indexes(timeout):
    import requests
    response = requests.get("https://index.commoncrawl.org/collinfo.json", headers={"User-Agent": BROWSER_UA}, timeout=timeout)
    response.raise_for_status()
    data = response.json() or []
    indexes = [item.get("id", "") for item in data if item.get("id")]
    return indexes


def fetch_captures(index, host, timeout, limit=800):
    import requests
    params = {"url": host + "/*", "output": "json", "filter": "status:200"}
    response = requests.get("https://index.commoncrawl.org/" + index + "-index", params=params, headers={"User-Agent": BROWSER_UA}, timeout=timeout)
    response.raise_for_status()
    captures = []
    for line in (response.text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json
            captures.append(json.loads(line))
        except Exception:
            continue
        if len(captures) >= limit:
            break
    return captures


def summarize(captures):
    rows = []
    urls = set()
    for item in captures:
        if item.get("url"):
            urls.add(item["url"])
    rows.append(("Common Crawl URLs", str(len(urls)) + " unique in " + str(len(captures)) + " captures"))
    total_bytes = 0
    for item in captures:
        try:
            total_bytes += int(item.get("length", 0) or 0)
        except Exception:
            continue
    if total_bytes:
        rows.append(("Archived bytes", format_bytes(total_bytes)))
    mimes = {}
    for item in captures:
        mime = str(item.get("mime", "") or "").split(";")[0].strip()
        if mime:
            mimes[mime] = mimes.get(mime, 0) + 1
    if mimes:
        rows.append(("Content types", str(len(mimes))))
        for mime, count in sorted(mimes.items(), key=lambda item: -item[1])[:6]:
            rows.append(("CC type: " + short(mime, 60), str(count)))
    subs = {}
    for url in urls:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if host:
            subs[host] = subs.get(host, 0) + 1
    if len(subs) > 1:
        rows.append(("CC subdomains", str(len(subs))))
        for host in sorted(subs, key=lambda h: -subs[h])[:8]:
            rows.append(("CC host: " + short(host, 80), str(subs[host]) + " URLs"))
    samples = sorted(urls)[:5]
    for index, url in enumerate(samples, 1):
        rows.append(("CC sample " + str(index), short(url, 200)))
    return rows


def format_bytes(count):
    if count >= 1073741824:
        return str(round(count / 1073741824, 2)) + " GB"
    if count >= 1048576:
        return str(round(count / 1048576, 1)) + " MB"
    if count >= 1024:
        return str(round(count / 1024, 1)) + " KB"
    return str(count) + " bytes"
