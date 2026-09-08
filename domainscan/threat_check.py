from domainscan.helpers import BROWSER_UA, short


def collect(host, apex, timeout=12):
    rows = []
    name = apex or host
    if not name:
        rows.append(("Threat intel", "No domain to query"))
        return {"rows": rows}
    rows.append(("Threat target", name))
    rows.extend(urlscan_rows(name, timeout))
    rows.extend(threatfox_rows(name, timeout))
    rows.extend(urlhaus_rows(name, timeout))
    return {"rows": rows}


def urlscan_rows(name, timeout):
    import requests
    rows = []
    try:
        url = "https://urlscan.io/api/v1/search/"
        params = {"q": "domain:" + name, "size": 100}
        response = requests.get(url, params=params, headers={"User-Agent": BROWSER_UA}, timeout=timeout)
        data = response.json()
    except Exception as exc:
        rows.append(("urlscan.io", "Query failed (" + exc.__class__.__name__ + ")"))
        return rows
    results = data.get("results", []) or []
    total = data.get("total", len(results))
    rows.append(("urlscan.io scans", str(total) + " public scans"))
    if not results:
        return rows
    malicious = 0
    suspicious = 0
    ips = {}
    asns = {}
    servers = {}
    countries = {}
    for item in results:
        verdicts = item.get("verdicts", {}) or {}
        overall = verdicts.get("overall", {}) or {}
        if overall.get("malicious"):
            malicious += 1
        elif overall.get("score", 0) and int(overall.get("score") or 0) > 0:
            suspicious += 1
        page = item.get("page", {}) or {}
        if page.get("ip"):
            ips[page["ip"]] = ips.get(page["ip"], 0) + 1
        if page.get("asn"):
            label = str(page["asn"]) + " " + str(page.get("asnname", "")).strip()
            asns[label] = asns.get(label, 0) + 1
        if page.get("server"):
            servers[page["server"]] = servers.get(page["server"], 0) + 1
        if page.get("country"):
            countries[page["country"]] = countries.get(page["country"], 0) + 1
    rows.append(("urlscan.io verdicts", str(malicious) + " malicious, " + str(suspicious) + " suspicious of " + str(len(results))))
    times = sorted((item.get("task", {}) or {}).get("time", "") for item in results if (item.get("task", {}) or {}).get("time"))
    if times:
        rows.append(("urlscan.io first seen", times[0][:10]))
        rows.append(("urlscan.io last seen", times[-1][:10]))
    if ips:
        rows.append(("urlscan.io IPs", str(len(ips)) + " distinct"))
        top_ip = sorted(ips, key=lambda k: -ips[k])[0]
        rows.append(("urlscan.io top IP", top_ip + " (" + str(ips[top_ip]) + " scans)"))
    if asns:
        rows.append(("urlscan.io ASN", short(sorted(asns, key=lambda k: -asns[k])[0], 120)))
    if servers:
        rows.append(("urlscan.io servers", short(", ".join(sorted(servers)[:5]), 200)))
    if countries:
        rows.append(("urlscan.io countries", short(", ".join(sorted(countries)[:8]), 160)))
    latest = results[0]
    scan_id = latest.get("_id", "")
    if scan_id:
        rows.append(("urlscan.io latest", "https://urlscan.io/result/" + scan_id + "/"))
    return rows


def threatfox_rows(name, timeout):
    import requests
    rows = []
    try:
        response = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": name}, headers={"User-Agent": BROWSER_UA}, timeout=timeout)
        data = response.json()
    except Exception as exc:
        rows.append(("ThreatFox", "Query failed (" + exc.__class__.__name__ + ")"))
        return rows
    if data.get("query_status") != "ok":
        rows.append(("ThreatFox", "No malware samples reference this domain"))
        return rows
    samples = data.get("data", []) or []
    rows.append(("ThreatFox samples", str(len(samples)) + " malware IoCs"))
    families = {}
    for sample in samples:
        family = sample.get("malware_printable", "") or "Unknown"
        families[family] = families.get(family, 0) + 1
    for family, count in sorted(families.items(), key=lambda item: -item[1])[:8]:
        rows.append(("ThreatFox: " + short(family, 60), str(count) + " samples"))
    first_seen = sorted(str(sample.get("first_seen", "")) for sample in samples if sample.get("first_seen"))
    if first_seen:
        rows.append(("ThreatFox first seen", first_seen[0][:10]))
    return rows


def urlhaus_rows(name, timeout):
    import requests
    rows = []
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": name}, headers={"User-Agent": BROWSER_UA}, timeout=timeout)
        data = response.json()
    except Exception as exc:
        rows.append(("URLhaus", "Query failed (" + exc.__class__.__name__ + ")"))
        return rows
    status = data.get("query_status", "")
    if status != "ok":
        rows.append(("URLhaus", "No malicious URLs hosted here"))
        return rows
    urls = ((data.get("data", {}) or {}).get("urls", [])) or []
    online = [item for item in urls if item.get("url_status", "") == "online"]
    rows.append(("URLhaus URLs", str(len(urls)) + " flagged (" + str(len(online)) + " still online)"))
    threats = {}
    for item in urls:
        threat = item.get("threat", "") or "unknown"
        threats[threat] = threats.get(threat, 0) + 1
    for threat, count in sorted(threats.items(), key=lambda item: -item[1])[:6]:
        rows.append(("URLhaus: " + short(threat, 60), str(count) + " URLs"))
    for item in online[:5]:
        rows.append(("URLhaus online", short(item.get("url", ""), 200)))
    return rows
