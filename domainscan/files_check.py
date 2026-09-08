import re
import json
import hashlib

from domainscan.helpers import BROWSER_UA, favicon_hash, short


def collect(base_url, timeout=10):
    import requests
    rows = []
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_UA})
    robots = parse_robots(fetch(session, base_url + "/robots.txt", timeout))
    rows.extend(robots["rows"])
    sitemap = fetch(session, base_url + "/sitemap.xml", timeout)
    if not sitemap["ok"] and robots["sitemaps"]:
        first = robots["sitemaps"][0]
        if first.startswith("http"):
            sitemap_url = first
        else:
            sitemap_url = base_url + first
        try:
            sitemap = fetch(session, sitemap_url, timeout)
        except Exception:
            pass
        rows.extend(parse_sitemap(sitemap, "sitemap (robots)"))
    else:
        rows.extend(parse_sitemap(sitemap))
    security = fetch(session, base_url + "/.well-known/security.txt", timeout)
    if not security["ok"]:
        fallback = fetch(session, base_url + "/security.txt", timeout)
        if fallback["ok"]:
            rows.extend(parse_security(fallback, "security.txt (root)"))
        else:
            rows.extend(parse_security(security))
    else:
        rows.extend(parse_security(security))
    ads = fetch(session, base_url + "/ads.txt", timeout)
    if ads["ok"]:
        lines = [line.strip() for line in ads["text"].splitlines() if line.strip()]
        rows.append(("ads.txt", "Present (" + str(len(lines)) + " entries)"))
    else:
        rows.append(("ads.txt", describe_missing(ads)))
    humans = fetch(session, base_url + "/humans.txt", timeout)
    if humans["ok"]:
        rows.append(("humans.txt", "Present (" + str(humans["size"]) + " bytes)"))
    else:
        rows.append(("humans.txt", describe_missing(humans)))
    crossdomain = fetch(session, base_url + "/crossdomain.xml", timeout)
    if crossdomain["ok"]:
        rows.append(("crossdomain.xml", "Present (" + str(crossdomain["size"]) + " bytes)"))
        if "*" in crossdomain["text"]:
            rows.append(("crossdomain.xml policy", "Wildcard found (review manually)"))
    else:
        rows.append(("crossdomain.xml", describe_missing(crossdomain)))
    clientaccess = fetch(session, base_url + "/clientaccesspolicy.xml", timeout)
    if clientaccess["ok"]:
        rows.append(("clientaccesspolicy.xml", "Present (" + str(clientaccess["size"]) + " bytes)"))
    else:
        rows.append(("clientaccesspolicy.xml", describe_missing(clientaccess)))
    favicon = fetch(session, base_url + "/favicon.ico", timeout, text=False)
    if favicon["ok"]:
        detail = "Present (" + str(favicon["size"]) + " bytes"
        if favicon["content_type"]:
            detail = detail + ", " + favicon["content_type"]
        rows.append(("Favicon", detail + ")"))
        rows.append(("Favicon hash", str(favicon_hash(favicon["raw"])) + " (Shodan-compatible)"))
        rows.append(("Favicon MD5", hashlib.md5(favicon["raw"]).hexdigest()))
    else:
        rows.append(("Favicon", describe_missing(favicon)))
    rows.extend(find_manifest(session, base_url, timeout))
    return {"rows": rows}


def fetch(session, url, timeout, text=True):
    try:
        response = session.get(url, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "status": 0, "text": "", "size": 0, "content_type": "", "error": exc.__class__.__name__, "raw": b""}
    body = response.content or b""
    content = ""
    if text:
        try:
            content = body[:200000].decode(response.encoding or "utf-8", "ignore")
        except Exception:
            content = ""
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "text": content,
        "size": len(body),
        "content_type": response.headers.get("Content-Type", ""),
        "error": "",
        "raw": body,
    }


def describe_missing(result):
    if result["status"]:
        return "Not available (HTTP " + str(result["status"]) + ")"
    return "Not available (" + result["error"] + ")"


def parse_robots(result):
    rows = []
    if not result["ok"]:
        rows.append(("robots.txt", describe_missing(result)))
        return {"rows": rows, "sitemaps": []}
    lines = [line.strip() for line in result["text"].splitlines()]
    rules = [line for line in lines if line and not line.startswith("#")]
    allows = [line for line in rules if line.lower().startswith("allow:")]
    disallows = [line for line in rules if line.lower().startswith("disallow:")]
    sitemaps = []
    agents = []
    for line in rules:
        low = line.lower()
        if low.startswith("sitemap:") and ":" in line:
            sitemaps.append(line.split(":", 1)[1].strip())
        if low.startswith("user-agent:") and ":" in line:
            agents.append(line.split(":", 1)[1].strip())
    rows.append(("robots.txt", "Present (" + str(result["size"]) + " bytes)"))
    rows.append(("robots.txt rules", str(len(rules)) + " lines"))
    rows.append(("robots.txt user-agents", str(len(set(agents)))))
    rows.append(("robots.txt allow count", str(len(allows))))
    rows.append(("robots.txt disallow count", str(len(disallows))))
    rows.append(("robots.txt sitemap count", str(len(sitemaps))))
    for index, line in enumerate(disallows[:10], 1):
        if ":" in line:
            value = line.split(":", 1)[1].strip()
        else:
            value = line
        rows.append(("robots.txt disallow " + str(index), short(value, 160)))
    for index, target in enumerate(sitemaps[:5], 1):
        rows.append(("robots.txt sitemap " + str(index), short(target, 200)))
    return {"rows": rows, "sitemaps": sitemaps}


def parse_sitemap(result, label="sitemap.xml"):
    rows = []
    if not result["ok"]:
        rows.append((label, describe_missing(result)))
        return rows
    locations = re.findall(r"<loc>(.*?)</loc>", result["text"], re.IGNORECASE | re.DOTALL)
    locations = [re.sub(r"\s+", "", item) for item in locations if item.strip()]
    rows.append((label, "Present (" + str(result["size"]) + " bytes)"))
    if "<sitemapindex" in result["text"].lower():
        rows.append(("Sitemap type", "Index of sitemaps"))
    else:
        rows.append(("Sitemap type", "URL set"))
    rows.append(("Sitemap URL count", str(len(locations))))
    for index, target in enumerate(locations[:5], 1):
        rows.append(("Sitemap URL " + str(index), short(target, 200)))
    return rows


def parse_security(result, label="security.txt"):
    rows = []
    if not result["ok"]:
        rows.append((label, describe_missing(result)))
        return rows
    rows.append((label, "Present (" + str(result["size"]) + " bytes)"))
    fields = ["Contact", "Expires", "Encryption", "Acknowledgments", "Preferred-Languages", "Canonical", "Hiring", "Policy"]
    for field in fields:
        match = re.search(r"^" + field + r":\s*(.+)$", result["text"], re.IGNORECASE | re.MULTILINE)
        if match:
            rows.append(("security.txt " + field, short(match.group(1).strip(), 200)))
    return rows


def find_manifest(session, base_url, timeout):
    rows = []
    for path in ("/site.webmanifest", "/manifest.json"):
        result = fetch(session, base_url + path, timeout)
        if not result["ok"]:
            continue
        try:
            data = json.loads(result["text"])
        except Exception:
            rows.append(("Web manifest", path + " exists but is not valid JSON"))
            return rows
        rows.append(("Web manifest", "Present at " + path))
        wanted = [
            ("name", "App name"),
            ("short_name", "Short name"),
            ("start_url", "Start URL"),
            ("display", "Display"),
            ("theme_color", "Theme color"),
            ("background_color", "Background color"),
        ]
        for key, label in wanted:
            if data.get(key):
                rows.append(("Manifest " + label.lower(), short(data[key], 120)))
        icons = data.get("icons", []) or []
        rows.append(("Manifest icons", str(len(icons))))
        return rows
    rows.append(("Web manifest", "Not found"))
    return rows
