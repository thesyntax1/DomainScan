import re
import json
import hashlib
import urllib.parse

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
        parsed = parse_sitemap(sitemap, "sitemap (robots)")
    else:
        parsed = parse_sitemap(sitemap)
    rows.extend(parsed["rows"])
    sitemap_urls = parsed["urls"]
    security = fetch(session, base_url + "/.well-known/security.txt", timeout)
    if not security["ok"]:
        fallback = fetch(session, base_url + "/security.txt", timeout)
        if fallback["ok"]:
            rows.extend(parse_security(fallback, "security.txt (root)", base_url))
        else:
            rows.extend(parse_security(security, "security.txt", base_url))
    else:
        rows.extend(parse_security(security, "security.txt", base_url))
    ads = fetch(session, base_url + "/ads.txt", timeout)
    rows.extend(parse_ads(ads))
    app_ads = fetch(session, base_url + "/app-ads.txt", timeout)
    if app_ads["ok"]:
        entries = [line.strip() for line in app_ads["text"].splitlines() if line.strip() and not line.strip().startswith("#")]
        rows.append(("app-ads.txt", "Present (" + str(len(entries)) + " entries)"))
    humans = fetch(session, base_url + "/humans.txt", timeout)
    if humans["ok"]:
        rows.append(("humans.txt", "Present (" + str(humans["size"]) + " bytes)"))
        rows.extend(parse_humans(humans["text"]))
    else:
        rows.append(("humans.txt", describe_missing(humans)))
    browserconfig = fetch(session, base_url + "/browserconfig.xml", timeout)
    if browserconfig["ok"]:
        rows.append(("browserconfig.xml", "Present (" + str(browserconfig["size"]) + " bytes)"))
    llms = fetch(session, base_url + "/llms.txt", timeout)
    if llms["ok"]:
        lines = [line.strip() for line in llms["text"].splitlines() if line.strip()]
        rows.append(("llms.txt", "Present (" + str(len(lines)) + " lines, AI crawler guidance)"))
    crossdomain = fetch(session, base_url + "/crossdomain.xml", timeout)
    rows.extend(parse_crossdomain(crossdomain))
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
    rows.extend(well_known_rows(session, base_url, timeout))
    rows.extend(cms_version_rows(session, base_url, timeout))
    return {"rows": rows, "sitemap_urls": sitemap_urls}


def parse_humans(text):
    rows = []
    emails = []
    for match in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text or ""):
        if match not in emails:
            emails.append(match)
    if emails:
        rows.append(("humans.txt emails", str(len(emails)) + ": " + short(", ".join(emails[:5]), 200)))
    for field in ("TEAM", "THANKS", "SITE"):
        if field in (text or ""):
            rows.append(("humans.txt " + field.lower(), "Section present"))
    match = re.search(r"Last update:\s*(.+)", text or "", re.IGNORECASE)
    if match:
        rows.append(("humans.txt updated", short(match.group(1).strip(), 80)))
    return rows


def parse_ads(result):
    rows = []
    if not result["ok"]:
        rows.append(("ads.txt", describe_missing(result)))
        return rows
    entries = []
    variables = []
    for line in result["text"].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and "," not in line.split("=", 1)[0]:
            variables.append(line)
        else:
            entries.append(line)
    rows.append(("ads.txt", "Present (" + str(len(entries)) + " entries, " + str(len(variables)) + " variables)"))
    direct = sum(1 for line in entries if ", DIRECT" in line.upper())
    reseller = sum(1 for line in entries if ", RESELLER" in line.upper())
    rows.append(("ads.txt relationships", str(direct) + " DIRECT, " + str(reseller) + " RESELLER"))
    sellers = set()
    for line in entries[:50]:
        bits = [bit.strip() for bit in line.split(",")]
        if bits:
            sellers.add(bits[0].lower())
    if sellers:
        rows.append(("ads.txt sellers", str(len(sellers)) + " distinct systems"))
    for line in variables[:4]:
        rows.append(("ads.txt variable", short(line, 160)))
    return rows


def parse_crossdomain(result):
    rows = []
    if not result["ok"]:
        rows.append(("crossdomain.xml", describe_missing(result)))
        return rows
    rows.append(("crossdomain.xml", "Present (" + str(result["size"]) + " bytes)"))
    domains = re.findall(r'domain="([^"]+)"', result["text"] or "")
    if domains:
        rows.append(("crossdomain.xml domains", short(", ".join(domains[:8]), 200)))
    if "*" in domains:
        rows.append(("crossdomain.xml policy", "Wildcard allows any Flash client (risky)"))
    if 'secure="false"' in (result["text"] or ""):
        rows.append(("crossdomain.xml transport", "secure=false allows plain HTTP (risky)"))
    return rows


WELL_KNOWN = [
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/openid-configuration",
    "/.well-known/host-meta",
    "/.well-known/dnt-policy.txt",
    "/.well-known/ai-plugin.json",
    "/.well-known/change-password",
]


def well_known_rows(session, base_url, timeout):
    rows = []
    found = 0
    for path in WELL_KNOWN:
        result = fetch(session, base_url + path, timeout)
        if not result["ok"]:
            continue
        found += 1
        rows.append((path, "Present (" + str(result["size"]) + " bytes)"))
        if path.endswith("openid-configuration"):
            rows.extend(parse_openid_config(result["text"]))
    if not found:
        rows.append(("Well-known files", "None of " + str(len(WELL_KNOWN)) + " probed files found"))
    return rows


def parse_openid_config(text):
    rows = []
    try:
        data = json.loads(text or "")
    except Exception:
        rows.append(("OpenID config", "Invalid JSON"))
        return rows
    if data.get("issuer"):
        rows.append(("OpenID issuer", short(data["issuer"], 200)))
    if data.get("authorization_endpoint"):
        rows.append(("OpenID auth", "Endpoint published"))
    grants = data.get("grant_types_supported", []) or []
    if grants:
        rows.append(("OpenID grants", short(", ".join(grants[:6]), 160)))
    return rows


def cms_version_rows(session, base_url, timeout):
    rows = []
    readme = fetch(session, base_url + "/readme.html", timeout)
    if readme["ok"]:
        version = parse_wp_readme(readme["text"])
        if version:
            rows.append(("WordPress version", version + " (readme.html exposed)"))
        else:
            rows.append(("WordPress readme", "Present but version not parsed"))
    changelog = fetch(session, base_url + "/CHANGELOG.txt", timeout)
    if changelog["ok"]:
        version = parse_drupal_changelog(changelog["text"])
        if version:
            rows.append(("Drupal version", version + " (CHANGELOG.txt exposed)"))
        else:
            rows.append(("Drupal changelog", "Present but version not parsed"))
    if not readme["ok"] and not changelog["ok"]:
        rows.append(("CMS version files", "readme.html and CHANGELOG.txt not exposed"))
    return rows


def parse_wp_readme(text):
    match = re.search(r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text or "")
    if match:
        return match.group(1)
    match = re.search(r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text or "")
    if match:
        return match.group(1)
    return ""


def parse_drupal_changelog(text):
    first = (text or "").splitlines()
    if first:
        match = re.search(r"Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9a-z.-]+)?)", first[0], re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


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
    if result["size"] > 500000:
        rows.append(("robots.txt size", "Over 500 KB (unusually large, review)"))
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
    delays = [line for line in rules if line.lower().startswith("crawl-delay:")]
    for line in delays[:3]:
        rows.append(("robots.txt crawl-delay", line.split(":", 1)[1].strip() + "s"))
    empties = [line for line in disallows if not line.split(":", 1)[1].strip()]
    if empties:
        rows.append(("robots.txt empty disallow", "Present (allows all crawling)"))
    interesting = find_interesting_disallows(disallows)
    if interesting:
        rows.append(("robots.txt sensitive paths", str(len(interesting)) + " (attackers read this too)"))
        for index, value in enumerate(interesting[:8], 1):
            rows.append(("robots.txt sensitive " + str(index), short(value, 160)))
    return {"rows": rows, "sitemaps": sitemaps}


def find_interesting_disallows(disallows):
    keywords = ("admin", "login", "wp-", "private", "backup", "config", "api", "internal", "test", "dev", "tmp", "cgi-bin", "phpmyadmin", "server-status")
    found = []
    for line in disallows:
        if ":" in line:
            value = line.split(":", 1)[1].strip()
        else:
            value = line
        if any(keyword in value.lower() for keyword in keywords) and value not in found:
            found.append(value)
    return found


def parse_sitemap(result, label="sitemap.xml"):
    rows = []
    if not result["ok"]:
        rows.append((label, describe_missing(result)))
        return {"rows": rows, "urls": []}
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
    stamps = re.findall(r"<lastmod>(.*?)</lastmod>", result["text"], re.IGNORECASE | re.DOTALL)
    stamps = sorted(item.strip() for item in stamps if item.strip())
    if stamps:
        rows.append(("Sitemap lastmod", str(len(stamps)) + " dated, oldest " + stamps[0][:10] + ", newest " + stamps[-1][:10]))
        rows.append(("Sitemap freshness", sitemap_freshness(stamps[-1][:10])))
    return {"rows": rows, "urls": locations}


def sitemap_freshness(newest):
    import datetime
    try:
        day = datetime.datetime.strptime(newest, "%Y-%m-%d")
    except Exception:
        return "Unparseable date"
    age = (datetime.datetime.now() - day).days
    if age < 0:
        return "Newest entry is in the future (clock issue?)"
    if age > 365:
        return "Stale (newest entry " + str(age) + " days old)"
    return "Fresh (newest entry " + str(age) + " days old)"


def parse_security(result, label="security.txt", base_url=""):
    rows = []
    if not result["ok"]:
        rows.append((label, describe_missing(result)))
        return rows
    rows.append((label, "Present (" + str(result["size"]) + " bytes)"))
    fields = ["Contact", "Expires", "Encryption", "Acknowledgments", "Preferred-Languages", "Canonical", "Hiring", "Policy"]
    values = {}
    for field in fields:
        match = re.search(r"^" + field + r":\s*(.+)$", result["text"], re.IGNORECASE | re.MULTILINE)
        if match:
            values[field] = match.group(1).strip()
            rows.append(("security.txt " + field, short(values[field], 200)))
    if "Expires" in values:
        rows.append(("security.txt expiry", security_expiry(values["Expires"])))
    else:
        rows.append(("security.txt expiry", "Expires field missing (required by RFC 9116)"))
    if "Contact" not in values:
        rows.append(("security.txt contact", "Contact field missing (required by RFC 9116)"))
    if "Canonical" in values and base_url:
        host = urllib.parse.urlsplit(base_url).hostname or ""
        if host and host not in values["Canonical"]:
            rows.append(("security.txt canonical", "Points to another host (review)"))
    if not result["content_type"].lower().startswith("text/plain"):
        rows.append(("security.txt type", "Served as " + short(result["content_type"], 80) + " (should be text/plain)"))
    return rows


def security_expiry(value):
    import datetime
    try:
        moment = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return "Unparseable date"
    now = datetime.datetime.now(datetime.timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    if moment < now:
        return "Expired (update required)"
    return "Valid until " + value[:10]


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
        rows.extend(verify_manifest_icons(session, base_url, path, icons, timeout))
        return rows
    rows.append(("Web manifest", "Not found"))
    return rows


def verify_manifest_icons(session, base_url, manifest_path, icons, timeout):
    rows = []
    if not icons:
        return rows
    base_dir = manifest_path.rsplit("/", 1)[0]
    ok_count = 0
    checked = 0
    for icon in icons[:5]:
        src = (icon or {}).get("src", "")
        if not src:
            continue
        checked += 1
        if src.startswith("http"):
            url = src
        else:
            url = base_url + base_dir + "/" + src.lstrip("/")
        try:
            response = session.head(url, timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                ok_count += 1
        except Exception:
            continue
    if checked:
        rows.append(("Manifest icons reachable", str(ok_count) + " of " + str(checked) + " sampled OK"))
    return rows
