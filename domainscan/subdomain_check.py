import random
import string
from concurrent.futures import ThreadPoolExecutor

from domainscan import dns_check
from domainscan.helpers import BROWSER_UA, short


WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "api", "dev", "development",
    "test", "testing", "stage", "staging", "beta", "alpha", "demo", "sandbox", "admin",
    "administrator", "portal", "login", "sso", "secure", "vpn", "remote", "office",
    "intranet", "extranet", "support", "help", "helpdesk", "docs", "wiki", "blog",
    "news", "forum", "community", "shop", "store", "pay", "billing", "cdn", "static",
    "assets", "img", "images", "media", "video", "m", "mobile", "app", "apps", "my",
    "account", "accounts", "id", "auth", "oauth", "git", "svn", "ci", "jenkins",
    "jira", "confluence", "status", "monitor", "grafana", "logs", "metrics", "db",
    "database", "mysql", "redis", "cache", "proxy", "gateway", "ns1", "ns2", "dns",
    "mx1", "mx2", "relay", "sip", "voip", "pbx", "backup", "old", "new", "v1",
    "v2", "eu", "us", "uk", "tr", "de", "fr", "partner", "partners", "client",
    "clients", "corp", "internal", "private", "public", "files", "drive", "cloud",
    "storage", "crm", "erp", "hr", "jobs", "careers", "marketing", "sales",
    "graphql", "rest", "webhook", "hooks", "socket", "ws", "mqtt", "kafka",
    "elastic", "kibana", "prometheus", "alertmanager", "sentry", "vault",
    "consul", "nomad", "k8s", "kubernetes", "rancher", "openshift", "docker",
    "registry", "artifacts", "nexus", "sonar", "gitlab", "bitbucket",
    "redmine", "youtrack", "wiki2", "kb", "lms", "moodle", "academia",
    "webinar", "events", "survey", "forms", "newsletter", "cdn2", "origin",
    "edge", "lb", "ha", "dr", "uat", "qa", "preprod", "preview", "canary",
    "ab", "labs", "research", "ai", "ml", "data", "analytics", "bi",
    "reports", "dashboard", "admin2", "root", "super", "manage", "control",
    "panel", "cpanel", "plesk", "webmin", "phpmyadmin", "dbadmin",
]

TAKEOVER_SUFFIXES = [
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudapp.azure.com",
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
    "fastly.net", "myshopify.com", "wordpress.com", "tumblr.com", "ghost.io",
    "readme.io", "uservoice.com", "zendesk.com", "freshdesk.com",
    "cargocollective.com", "bitbucket.io", "unbouncepages.com", "launchrock.com",
    "helpscoutdocs.com", "surge.sh", "ngrok.io", "pantheonsite.io",
    "netlify.app", "vercel.app", "pages.dev", "webflow.io", "thinkific.com",
    "teachable.com", "bigcartel.com", "squarespace.com", "weebly.com",
    "animaapp.io", "apology.io", "aftership.com", "aha.io", "helpjuice.com",
    "helprace.com", "landingi.com", "mashery.com", "ngrok-free.app",
    "pingdom.com", "proposify.com", "readthedocs.io", "short.io",
    "smugmug.com", "strikingly.com", "tilda.ws", "wixsite.com",
    "wordpress.org", "worksites.net", "yolasite.com", "hatenablog.com",
    "feedpress.com", "gemfury.com", "jit.si", "kinsta.cloud",
]


def collect(apex, enabled=True):
    rows = []
    if not enabled:
        rows.append(("Subdomain discovery", "Skipped (disabled in options)"))
        return {"rows": rows, "confirmed": {}}
    if not apex or "." not in apex:
        rows.append(("Subdomain discovery", "Requires a domain name"))
        return {"rows": rows, "confirmed": {}}
    rows.append(("Subdomain target", apex))
    if not dns_check.HAS_DNSPYTHON:
        rows.append(("Subdomain discovery", "Limited (dnspython not installed)"))
        return {"rows": rows, "confirmed": {}}
    resolver = dns_check.make_resolver()
    wildcard, wildcard_ips = detect_wildcard(resolver, apex)
    if wildcard:
        rows.append(("Wildcard DNS", "Yes, unknown names resolve to " + ", ".join(sorted(wildcard_ips))))
    else:
        rows.append(("Wildcard DNS", "No"))
    certs, crt_names, crt_wild = fetch_crt(apex)
    if certs < 0:
        rows.append(("crt.sh", "Lookup failed"))
        crt_names = set()
    else:
        rows.append(("crt.sh certificates", str(certs)))
        rows.append(("crt.sh names", str(len(crt_names))))
        rows.append(("crt.sh wildcards", str(crt_wild)))
    sonar_names = fetch_sonar(apex)
    if sonar_names is None:
        rows.append(("Sonar passive DNS", "Lookup failed"))
    else:
        rows.append(("Sonar names", str(len(sonar_names))))
    ht_names = fetch_hackertarget(apex)
    if ht_names is None:
        rows.append(("HackerTarget", "Lookup failed"))
    else:
        rows.append(("HackerTarget names", str(len(ht_names))))
    brute = brute_force(resolver, apex, wildcard_ips)
    rows.append(("Brute-force names tried", str(len(WORDLIST))))
    rows.append(("Brute-force hits", str(len(brute))))
    combined = set(brute)
    for names in (crt_names, sonar_names or set(), ht_names or set()):
        for name in names:
            if name == apex or name.endswith("." + apex):
                combined.add(name)
    combined.discard(apex)
    rows.append(("Unique names found", str(len(combined))))
    confirmed, excluded = verify_names(resolver, combined - set(brute), 150, wildcard_ips)
    if excluded:
        rows.append(("Wildcard artifacts excluded", str(excluded)))
    for name, addresses in brute.items():
        confirmed[name] = addresses
    rows.extend(depth_rows(combined, apex))
    rows.append(("Confirmed subdomains", str(len(confirmed))))
    for index, name in enumerate(sorted(confirmed)[:60], 1):
        rows.append(("Subdomain " + str(index), name + " -> " + ", ".join(confirmed[name][:4])))
    if len(confirmed) > 60:
        rows.append(("Subdomain note", "Showing first 60 of " + str(len(confirmed))))
    unresolved = len(combined) - len(confirmed)
    if unresolved > 0:
        rows.append(("Unresolved names", str(unresolved) + " (seen in records but no A answer)"))
    rows.extend(check_takeover(resolver, sorted(confirmed)[:40]))
    return {"rows": rows, "confirmed": confirmed}


def detect_wildcard(resolver, apex):
    hits = []
    for _ in range(2):
        label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(14))
        try:
            result = dns_check.query(resolver, label + "." + apex, "A")
        except Exception:
            return False, set()
        if not result["records"]:
            return False, set()
        hits.append(set(result["records"]))
    if hits[0] == hits[1]:
        return True, hits[0]
    return False, set()


def brute_force(resolver, apex, wildcard_ips):
    found = {}

    def check(prefix):
        try:
            result = dns_check.query(resolver, prefix + "." + apex, "A")
        except Exception:
            return None
        if not result["records"]:
            return None
        if wildcard_ips and set(result["records"]) <= wildcard_ips:
            return None
        return (prefix + "." + apex, result["records"])

    with ThreadPoolExecutor(max_workers=10) as pool:
        for item in pool.map(check, WORDLIST):
            if item:
                found[item[0]] = item[1]
    return found


def verify_names(resolver, names, cap=150, wildcard_ips=None):
    confirmed = {}
    excluded = 0
    picked = sorted(names)[:cap]

    def check(name):
        try:
            result = dns_check.query(resolver, name, "A")
        except Exception:
            return None
        if not result["records"]:
            return None
        if wildcard_ips and set(result["records"]) <= set(wildcard_ips):
            return (name, None)
        return (name, result["records"])

    with ThreadPoolExecutor(max_workers=10) as pool:
        for item in pool.map(check, picked):
            if not item:
                continue
            if item[1] is None:
                excluded += 1
            else:
                confirmed[item[0]] = item[1]
    return confirmed, excluded


def subdomain_depths(names, apex):
    depths = {}
    base = len((apex or "").split("."))
    for name in names or []:
        depth = max(len(name.split(".")) - base, 0)
        depths[depth] = depths.get(depth, 0) + 1
    return depths


def depth_rows(names, apex):
    rows = []
    for depth in sorted(subdomain_depths(names, apex)):
        count = subdomain_depths(names, apex)[depth]
        if depth == 1:
            rows.append(("Direct subdomains", str(count)))
        else:
            rows.append(("Level " + str(depth) + " subdomains", str(count)))
    return rows


def is_takeover_candidate(target):
    clean = (target or "").lower().rstrip(".")
    for suffix in TAKEOVER_SUFFIXES:
        if clean == suffix or clean.endswith("." + suffix):
            return True
    return False


def check_takeover(resolver, names):
    rows = []
    if not names:
        rows.append(("Takeover review", "No subdomains to review"))
        return rows

    def check(name):
        try:
            cname_result = dns_check.query(resolver, name, "CNAME")
        except Exception:
            return ""
        if not cname_result["records"]:
            return ""
        target = cname_result["records"][0].rstrip(".").lower()
        if not is_takeover_candidate(target):
            return ""
        try:
            target_result = dns_check.query(resolver, target, "A")
            records = target_result["records"]
        except Exception:
            records = []
        if not records:
            return name + " CNAME " + target + " (target has no A record, verify manually)"
        return ""

    flagged = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for item in pool.map(check, names):
            if item:
                flagged.append(item)
    if not flagged:
        rows.append(("Takeover review", "No dangling CNAMEs spotted on checked subdomains"))
        return rows
    for index, item in enumerate(flagged[:10], 1):
        rows.append(("Review " + str(index), short(item, 220)))
    if len(flagged) > 10:
        rows.append(("Review note", "Showing first 10 of " + str(len(flagged))))
    return rows


def fetch_crt(apex):
    import requests
    try:
        url = "https://crt.sh/?q=%25." + apex + "&output=json"
        response = requests.get(url, timeout=15, headers={"User-Agent": BROWSER_UA})
        response.raise_for_status()
        entries = response.json()
    except Exception:
        return -1, set(), 0
    return parse_crt(entries)


def parse_crt(entries):
    names = set()
    wildcards = 0
    certs = 0
    for entry in entries or []:
        certs += 1
        blob = str((entry or {}).get("name_value", ""))
        for line in blob.splitlines():
            item = line.strip().lower().rstrip(".")
            if not item:
                continue
            if item.startswith("*."):
                wildcards += 1
                continue
            names.add(item)
    return certs, names, wildcards


def fetch_sonar(apex):
    import requests
    try:
        url = "https://sonar.omnisint.io/subdomains/" + apex
        response = requests.get(url, timeout=10, headers={"User-Agent": BROWSER_UA})
        response.raise_for_status()
        data = response.json()
    except Exception:
        return None
    return parse_sonar(data)


def parse_sonar(data):
    names = set()
    for item in data or []:
        clean = str(item).strip().lower().rstrip(".")
        if clean:
            names.add(clean)
    return names


def fetch_hackertarget(apex):
    import requests
    try:
        url = "https://api.hackertarget.com/hostsearch/"
        response = requests.get(url, params={"q": apex}, timeout=10, headers={"User-Agent": BROWSER_UA})
        response.raise_for_status()
        text = response.text
    except Exception:
        return None
    return parse_hostsearch(text)


def parse_hostsearch(text):
    names = set()
    for line in (text or "").splitlines():
        clean = line.strip().lower()
        if "," not in clean:
            continue
        host = clean.split(",", 1)[0].strip().rstrip(".")
        if not host or " " in host or "/" in host:
            continue
        names.add(host)
    return names


def extract_title(html):
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    if match:
        return short(re.sub(r"\s+", " ", match.group(1).strip()), 120)
    return ""


def fetch_subdomain_page(url, timeout=8):
    import requests
    response = requests.get(url, timeout=timeout, headers={"User-Agent": BROWSER_UA}, allow_redirects=True)
    return {
        "status": response.status_code,
        "server": response.headers.get("Server", ""),
        "title": extract_title(response.text or ""),
        "url": response.url,
    }


def probe_web(names, limit=20, timeout=8):
    rows = []
    picked = sorted(names)[:limit]
    if not picked:
        rows.append(("Subdomain web", "No subdomains to probe"))
        return {"rows": rows}

    def fetch(name):
        for scheme in ("https", "http"):
            try:
                info = fetch_subdomain_page(scheme + "://" + name + "/", timeout)
                return (name, info)
            except Exception:
                continue
        return (name, None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(fetch, picked))
    for name, info in sorted(results):
        if not info:
            rows.append((name, "No HTTP(S) response"))
            continue
        detail = "HTTP " + str(info["status"])
        if info["server"]:
            detail = detail + ", " + short(info["server"], 80)
        if info["title"]:
            detail = detail + ", " + info["title"]
        rows.append((name, detail))
    return {"rows": rows}
