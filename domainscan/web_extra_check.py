import urllib.parse

from domainscan import dns_check
from domainscan.helpers import BROWSER_UA, short


SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref:"),
    ("/.env", None),
    ("/server-status", None),
    ("/phpinfo.php", "phpinfo()"),
    ("/.DS_Store", None),
]


def collect(base_url, headers=None, timeout=10):
    import requests
    rows = []
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_UA})
    host = urllib.parse.urlsplit(base_url).hostname or ""
    rows.extend(method_checks(session, base_url, timeout))
    rows.extend(header_checks(headers or {}))
    rows.append(("HSTS preload", hsts_preload(host)))
    rows.append(("IPv6 web", ipv6_web(host, base_url)))
    rows.extend(probe_404(session, base_url, timeout))
    rows.extend(sensitive_checks(session, base_url, timeout))
    return {"rows": rows}


def method_checks(session, base_url, timeout):
    rows = []
    try:
        response = session.options(base_url + "/", timeout=timeout)
        allow = response.headers.get("Allow", "")
        rows.append(("OPTIONS status", str(response.status_code)))
        if allow:
            rows.append(("Allowed methods", short(allow, 200)))
        else:
            rows.append(("Allowed methods", "No Allow header"))
    except Exception as exc:
        rows.append(("OPTIONS status", "Request failed (" + exc.__class__.__name__ + ")"))
    for method in ("PUT", "DELETE", "PATCH"):
        try:
            response = session.request(method, base_url + "/", timeout=timeout)
            rows.append((method + " status", str(response.status_code)))
        except Exception as exc:
            rows.append((method + " status", "Request failed (" + exc.__class__.__name__ + ")"))
    try:
        response = session.request("TRACE", base_url + "/", timeout=timeout)
        body = response.text or ""
        if response.status_code == 200 and "TRACE" in body.upper():
            rows.append(("TRACE method", "Enabled (request echoed, review needed)"))
        else:
            rows.append(("TRACE method", "Disabled or blocked (HTTP " + str(response.status_code) + ")"))
    except Exception as exc:
        rows.append(("TRACE method", "Request failed (" + exc.__class__.__name__ + ")"))
    return rows


def header_checks(headers):
    rows = []
    rows.append(("HTTP/3 advertised", parse_alt_svc(headers.get("Alt-Svc", ""))))
    robots_tag = headers.get("X-Robots-Tag", "")
    if robots_tag:
        rows.append(("X-Robots-Tag", short(robots_tag, 160)))
    if headers.get("Report-To", "") or headers.get("NEL", ""):
        rows.append(("Error reporting", "Configured (Report-To/NEL present)"))
    else:
        rows.append(("Error reporting", "No Report-To/NEL header"))
    timing = headers.get("Server-Timing", "")
    if timing:
        rows.append(("Server-Timing", short(timing, 160)))
    return rows


def parse_alt_svc(value):
    if not value:
        return "No (no Alt-Svc header)"
    low = value.lower()
    if "h3=" in low or "h3-" in low or low.strip().startswith("h3"):
        return "Yes (" + short(value, 160) + ")"
    return "No (" + short(value, 160) + ")"


def hsts_preload(host):
    import requests
    if not host:
        return "Unknown"
    try:
        url = "https://hstspreload.org/api/v2/status?domain=" + host
        response = requests.get(url, timeout=8, headers={"User-Agent": BROWSER_UA})
        data = response.json()
    except Exception:
        return "Lookup failed"
    status = str(data.get("status", "")).lower()
    if status == "preloaded":
        return "Yes, domain is preloaded"
    if status == "pending":
        return "Pending submission"
    return "Not preloaded"


def ipv6_web(host, base_url):
    import socket
    import time
    if not host or not dns_check.HAS_DNSPYTHON:
        return "Not checked"
    try:
        resolver = dns_check.make_resolver()
        result = dns_check.query(resolver, host, "AAAA")
    except Exception:
        return "Lookup failed"
    if not result["records"]:
        return "No AAAA record"
    ip = result["records"][0]
    if base_url.startswith("http://"):
        port = 80
    else:
        port = 443
    started = time.perf_counter()
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        sock.close()
    except Exception:
        return "AAAA present but port " + str(port) + " unreachable over IPv6"
    elapsed = int((time.perf_counter() - started) * 1000)
    return "Reachable (" + ip + ", " + str(elapsed) + " ms)"


def probe_404(session, base_url, timeout):
    rows = []
    try:
        response = session.get(base_url + "/domainscan-404-probe", timeout=timeout)
    except Exception as exc:
        rows.append(("404 probe", "Request failed (" + exc.__class__.__name__ + ")"))
        return rows
    rows.append(("404 probe status", str(response.status_code)))
    rows.append(("404 probe size", str(len(response.content or b"")) + " bytes"))
    server = response.headers.get("Server", "")
    if server:
        rows.append(("404 probe server", short(server, 120)))
    if response.status_code == 200:
        rows.append(("404 handling", "Unknown paths return 200 (soft 404)"))
    elif response.status_code == 404:
        rows.append(("404 handling", "Standard 404 page"))
    elif response.status_code in (401, 403):
        rows.append(("404 handling", "Blocked (" + str(response.status_code) + "), possible WAF"))
    return rows


def sensitive_checks(session, base_url, timeout):
    rows = []
    for path, marker in SENSITIVE_PATHS:
        try:
            response = session.get(base_url + path, timeout=timeout)
            rows.append((path, verdict_sensitive(response.status_code, response.text or "", marker)))
        except Exception as exc:
            rows.append((path, "Request failed (" + exc.__class__.__name__ + ")"))
    return rows


def verdict_sensitive(status, body, marker):
    if status == 200:
        if marker is None or marker in body:
            return "EXPOSED (returns 200, review immediately)"
        return "Returns 200 without expected marker (review manually)"
    if status in (401, 403):
        return "Protected (HTTP " + str(status) + ")"
    if status == 404:
        return "Not found"
    return "HTTP " + str(status)
