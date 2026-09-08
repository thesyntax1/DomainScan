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
    rows.append(("Clickjacking", framing_verdict(headers or {})))
    rows.extend(cors_check(session, base_url, timeout))
    rows.extend(waf_probe(session, base_url, timeout))
    rows.append(("HSTS preload", hsts_preload(host)))
    rows.append(("IPv6 web", ipv6_web(host, base_url)))
    rows.extend(cdn_rows(headers or {}))
    rows.extend(redirect_rows(session, base_url, timeout))
    rows.extend(host_injection_rows(session, base_url, timeout))
    rows.extend(probe_404(session, base_url, timeout))
    rows.extend(sensitive_checks(session, base_url, timeout))
    rows.extend(api_discovery(session, base_url, timeout))
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
    policy = headers.get("X-Permitted-Cross-Domain-Policies", "")
    if policy:
        rows.append(("X-Permitted-Cross-Domain-Policies", short(policy, 120)))
    return rows


def framing_verdict(headers):
    xfo = headers.get("X-Frame-Options", "").upper()
    csp = headers.get("Content-Security-Policy", "").lower()
    if "frame-ancestors" in csp:
        return "Blocked by CSP frame-ancestors"
    if xfo in ("DENY", "SAMEORIGIN"):
        return "Blocked (" + xfo + ")"
    return "Framing allowed (no X-Frame-Options or frame-ancestors)"


def cors_verdict(acao, vary, evil="https://evil.example"):
    if not acao:
        return "No CORS reflection"
    if acao == "*":
        return "Allows any origin (*)"
    if evil in acao:
        return "Reflects arbitrary origin (misconfigured)"
    detail = "Reflects " + short(acao, 100)
    if "origin" in vary.lower():
        detail = detail + " (Vary: Origin present)"
    return detail


def cors_check(session, base_url, timeout):
    rows = []
    try:
        response = session.get(base_url + "/", timeout=timeout, headers={"Origin": "https://evil.example"})
    except Exception as exc:
        rows.append(("CORS probe", "Request failed (" + exc.__class__.__name__ + ")"))
        return rows
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    vary = response.headers.get("Vary", "")
    rows.append(("CORS probe", cors_verdict(acao, vary)))
    creds = response.headers.get("Access-Control-Allow-Credentials", "")
    if creds.lower() == "true":
        rows.append(("CORS credentials", "Allowed (review with origin policy)"))
    try:
        null_probe = session.get(base_url + "/", timeout=timeout, headers={"Origin": "null"})
        null_acao = null_probe.headers.get("Access-Control-Allow-Origin", "")
        if null_acao == "null":
            rows.append(("CORS null origin", "Trusted (misconfigured, allows sandboxed requests)"))
        else:
            rows.append(("CORS null origin", "Not trusted"))
    except Exception:
        rows.append(("CORS null origin", "Probe failed"))
    return rows


def waf_signature(headers, body):
    low_headers = " ".join((name + " " + value for name, value in headers.items())).lower()
    low_body = (body or "").lower()
    if "cf-ray" in low_headers or "cloudflare" in low_headers or "__cf_bm" in low_body:
        return "Cloudflare"
    if "sucuri" in low_headers or "sucuri" in low_body:
        return "Sucuri"
    if "incapsula" in low_headers or "incap_ses" in low_body:
        return "Imperva"
    if "akamai" in low_headers or "akamaighost" in low_body:
        return "Akamai"
    if "bigip" in low_headers or "f5" in low_headers:
        return "F5 BIG-IP"
    if "barracuda" in low_headers:
        return "Barracuda"
    if "fortigate" in low_headers or "fortinet" in low_body:
        return "Fortinet"
    if "awselb" in low_headers or "awselb" in low_headers:
        return "AWS ELB"
    if "x-sucuri-id" in low_headers:
        return "Sucuri"
    if "x-waf" in low_headers or "waf-event" in low_headers:
        return "Generic WAF"
    if "mod_security" in low_body or "modsecurity" in low_body or "not acceptable" in low_body:
        return "ModSecurity"
    if "wordfence" in low_body or "wfblock" in low_body:
        return "Wordfence"
    if "cloudflare" in low_body and ("attention required" in low_body or "cf-error" in low_body):
        return "Cloudflare"
    if "request unsuccessful" in low_body and "incapsula" in low_body:
        return "Imperva"
    if "reference #" in low_body and "akamai" in low_body:
        return "Akamai"
    if "aws-waf" in low_headers or "awselb/2.0" in low_headers:
        return "AWS WAF"
    if "x-azure-ref" in low_headers and "403" in low_body:
        return "Azure WAF"
    if "x-nf-request-id" in low_headers:
        return "Netlify"
    if "x-vercel" in low_headers:
        return "Vercel"
    if "x-sucuri-cache" in low_headers:
        return "Sucuri"
    return ""


def waf_probe(session, base_url, timeout):
    import requests
    rows = []
    try:
        normal = session.get(base_url + "/", timeout=timeout)
        normal_status = normal.status_code
    except Exception as exc:
        rows.append(("WAF probe", "Request failed (" + exc.__class__.__name__ + ")"))
        return rows
    try:
        probe = session.get(base_url + "/", params={"x": "<script>alert(1)</script>"}, timeout=timeout)
    except Exception as exc:
        rows.append(("WAF probe", "Probe failed (" + exc.__class__.__name__ + ")"))
        return rows
    name = waf_signature(probe.headers, probe.text or "")
    rows.append(("WAF probe status", str(probe.status_code) + " (normal " + str(normal_status) + ")"))
    if probe.status_code in (403, 406, 419, 501, 503) and probe.status_code != normal_status:
        if name:
            rows.append(("WAF verdict", "Request blocked, likely " + name))
        else:
            rows.append(("WAF verdict", "Request blocked by unknown filter"))
    elif name:
        rows.append(("WAF verdict", name + " detected in headers, probe not blocked"))
    else:
        rows.append(("WAF verdict", "No WAF blocking observed"))
    return rows


def api_discovery(session, base_url, timeout):
    rows = []
    targets = [
        "/.well-known/openid-configuration",
        "/api",
        "/api/v1",
        "/graphql",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/wp-json/",
        "/api/openapi.json",
    ]
    for path in targets:
        try:
            response = session.get(base_url + path, timeout=6)
            status = response.status_code
            body = response.text or ""
            ctype = response.headers.get("Content-Type", "")
        except Exception:
            rows.append(("API " + path, "Request failed"))
            continue
        if path == "/.well-known/openid-configuration" and status == 200:
            rows.append(("API " + path, parse_openid(body)))
        elif path == "/graphql":
            hint = graphql_hint(status, body, ctype)
            rows.append(("API " + path, hint))
            if "likely" in hint or "possible" in hint:
                rows.extend(graphql_introspection(session, base_url, timeout))
        elif path in ("/swagger.json", "/openapi.json", "/api/openapi.json") and status == 200:
            rows.append(("API " + path, swagger_hint(body)))
        elif path == "/wp-json/" and status == 200:
            rows.append(("API " + path, wpjson_hint(body)))
        elif status == 200:
            rows.append(("API " + path, "Exists (HTTP 200, " + str(len(body)) + " bytes)"))
        elif status in (401, 403):
            rows.append(("API " + path, "Protected (HTTP " + str(status) + ")"))
        else:
            rows.append(("API " + path, "HTTP " + str(status)))
    return rows


def parse_openid(body):
    import json
    try:
        data = json.loads(body or "")
    except Exception:
        return "Exists but not valid JSON"
    issuer = data.get("issuer", "")
    if issuer:
        return "OpenID provider, issuer " + short(issuer, 120)
    return "JSON found, no issuer field"


def graphql_hint(status, body, ctype):
    low = (body or "").lower()
    if "graphql" in low or '"errors"' in low or '"data"' in low:
        return "GraphQL endpoint likely (HTTP " + str(status) + ")"
    if status == 200:
        return "Exists (HTTP 200)"
    if status in (400, 405) and "json" in ctype.lower():
        return "GraphQL endpoint possible (HTTP " + str(status) + " JSON)"
    return "HTTP " + str(status)


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


def cdn_rows(headers):
    rows = []
    low = " ".join((name + " " + value for name, value in headers.items())).lower()
    names = dict(headers)
    found = []
    if "cf-ray" in low or names.get("Server", "").lower() == "cloudflare":
        found.append("Cloudflare")
    if "x-amz-cf-id" in low or "cloudfront" in low:
        found.append("CloudFront")
    if "fastly" in low:
        found.append("Fastly")
    if "akamai" in low or "x-akamai" in low:
        found.append("Akamai")
    if "bunnycdn" in low:
        found.append("BunnyCDN")
    if "keycdn" in low:
        found.append("KeyCDN")
    if "x-vercel-cache" in low:
        found.append("Vercel")
    if "x-nf-request-id" in low:
        found.append("Netlify")
    if "x-github-request-id" in low:
        found.append("GitHub Pages")
    if "x-sucuri" in low:
        found.append("Sucuri")
    if "incapsula" in low:
        found.append("Imperva")
    if found:
        rows.append(("CDN detected", ", ".join(found)))
    else:
        rows.append(("CDN detected", "None identified in headers"))
    if names.get("Age", ""):
        rows.append(("Cache age", names.get("Age") + "s (response served from cache)"))
    return rows


def redirect_rows(session, base_url, timeout):
    rows = []
    params = ["next", "url", "redirect", "return", "continue", "dest", "r", "u"]
    vulnerable = []
    tested = 0
    for param in params:
        try:
            response = session.get(base_url + "/", params={param: "https://evil.example/"}, timeout=6, allow_redirects=False)
            tested += 1
        except Exception:
            continue
        location = response.headers.get("Location", "")
        if response.status_code in (301, 302, 303, 307, 308) and "evil.example" in location:
            vulnerable.append(param)
    rows.append(("Redirect params tested", str(tested)))
    if vulnerable:
        rows.append(("Open redirect", "VULNERABLE via: " + ", ".join(vulnerable)))
    else:
        rows.append(("Open redirect", "No reflection on common parameters"))
    return rows


def host_injection_rows(session, base_url, timeout):
    rows = []
    try:
        response = session.get(base_url + "/", timeout=timeout, headers={"Host": "evil.example"}, allow_redirects=False)
    except Exception as exc:
        rows.append(("Host header test", "Request failed (" + exc.__class__.__name__ + ")"))
        return rows
    location = response.headers.get("Location", "")
    body = (response.text or "")[:2000]
    if "evil.example" in location:
        rows.append(("Host header test", "Location reflects injected host (cache poisoning risk)"))
    elif "evil.example" in body.lower():
        rows.append(("Host header test", "Body reflects injected host (review)"))
    else:
        rows.append(("Host header test", "Injected host not reflected (HTTP " + str(response.status_code) + ")"))
    return rows


def graphql_introspection(session, base_url, timeout):
    rows = []
    try:
        response = session.post(base_url + "/graphql", json={"query": "{__typename}"}, timeout=8)
    except Exception:
        rows.append(("GraphQL introspection", "Probe failed"))
        return rows
    body = response.text or ""
    if '"__typename"' in body and '"data"' in body:
        rows.append(("GraphQL introspection", "Enabled (schema queryable)"))
    elif response.status_code in (400, 401, 403):
        rows.append(("GraphQL introspection", "Blocked (HTTP " + str(response.status_code) + ")"))
    else:
        rows.append(("GraphQL introspection", "HTTP " + str(response.status_code) + " (review)"))
    return rows


def swagger_hint(body):
    import json
    try:
        data = json.loads(body or "")
    except Exception:
        return "Exists but not valid JSON"
    version = data.get("openapi", "") or data.get("swagger", "")
    title = ""
    try:
        title = (data.get("info", {}) or {}).get("title", "")
    except Exception:
        title = ""
    detail = "Spec published"
    if version:
        detail = detail + " (OpenAPI " + str(version) + ")"
    if title:
        detail = detail + ", " + short(title, 80)
    paths = data.get("paths", {}) or {}
    if isinstance(paths, dict) and paths:
        detail = detail + ", " + str(len(paths)) + " paths"
    return detail


def wpjson_hint(body):
    import json
    try:
        data = json.loads(body or "")
    except Exception:
        return "Exists but not valid JSON"
    detail = "WordPress REST API exposed"
    if isinstance(data, dict):
        if data.get("name"):
            detail = detail + " (" + short(data["name"], 60) + ")"
        namespaces = data.get("namespaces", []) or []
        if namespaces:
            detail = detail + ", " + str(len(namespaces)) + " namespaces"
    return detail


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
