import re
import socket
import ssl
import time
import warnings
import hashlib
import datetime

from domainscan.helpers import BROWSER_UA, short


SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking protection"),
    ("X-Content-Type-Options", "MIME sniffing protection"),
    ("Referrer-Policy", "Referrer policy"),
    ("Permissions-Policy", "Permissions policy"),
    ("Cross-Origin-Opener-Policy", "COOP"),
    ("Cross-Origin-Resource-Policy", "CORP"),
    ("Cross-Origin-Embedder-Policy", "COEP"),
]

MAX_HTML = 1500000


def collect_http(fetch_url, timeout=12):
    import requests
    rows = []
    result = {
        "rows": rows,
        "html": "",
        "headers": {},
        "final_url": fetch_url,
        "status": 0,
        "cookies": [],
        "elapsed_ms": 0,
        "total_ms": 0,
        "ttfb_ms": 0,
        "raw_bytes": 0,
        "decoded_bytes": 0,
        "http_version": "",
    }
    session = requests.Session()
    session.headers.update({
        "User-Agent": BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    started = time.perf_counter()
    try:
        response = session.get(fetch_url, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        rows.append(("Website status", "Request failed (" + exc.__class__.__name__ + ": " + short(str(exc), 160) + ")"))
        return result
    elapsed = int((time.perf_counter() - started) * 1000)
    result["elapsed_ms"] = elapsed
    result["total_ms"] = elapsed
    try:
        result["ttfb_ms"] = int(response.elapsed.total_seconds() * 1000)
    except Exception:
        result["ttfb_ms"] = 0
    decoded_size = len(response.content or b"")
    result["decoded_bytes"] = decoded_size
    try:
        raw_hint = int(response.headers.get("Content-Length", "0") or 0)
    except Exception:
        raw_hint = 0
    if response.headers.get("Content-Encoding", "") and raw_hint:
        result["raw_bytes"] = raw_hint
    else:
        result["raw_bytes"] = decoded_size
    result["http_version"] = http_version(response)
    result["status"] = response.status_code
    result["final_url"] = response.url
    result["headers"] = dict(response.headers)
    history = response.history or []
    rows.append(("Requested URL", fetch_url))
    rows.append(("Final URL", response.url))
    rows.append(("Redirect count", str(len(history))))
    for index, hop in enumerate(history, 1):
        target = hop.headers.get("Location", "")
        rows.append(("Redirect " + str(index), str(hop.status_code) + " " + (hop.reason or "") + " -> " + short(target, 200)))
        server = hop.headers.get("Server", "")
        if server:
            rows.append(("Redirect " + str(index) + " server", short(server, 120)))
    if fetch_url.startswith("http://") and response.url.startswith("https://"):
        rows.append(("HTTPS upgrade", "Yes, plain HTTP redirects to HTTPS"))
    rows.append(("HTTP status", str(response.status_code) + " " + (response.reason or "")))
    rows.append(("Response time", str(elapsed) + " ms"))
    if result["ttfb_ms"]:
        rows.append(("Time to first byte", str(result["ttfb_ms"]) + " ms"))
    if result["http_version"]:
        rows.append(("HTTP version", result["http_version"]))
    if result["raw_bytes"] and result["decoded_bytes"] and result["raw_bytes"] != result["decoded_bytes"]:
        saved = 100 - int(result["raw_bytes"] * 100 / result["decoded_bytes"])
        rows.append(("Compression saving", str(saved) + "% (" + str(result["raw_bytes"]) + " of " + str(result["decoded_bytes"]) + " bytes)"))
    rows.append(("Body size", str(len(response.content or b"")) + " bytes"))
    rows.append(("Content type", response.headers.get("Content-Type", "Not specified")))
    rows.append(("Encoding", response.encoding or "Not specified"))
    rows.append(("Header count", str(len(response.headers))))
    for name, value in response.headers.items():
        rows.append(("Header: " + name, short(value, 300)))
    jar = session.cookies
    for cookie in jar:
        result["cookies"].append({
            "name": cookie.name,
            "value": cookie.value or "",
            "domain": cookie.domain or "",
            "secure": bool(cookie.secure),
        })
    rows.append(("Cookie count", str(len(result["cookies"]))))
    for cookie in result["cookies"]:
        detail = short(cookie["value"], 120)
        if cookie["domain"]:
            detail = detail + " (domain " + cookie["domain"] + ")"
        if cookie["secure"]:
            detail = detail + " [Secure]"
        if not detail:
            detail = "(empty)"
        rows.append(("Cookie: " + cookie["name"], detail))
    try:
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_cookies = []
    rows.extend(cookie_flag_rows(raw_cookies))
    rows.extend(security_summary(response.headers))
    rows.append(("Clock skew", clock_skew(response.headers.get("Date", ""))))
    validators = []
    if response.headers.get("ETag", ""):
        validators.append("ETag")
    if response.headers.get("Last-Modified", ""):
        validators.append("Last-Modified")
    if validators:
        rows.append(("Cache validators", ", ".join(validators)))
    else:
        rows.append(("Cache validators", "None (no ETag or Last-Modified)"))
    html = response.text or ""
    if len(html) > MAX_HTML:
        rows.append(("HTML note", "Body truncated for analysis at " + str(MAX_HTML) + " characters"))
        html = html[:MAX_HTML]
    result["html"] = html
    return result


def http_version(response):
    try:
        code = response.raw.version
    except Exception:
        return ""
    mapping = {9: "HTTP/0.9", 10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}
    return mapping.get(code, "HTTP/" + str(code))


def parse_set_cookie(header):
    info = {"name": "", "secure": False, "httponly": False, "samesite": "", "domain": "", "path": "", "persistent": False, "partitioned": False}
    parts = (header or "").split(";")
    if parts:
        info["name"] = parts[0].split("=", 1)[0].strip()
    for part in parts[1:]:
        attr = part.strip()
        low = attr.lower()
        if low == "secure":
            info["secure"] = True
        elif low == "httponly":
            info["httponly"] = True
        elif low.startswith("samesite"):
            if "=" in attr:
                info["samesite"] = attr.split("=", 1)[1].strip()
            else:
                info["samesite"] = "set"
        elif low.startswith("domain="):
            info["domain"] = attr.split("=", 1)[1].strip()
        elif low.startswith("path="):
            info["path"] = attr.split("=", 1)[1].strip()
        elif low.startswith("expires=") or low.startswith("max-age="):
            info["persistent"] = True
        elif low == "partitioned":
            info["partitioned"] = True
    return info


def clock_skew(date_str, now=None):
    import email.utils
    if not date_str:
        return "No Date header"
    try:
        moment = email.utils.parsedate_to_datetime(date_str)
    except Exception:
        return "Unparseable Date header"
    if moment.tzinfo:
        moment = moment.replace(tzinfo=None)
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    delta = int((moment - now).total_seconds())
    if abs(delta) > 3600:
        return "Over 1h off (" + str(delta) + "s, review)"
    if delta >= 0:
        return "Server ahead by " + str(delta) + "s"
    return "Server behind by " + str(abs(delta)) + "s"


def cookie_flag_rows(raw_cookies):
    rows = []
    if not raw_cookies:
        return rows
    insecure = 0
    script_readable = 0
    for header in raw_cookies:
        info = parse_set_cookie(header)
        flags = []
        if info["secure"]:
            flags.append("Secure")
        else:
            flags.append("no Secure")
            insecure += 1
        if info["httponly"]:
            flags.append("HttpOnly")
        else:
            flags.append("no HttpOnly")
            script_readable += 1
        if info["samesite"]:
            flags.append("SameSite=" + info["samesite"])
        else:
            flags.append("no SameSite")
        name = info["name"] or "cookie"
        rows.append(("Cookie flags: " + name, ", ".join(flags)))
    rows.append(("Cookies missing Secure", str(insecure)))
    rows.append(("Cookies missing HttpOnly", str(script_readable)))
    partitioned = sum(1 for header in raw_cookies if parse_set_cookie(header)["partitioned"])
    if partitioned:
        rows.append(("Partitioned cookies", str(partitioned) + " use CHIPS isolation"))
    rows.extend(cookie_prefix_rows(raw_cookies))
    return rows


def cookie_prefix_rows(raw_cookies):
    rows = []
    for header in raw_cookies or []:
        info = parse_set_cookie(header)
        name = info["name"] or ""
        if name.startswith("__Secure-") and not info["secure"]:
            rows.append(("Cookie prefix: " + name, "Rejected by browsers (needs Secure)"))
        if name.startswith("__Host-"):
            problems = []
            if not info["secure"]:
                problems.append("needs Secure")
            if info["path"] != "/":
                problems.append("needs Path=/")
            if info["domain"]:
                problems.append("must not set Domain")
            if problems:
                rows.append(("Cookie prefix: " + name, "Rejected by browsers (" + ", ".join(problems) + ")"))
            else:
                rows.append(("Cookie prefix: " + name, "Valid __Host- cookie"))
        if info["samesite"].lower() == "none" and not info["secure"]:
            rows.append(("Cookie flags: " + name, "SameSite=None without Secure is rejected"))
    return rows


def parse_csp(value):
    rows = []
    directives = {}
    for chunk in str(value or "").split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        bits = chunk.split()
        directives[bits[0].lower()] = bits[1:]
    rows.append(("CSP directives", str(len(directives))))
    weak = []
    for directive in ("script-src", "default-src"):
        sources = directives.get(directive, [])
        if "'unsafe-inline'" in sources:
            weak.append(directive + " allows unsafe-inline")
        if "'unsafe-eval'" in sources:
            weak.append(directive + " allows unsafe-eval")
        if "*" in sources:
            weak.append(directive + " contains wildcard")
        if "data:" in sources:
            weak.append(directive + " allows data:")
        if "http:" in sources:
            weak.append(directive + " allows plain http")
    if weak:
        rows.append(("CSP weaknesses", "; ".join(weak[:4])))
    else:
        rows.append(("CSP weaknesses", "None spotted"))
    for directive in ("default-src", "script-src", "object-src", "base-uri", "form-action", "frame-ancestors"):
        if directive in directives:
            rows.append(("CSP " + directive, short(" ".join(directives[directive][:8]), 200)))
    if "object-src" not in directives:
        rows.append(("CSP object-src", "Not set (plugins unrestricted)"))
    if "report-uri" in directives or "report-to" in directives:
        rows.append(("CSP reporting", "Configured"))
    else:
        rows.append(("CSP reporting", "Not configured"))
    if "upgrade-insecure-requests" in directives:
        rows.append(("CSP upgrade", "upgrade-insecure-requests set"))
    return rows


def parse_permissions_policy(value):
    rows = []
    if not value:
        return rows
    features = [chunk.strip() for chunk in str(value).split(",") if chunk.strip()]
    rows.append(("Permissions features", str(len(features))))
    disabled = []
    for chunk in features:
        if "=" in chunk:
            name, setting = chunk.split("=", 1)
            if setting.strip() in ("()", "none"):
                disabled.append(name.strip())
    if disabled:
        rows.append(("Permissions disabled", ", ".join(disabled[:10])))
    return rows


def parse_link_header(value):
    rows = []
    if not value:
        return rows
    parts = [chunk.strip() for chunk in str(value).split(",") if chunk.strip()]
    rows.append(("Link headers", str(len(parts))))
    for rel in ("preload", "preconnect", "dns-prefetch", "modulepreload"):
        items = [chunk.split(";")[0].strip("<> ") for chunk in parts if 'rel=' in chunk and rel in chunk.lower()]
        if items:
            rows.append(("Link " + rel, str(len(items)) + " (" + short(", ".join(items[:3]), 180) + ")"))
    return rows


def parse_server_timing(value):
    rows = []
    if not value:
        return rows
    metrics = []
    for chunk in str(value).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        name = chunk.split(";")[0].strip()
        duration = ""
        for piece in chunk.split(";")[1:]:
            piece = piece.strip()
            if piece.lower().startswith("dur="):
                duration = piece.split("=", 1)[1].strip()
        if duration:
            metrics.append(name + "=" + duration + "ms")
        else:
            metrics.append(name)
    rows.append(("Server-Timing", short("; ".join(metrics[:8]), 220)))
    return rows


def x_header_inventory(headers):
    rows = []
    names = []
    for name in headers:
        low = str(name).lower()
        if low.startswith("x-") and low not in ("x-content-type-options", "x-frame-options"):
            names.append(str(name))
    if names:
        rows.append(("Custom X- headers", str(len(names)) + ": " + short(", ".join(sorted(names)[:15]), 220)))
    return rows


def hsts_rows(value):
    rows = []
    low = str(value or "").lower()
    match = re.search(r"max-age\s*=\s*(\d+)", low)
    age = 0
    if match:
        age = int(match.group(1))
        rows.append(("HSTS max-age", str(age) + " seconds (~" + str(age // 86400) + " days)"))
        if age < 86400:
            rows.append(("HSTS duration", "Under 1 day (weak)"))
    else:
        rows.append(("HSTS max-age", "Missing (header is invalid)"))
    if "includesubdomains" in low:
        rows.append(("HSTS subdomains", "Covered"))
    else:
        rows.append(("HSTS subdomains", "Not covered"))
    if age >= 31536000 and "includesubdomains" in low and "preload" in low:
        rows.append(("HSTS readiness", "Meets preload requirements"))
    return rows


def security_summary(headers):
    rows = []
    present = 0
    for header, label in SECURITY_HEADERS:
        value = headers.get(header, "")
        if value:
            present += 1
            rows.append(("Security: " + label, "Present: " + short(value, 220)))
        else:
            rows.append(("Security: " + label, "Missing"))
    rows.append(("Security headers score", str(present) + " of " + str(len(SECURITY_HEADERS)) + " present"))
    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        if "preload" in hsts.lower():
            rows.append(("HSTS preload", "Enabled"))
        else:
            rows.append(("HSTS preload", "Not enabled"))
        rows.extend(hsts_rows(hsts))
    csp = headers.get("Content-Security-Policy", "")
    if csp:
        rows.extend(parse_csp(csp))
    report_only = headers.get("Content-Security-Policy-Report-Only", "")
    if report_only:
        rows.append(("CSP report-only", "Present (" + str(len(report_only.split(";"))) + " directives, not enforced)"))
    rows.extend(parse_permissions_policy(headers.get("Permissions-Policy", "")))
    rows.extend(parse_link_header(headers.get("Link", "")))
    rows.extend(parse_server_timing(headers.get("Server-Timing", "")))
    rows.extend(x_header_inventory(headers))
    server = headers.get("Server", "")
    if server:
        if re.search(r"\d", server):
            rows.append(("Server version exposed", "Yes (" + short(server, 120) + ")"))
        else:
            rows.append(("Server version exposed", "No (" + short(server, 120) + ")"))
    powered = headers.get("X-Powered-By", "")
    if powered:
        rows.append(("Powered-By exposed", short(powered, 120)))
    else:
        rows.append(("Powered-By exposed", "No"))
    for extra in ("X-AspNet-Version", "X-Generator", "X-Drupal-Cache", "X-Varnish"):
        if headers.get(extra, ""):
            rows.append((extra + " exposed", short(headers.get(extra, ""), 120)))
    etag = headers.get("ETag", "")
    if etag:
        if etag.startswith("W/"):
            rows.append(("ETag strength", "Weak validator"))
        else:
            rows.append(("ETag strength", "Strong validator"))
    cache = headers.get("Cache-Control", "")
    if cache:
        rows.append(("Caching", short(cache, 200)))
    else:
        rows.append(("Caching", "No Cache-Control header"))
    cors = headers.get("Access-Control-Allow-Origin", "")
    if cors:
        rows.append(("CORS", "Allows " + short(cors, 120)))
    else:
        rows.append(("CORS", "No Access-Control-Allow-Origin header"))
    endpoints = headers.get("Reporting-Endpoints", "")
    if endpoints:
        rows.append(("Reporting endpoints", short(endpoints, 220)))
    nel = headers.get("NEL", "")
    if nel:
        rows.append(("Network Error Logging", short(nel, 220)))
    document = headers.get("Document-Policy", "")
    if document:
        rows.append(("Document policy", short(document, 220)))
    cluster = headers.get("Origin-Agent-Cluster", "")
    if cluster:
        rows.append(("Origin agent cluster", short(cluster, 120)))
    encoding = headers.get("Content-Encoding", "")
    if encoding:
        rows.append(("Compression", encoding))
    else:
        rows.append(("Compression", "None (identity)"))
    return rows


def collect_tls(host, port=443, deep=True):
    rows = []
    try:
        trusted, trust_error = verify_handshake(host, port)
    except Exception as exc:
        rows.append(("TLS status", "No TLS on port " + str(port) + " (" + exc.__class__.__name__ + ")"))
        return {"rows": rows}
    rows.append(("TLS reachable", "Yes, port " + str(port) + " open"))
    try:
        cert, der, cipher, version, alpn = fetch_cert(host, port)
    except Exception as exc:
        rows.append(("Certificate status", "Could not retrieve certificate (" + exc.__class__.__name__ + ")"))
        return {"rows": rows}
    if version:
        rows.append(("TLS version", version))
    if cipher:
        rows.append(("Cipher suite", str(cipher[0])))
        rows.append(("Cipher protocol", str(cipher[1])))
        rows.append(("Cipher bits", str(cipher[2])))
    if alpn:
        rows.append(("ALPN protocol", alpn))
    else:
        rows.append(("ALPN protocol", "None negotiated"))
    if alpn == "h2":
        rows.append(("HTTP/2", "Supported (h2 negotiated)"))
    else:
        rows.append(("HTTP/2", "Not negotiated"))
    rows.extend(version_probe_rows(host, port))
    if trusted:
        rows.append(("Chain trusted", "Yes (system certificate store)"))
    else:
        rows.append(("Chain trusted", "No: " + short(trust_error, 200)))
    rows.extend(parse_cert(cert, der, host))
    # Deep-only probes: each of these shells out to openssl or opens extra
    # sockets, so they are skipped on the Quick profile to keep it fast.
    if deep:
        rows.extend(openssl_chain(host, port))
        rows.extend(openssl_cert_text(host, port))
        rows.extend(ocsp_stapling(host, port))
        rows.extend(session_reuse(host, port))
        rows.extend(weak_cipher_probe(host, port))
        rows.extend(accepted_cipher_rows(host, port))
    else:
        rows.append(("TLS deep checks", "Skipped (Quick profile: chain text, OCSP, ciphers, session reuse)"))
    return {"rows": rows}


CIPHER_PROBES = [
    ("AES-128-GCM", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:AES128-GCM-SHA256"),
    ("AES-256-GCM", "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:AES256-GCM-SHA384"),
    ("ChaCha20", "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305"),
    ("AES-CBC", "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:AES128-SHA"),
    ("3DES", "DES-CBC3-SHA"),
    ("RC4", "RC4-SHA:RC4-MD5"),
    ("No forward secrecy", "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"),
]


def accepted_cipher_rows(host, port=443, timeout=6):
    rows = []
    accepted = []
    for label, ciphers in CIPHER_PROBES:
        name = try_cipher_group(host, port, ciphers, timeout)
        if name:
            accepted.append((label, name))
    if not accepted:
        rows.append(("Cipher groups", "No probe handshake succeeded"))
        return rows
    rows.append(("Cipher groups accepted", str(len(accepted)) + " of " + str(len(CIPHER_PROBES))))
    for label, name in accepted:
        detail = name
        if label in ("3DES", "RC4"):
            detail = detail + " (weak, disable)"
        elif label == "AES-CBC":
            detail = detail + " (legacy, prefer GCM)"
        elif label == "No forward secrecy":
            detail = detail + " (no PFS, deprefer)"
        rows.append(("Accepts " + label, detail))
    weak = [label for label, _ in accepted if label in ("3DES", "RC4")]
    if weak:
        rows.append(("Cipher verdict", "Weak groups accepted: " + ", ".join(weak)))
    else:
        rows.append(("Cipher verdict", "Only strong groups accepted"))
    return rows


def try_cipher_group(host, port, ciphers, timeout):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers(ciphers)
    except Exception:
        return ""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return ""
    try:
        sock = context.wrap_socket(raw, server_hostname=host)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return ""
    try:
        cipher = sock.cipher()
        name = cipher[0] if cipher else ""
        sock.close()
    except Exception:
        return ""
    return name or ""


def probe_tls_version(host, port, minimum, maximum):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = minimum
        context.maximum_version = maximum
    raw = socket.create_connection((host, port), timeout=6)
    try:
        sock = context.wrap_socket(raw, server_hostname=host)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return False, ""
    try:
        version = sock.version() or ""
        sock.close()
    except Exception:
        return False, ""
    return True, version


def version_probe_rows(host, port):
    rows = []
    try:
        legacy_ok, legacy_version = probe_tls_version(host, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
    except Exception:
        legacy_ok, legacy_version = False, ""
    if legacy_ok:
        rows.append(("Legacy TLS", "TLS 1.0/1.1 accepted (" + legacy_version + ", weak)"))
    else:
        rows.append(("Legacy TLS", "TLS 1.0/1.1 not accepted"))
    try:
        modern_ok, modern_version = probe_tls_version(host, port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    except Exception:
        modern_ok, modern_version = False, ""
    if modern_ok:
        rows.append(("TLS 1.3", "Supported (" + modern_version + ")"))
    else:
        rows.append(("TLS 1.3", "Not supported"))
    return rows


def openssl_chain(host, port=443, timeout=10):
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return []
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", host, "-showcerts"],
            input="", capture_output=True, text=True, timeout=timeout)
    except Exception:
        return [("TLS chain (openssl)", "Probe failed")]
    return parse_openssl_chain(proc.stdout or "")


def parse_openssl_chain(text):
    rows = []
    count = text.count("BEGIN CERTIFICATE")
    if not count:
        return [("TLS chain (openssl)", "No certificates captured")]
    rows.append(("Chain depth", str(count) + " certificates"))
    subjects = re.findall(r"^\s*(?:\d+\s+)?s:(.+)$", text, re.MULTILINE)
    for index, subject in enumerate(subjects[:5], 1):
        rows.append(("Chain subject " + str(index), short(subject.strip(), 160)))
    match = re.search(r"Verify return code: (\d+) \((.+?)\)", text)
    if match:
        rows.append(("Chain verify", match.group(1) + " (" + match.group(2) + ")"))
    return rows


def weak_cipher_probe(host, port=443, timeout=10):
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return []
    rows = []
    for label, cipher in (("Weak ciphers", "LOW:EXP:eNULL:@STRENGTH"), ("3DES offered", "3DES"), ("RC4 offered", "RC4")):
        try:
            proc = subprocess.run(
                ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", host, "-cipher", cipher],
                input="", capture_output=True, text=True, timeout=timeout)
        except Exception:
            rows.append((label, "Probe failed"))
            continue
        rows.append((label, parse_weak_cipher_output((proc.stdout or "") + (proc.stderr or ""))))
    return rows


def openssl_cert_text(host, port=443, timeout=10):
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return []
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", host, "-showcerts"],
            input="", capture_output=True, text=True, timeout=timeout)
    except Exception:
        return [("Certificate details", "Probe failed")]
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", proc.stdout or "", re.DOTALL)
    if not match:
        return [("Certificate details", "No certificate captured")]
    try:
        proc2 = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=match.group(0), capture_output=True, text=True, timeout=timeout)
    except Exception:
        return [("Certificate details", "Parse failed")]
    return parse_openssl_text(proc2.stdout or "")


def parse_openssl_text(text):
    rows = []
    match = re.search(r"Signature Algorithm:\s*(\S+)", text)
    if match:
        algo = match.group(1)
        rows.append(("Signature algorithm", algo))
        if "md5" in algo.lower() or "sha1" in algo.lower().replace("-", ""):
            rows.append(("Signature verdict", "Weak hash (review)"))
    match = re.search(r"Public-Key:\s*\((\d+) bit", text)
    if match:
        bits = int(match.group(1))
        rows.append(("Public key size", str(bits) + " bits"))
        if bits < 2048:
            rows.append(("Key size verdict", "Under 2048 bits (weak)"))
    match = re.search(r"ASN1 OID:\s*(\S+)", text)
    if match:
        rows.append(("EC curve", match.group(1)))
    usages = re.search(r"X509v3 Key Usage:[^\n]*\n\s*(.+)", text)
    if usages:
        rows.append(("Key usage", short(usages.group(1).strip(), 160)))
    ext_usages = re.search(r"X509v3 Extended Key Usage:[^\n]*\n\s*(.+)", text)
    if ext_usages:
        detail = ext_usages.group(1).strip()
        rows.append(("Extended key usage", short(detail, 160)))
        if "TLS Web Server Authentication" not in detail and "serverAuth" not in detail:
            rows.append(("Server auth usage", "Missing (review)"))
    if "CT Precertificate SCTs" in text:
        count = len(re.findall(r"Signed Certificate Timestamp:", text))
        rows.append(("Embedded SCTs", str(count)))
        if count >= 2:
            rows.append(("SCT verdict", "Meets transparency requirements"))
        else:
            rows.append(("SCT verdict", "Only 1 embedded (relies on OCSP/TLS delivery too)"))
    else:
        rows.append(("Embedded SCTs", "None (transparency via OCSP or other)"))
    if "1.3.6.1.5.5.7.1.24" in text or "OCSP Requirement" in text or "status_request" in text:
        rows.append(("OCSP Must-Staple", "Present"))
    else:
        rows.append(("OCSP Must-Staple", "Not set"))
    return rows


def ocsp_stapling(host, port=443, timeout=10):
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return []
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", host, "-status"],
            input="", capture_output=True, text=True, timeout=timeout)
    except Exception:
        return [("OCSP stapling", "Probe failed")]
    output = (proc.stdout or "") + (proc.stderr or "")
    if "OCSP Response Status successful" in output or "OCSP response:" in output and "successful" in output:
        rows = [("OCSP stapling", "Enabled (response stapled)")]
        match = re.search(r"Cert Status:\s*(\S+)", output)
        if match:
            rows.append(("OCSP cert status", match.group(1)))
        match = re.search(r"Next Update:\s*(.+)", output)
        if match:
            rows.append(("OCSP next update", short(match.group(1).strip(), 120)))
        return rows
    if "OCSP response: no response sent" in output:
        return [("OCSP stapling", "Not enabled")]
    return [("OCSP stapling", "No stapled response")]


def session_reuse(host, port=443, timeout=12):
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        return []
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", host, "-reconnect", "-no_shutdown"],
            input="", capture_output=True, text=True, timeout=timeout)
    except Exception:
        return [("Session resumption", "Probe failed")]
    output = (proc.stdout or "") + (proc.stderr or "")
    reused = len(re.findall(r"Reused, [A-Z]", output))
    fresh = len(re.findall(r"New, [A-Z]", output))
    if reused + fresh == 0:
        return [("Session resumption", "Unknown (parse failed)")]
    rows = [("Session resumption", str(reused) + " reused of " + str(reused + fresh) + " handshakes")]
    if reused:
        rows.append(("Session verdict", "Resumption works (faster reconnects)"))
    else:
        rows.append(("Session verdict", "No resumption (every visit is a full handshake)"))
    return rows


def parse_weak_cipher_output(output):
    low = output.lower()
    if "cipher is (none)" in low or "handshake failure" in low or "no cipher" in low or "no protocols available" in low:
        return "Rejected (good)"
    match = re.search(r"Cipher\s*:\s*(\S+)", output)
    if match and match.group(1) not in ("(NONE)", "0000", "None", "New,"):
        return "ACCEPTED: " + match.group(1) + " (weak)"
    return "Rejected (good)"


def verify_handshake(host, port):
    context = ssl.create_default_context()
    raw = socket.create_connection((host, port), timeout=8)
    try:
        sock = context.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        try:
            raw.close()
        except Exception:
            pass
        return False, str(exc)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        raise
    try:
        sock.close()
    except Exception:
        pass
    return True, ""


def fetch_cert(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    raw = socket.create_connection((host, port), timeout=8)
    sock = context.wrap_socket(raw, server_hostname=host)
    try:
        cert = sock.getpeercert()
        der = sock.getpeercert(binary_form=True)
        cipher = sock.cipher()
        version = sock.version()
        try:
            alpn = sock.selected_alpn_protocol()
        except Exception:
            alpn = ""
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return cert, der, cipher, version, alpn or ""


def cert_names(entry):
    parts = {}
    for item in entry or []:
        for key, value in item:
            parts[key] = value
    return parts


def parse_cert_date(text):
    normalized = " ".join(str(text).split())
    return datetime.datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")


def format_fingerprint(raw):
    pairs = [raw[i:i + 2].upper() for i in range(0, len(raw), 2)]
    return ":".join(pairs)


def host_covered(host, sans, common_name):
    names = []
    for kind, value in sans or []:
        if kind == "DNS":
            names.append(value)
    if common_name:
        names.append(common_name)
    host = host.lower()
    for pattern in names:
        candidate = pattern.lower()
        if candidate == host:
            return True, pattern
        if candidate.startswith("*.") and host.endswith(candidate[1:]):
            if host.count(".") == candidate.count("."):
                return True, pattern
    return False, ""


def parse_cert(cert, der, host):
    rows = []
    subject = cert_names(cert.get("subject", []))
    issuer = cert_names(cert.get("issuer", []))
    subject_fields = [
        ("commonName", "Subject CN"),
        ("organizationName", "Subject organization"),
        ("organizationalUnitName", "Subject unit"),
        ("localityName", "Subject city"),
        ("stateOrProvinceName", "Subject state"),
        ("countryName", "Subject country"),
        ("emailAddress", "Subject email"),
    ]
    for key, label in subject_fields:
        if subject.get(key):
            rows.append((label, short(subject[key], 160)))
    issuer_fields = [
        ("commonName", "Issuer CN"),
        ("organizationName", "Issuer organization"),
        ("organizationalUnitName", "Issuer unit"),
        ("countryName", "Issuer country"),
    ]
    for key, label in issuer_fields:
        if issuer.get(key):
            rows.append((label, short(issuer[key], 160)))
    if cert.get("serialNumber"):
        rows.append(("Serial number", str(cert.get("serialNumber"))))
    if cert.get("version"):
        rows.append(("Certificate version", str(cert.get("version"))))
    try:
        start = parse_cert_date(cert.get("notBefore", ""))
        end = parse_cert_date(cert.get("notAfter", ""))
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        rows.append(("Valid from", start.strftime("%Y-%m-%d %H:%M:%S UTC")))
        rows.append(("Valid until", end.strftime("%Y-%m-%d %H:%M:%S UTC")))
        rows.append(("Validity period", str((end - start).days) + " days"))
        if (end - start).days > 398:
            rows.append(("Lifetime compliance", "Over 398 days (browsers distrust)"))
        else:
            rows.append(("Lifetime compliance", "Within 398-day limit"))
        remaining = (end - now).days
        if remaining < 0:
            rows.append(("Certificate state", "Expired " + str(abs(remaining)) + " days ago"))
        else:
            rows.append(("Certificate state", "Valid, " + str(remaining) + " days remaining"))
    except Exception:
        rows.append(("Valid from", str(cert.get("notBefore", ""))))
        rows.append(("Valid until", str(cert.get("notAfter", ""))))
    if cert.get("subject") and cert.get("subject") == cert.get("issuer"):
        rows.append(("Self-signed", "Yes (subject matches issuer, browsers distrust)"))
    else:
        rows.append(("Self-signed", "No"))
    sans = cert.get("subjectAltName", []) or []
    dns_names = [value for kind, value in sans if kind == "DNS"]
    rows.append(("SAN count", str(len(dns_names))))
    if not dns_names:
        rows.append(("SAN verdict", "No DNS SANs (CN fallback is deprecated)"))
    else:
        wildcards = [name for name in dns_names if name.startswith("*.")]
        if wildcards:
            rows.append(("Wildcard SANs", str(len(wildcards)) + ": " + short(", ".join(wildcards[:5]), 160)))
    for index, value in enumerate(dns_names[:20], 1):
        rows.append(("SAN " + str(index), value))
    if len(dns_names) > 20:
        rows.append(("SAN note", "Showing first 20 of " + str(len(dns_names))))
    covered, pattern = host_covered(host, sans, subject.get("commonName", ""))
    if covered:
        rows.append(("Hostname match", "Yes (" + host + " covered by " + pattern + ")"))
    else:
        rows.append(("Hostname match", "No (" + host + " not listed)"))
    for url in cert.get("OCSP", []) or []:
        rows.append(("OCSP responder", short(url, 200)))
    for url in cert.get("caIssuers", []) or []:
        rows.append(("CA issuer URL", short(url, 200)))
    for url in cert.get("crlDistributionPoints", []) or []:
        rows.append(("CRL distribution", short(url, 200)))
    if der:
        sha256 = format_fingerprint(hashlib.sha256(der).hexdigest())
        sha1 = format_fingerprint(hashlib.sha1(der).hexdigest())
        rows.append(("Fingerprint SHA-256", sha256))
        rows.append(("Fingerprint SHA-1", sha1))
    return rows
