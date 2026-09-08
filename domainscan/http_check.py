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
    html = response.text or ""
    if len(html) > MAX_HTML:
        rows.append(("HTML note", "Body truncated for analysis at " + str(MAX_HTML) + " characters"))
        html = html[:MAX_HTML]
    result["html"] = html
    return result


def parse_set_cookie(header):
    info = {"name": "", "secure": False, "httponly": False, "samesite": ""}
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
    return info


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
    csp = headers.get("Content-Security-Policy", "")
    if csp:
        weak = []
        if "unsafe-inline" in csp:
            weak.append("allows unsafe-inline")
        if "unsafe-eval" in csp:
            weak.append("allows unsafe-eval")
        if "*" in csp:
            weak.append("contains wildcard")
        if weak:
            rows.append(("CSP notes", ", ".join(weak)))
        else:
            rows.append(("CSP notes", "No obvious weak directives"))
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
    encoding = headers.get("Content-Encoding", "")
    if encoding:
        rows.append(("Compression", encoding))
    else:
        rows.append(("Compression", "None (identity)"))
    return rows


def collect_tls(host, port=443):
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
    rows.extend(openssl_chain(host, port))
    rows.extend(weak_cipher_probe(host, port))
    return {"rows": rows}


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
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", host, "-cipher", "LOW:EXP:eNULL:@STRENGTH"],
            input="", capture_output=True, text=True, timeout=timeout)
    except Exception:
        return [("Weak ciphers", "Probe failed")]
    return [("Weak ciphers", parse_weak_cipher_output((proc.stdout or "") + (proc.stderr or "")))]


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
        remaining = (end - now).days
        if remaining < 0:
            rows.append(("Certificate state", "Expired " + str(abs(remaining)) + " days ago"))
        else:
            rows.append(("Certificate state", "Valid, " + str(remaining) + " days remaining"))
    except Exception:
        rows.append(("Valid from", str(cert.get("notBefore", ""))))
        rows.append(("Valid until", str(cert.get("notAfter", ""))))
    sans = cert.get("subjectAltName", []) or []
    dns_names = [value for kind, value in sans if kind == "DNS"]
    rows.append(("SAN count", str(len(dns_names))))
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
