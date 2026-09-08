import socket
import time
from concurrent.futures import ThreadPoolExecutor

from domainscan.helpers import BROWSER_UA, short


PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (465, "SMTPS"), (587, "Submission"),
    (636, "LDAPS"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (3000, "Node"),
    (3306, "MySQL"), (3389, "RDP"), (5000, "Flask"),
    (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"),
    (8000, "Django"), (8008, "HTTP-Alt"), (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"), (8888, "HTTP-Alt"), (9000, "App"),
    (9200, "Elasticsearch"), (11211, "Memcached"), (27017, "MongoDB"),
]

RISK = {
    23: "critical (cleartext admin)",
    1433: "critical (database)",
    1521: "critical (database)",
    3306: "critical (database)",
    5432: "critical (database)",
    6379: "critical (database)",
    9200: "critical (database)",
    11211: "critical (cache, abused for DDoS)",
    27017: "critical (database)",
    5900: "high (remote desktop)",
    3389: "high (remote desktop)",
    21: "high (cleartext auth)",
    110: "medium (cleartext mail)",
    143: "medium (cleartext mail)",
    25: "medium (mail relay target)",
}

BANNER_PORTS = (21, 22, 25, 110, 143, 3306)

TLS_PORTS = (443, 465, 636, 993, 995, 8443)

WEB_PROBE_PORTS = {
    80: "http", 443: "https", 3000: "http", 5000: "http",
    8000: "http", 8008: "http", 8080: "http", 8443: "https",
    8888: "http", 9000: "http",
}

TIMEOUT = 2.0


def classify_error(exc):
    import errno
    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "filtered"
    code = getattr(exc, "errno", 0)
    if code in (errno.ECONNREFUSED,):
        return "closed"
    if code in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
        return "filtered"
    return "filtered"


def probe(host, port):
    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
    except Exception as exc:
        return {"port": port, "open": False, "ms": 0, "banner": "", "state": classify_error(exc)}
    elapsed = int((time.perf_counter() - started) * 1000)
    banner = ""
    if port in BANNER_PORTS:
        try:
            sock.settimeout(2.0)
            data = sock.recv(512).decode("utf-8", "ignore").strip()
            if data:
                banner = data.splitlines()[0]
        except Exception:
            banner = ""
    try:
        sock.close()
    except Exception:
        pass
    return {"port": port, "open": True, "ms": elapsed, "banner": banner, "state": "open"}


def probe_web_port(host, port, timeout=5):
    import requests
    scheme = WEB_PROBE_PORTS.get(port, "http")
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = scheme + "://" + host + "/"
    else:
        url = scheme + "://" + host + ":" + str(port) + "/"
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": BROWSER_UA})
    except Exception:
        return "No HTTP response"
    title = ""
    try:
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", response.text or "", re.IGNORECASE | re.DOTALL)
        if match:
            title = short(re.sub(r"\s+", " ", match.group(1).strip()), 80)
    except Exception:
        title = ""
    detail = "HTTP " + str(response.status_code)
    server = response.headers.get("Server", "")
    if server:
        detail = detail + ", " + short(server, 60)
    if title:
        detail = detail + ", " + title
    return detail


def collect(host, enabled=True):
    rows = []
    if not enabled:
        rows.append(("Port scan", "Skipped (disabled in options)"))
        return {"rows": rows}
    rows.append(("Port scan", "TCP connect on " + str(len(PORTS)) + " common ports"))
    numbers = [port for port, name in PORTS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda port: probe(host, port), numbers))
    names = {port: name for port, name in PORTS}
    opened = [item for item in results if item["open"]]
    rows.append(("Open ports", str(len(opened)) + " of " + str(len(PORTS))))
    risky = [(item["port"], RISK[item["port"]]) for item in opened if item["port"] in RISK]
    if risky:
        rows.append(("Risky open ports", str(len(risky))))
        for port, reason in sorted(risky):
            rows.append(("Risk: port " + str(port), "Open, " + reason))
    for result in sorted(results, key=lambda item: item["port"]):
        label = "Port " + str(result["port"]) + " (" + names[result["port"]] + ")"
        if result["open"]:
            rows.append((label, "Open (" + str(result["ms"]) + " ms)"))
            if result["banner"]:
                rows.append((label + " banner", short(result["banner"], 160)))
                rows.extend(banner_verdict(result["port"], result["banner"]))
        elif result.get("state") == "closed":
            rows.append((label, "Closed (connection refused)"))
        else:
            rows.append((label, "Filtered (no response)"))
    web_ports = [item["port"] for item in opened if item["port"] in WEB_PROBE_PORTS]
    for port in sorted(web_ports):
        rows.append(("Port " + str(port) + " web", probe_web_port(host, port)))
    tls_ports = [item["port"] for item in opened if item["port"] in TLS_PORTS]
    for port in sorted(tls_ports):
        rows.append(("Port " + str(port) + " TLS", tls_detect(host, port)))
    if any(item["port"] == 21 for item in opened):
        rows.append(("FTP anonymous", ftp_anonymous(host)))
    rows.append(("UDP port 53", udp_dns_probe(host)))
    return {"rows": rows}


def banner_verdict(port, banner):
    import re
    rows = []
    if port == 22:
        match = re.search(r"OpenSSH_(\S+)", banner)
        if match:
            rows.append(("SSH version", match.group(1)))
            major = match.group(1).split(".")[0]
            if major.isdigit() and int(major) < 8:
                rows.append(("SSH verdict", "OpenSSH 7.x or older (review for patches)"))
    if port == 21 and "vsftpd" in banner.lower():
        match = re.search(r"vsftpd (\S+)", banner, re.IGNORECASE)
        if match:
            rows.append(("FTP version", "vsftpd " + match.group(1)))
    if port == 3306 and "mysql" in banner.lower():
        match = re.search(r"(\d+\.\d+\.\d+)", banner)
        if match:
            rows.append(("MySQL version", match.group(1)))
    return rows


def tls_detect(host, port, timeout=5):
    import ssl
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return "Connection failed"
    try:
        sock = context.wrap_socket(raw, server_hostname=host)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return "Plaintext (no TLS handshake)"
    try:
        cert = sock.getpeercert() or {}
        version = sock.version() or ""
    finally:
        try:
            sock.close()
        except Exception:
            pass
    common = ""
    for entry in cert.get("subject", []) or []:
        for key, value in entry:
            if key == "commonName":
                common = value
    if common:
        return "TLS service (" + version + ", CN " + short(common, 60) + ")"
    return "TLS service (" + version + ")"


def ftp_anonymous(host, timeout=6):
    try:
        sock = socket.create_connection((host, 21), timeout=timeout)
    except Exception:
        return "Probe failed"
    try:
        sock.settimeout(timeout)
        banner = sock.recv(256).decode("utf-8", "ignore")
        if not banner.startswith("220"):
            return "Unexpected greeting"
        sock.sendall(b"USER anonymous\r\n")
        reply = sock.recv(256).decode("utf-8", "ignore")
        if reply.startswith("230"):
            return "ALLOWED without password (review)"
        if not reply.startswith("331"):
            return "Anonymous rejected (" + short(reply.splitlines()[0], 80) + ")"
        sock.sendall(b"PASS domainscan@example.com\r\n")
        reply = sock.recv(256).decode("utf-8", "ignore")
        if reply.startswith("230"):
            return "ALLOWED with any password (review)"
        return "Anonymous rejected"
    except Exception:
        return "Probe failed"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def udp_dns_probe(host, timeout=3):
    import random
    ident = random.randint(1, 65535)
    packet = ident.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (host, 53))
        data, _ = sock.recvfrom(512)
    except socket.timeout:
        return "Filtered (no UDP response)"
    except ConnectionRefusedError:
        return "Closed (port unreachable)"
    except Exception as exc:
        return "Probe failed (" + exc.__class__.__name__ + ")"
    finally:
        try:
            sock.close()
        except Exception:
            pass
    if len(data) >= 2 and data[:2] == ident.to_bytes(2, "big"):
        return "Open (UDP DNS answers)"
    return "Filtered (unexpected UDP reply)"
