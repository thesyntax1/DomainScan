import socket
import time
from concurrent.futures import ThreadPoolExecutor

from domainscan.helpers import BROWSER_UA, short


PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (465, "SMTPS"), (587, "Submission"),
    (993, "IMAPS"), (995, "POP3S"), (3000, "Node"), (3306, "MySQL"),
    (5000, "Flask"), (8000, "Django"), (8008, "HTTP-Alt"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (8888, "HTTP-Alt"),
    (9000, "App"),
]

BANNER_PORTS = (21, 22, 25, 110, 143)

WEB_PROBE_PORTS = {
    80: "http", 443: "https", 3000: "http", 5000: "http",
    8000: "http", 8008: "http", 8080: "http", 8443: "https",
    8888: "http", 9000: "http",
}

TIMEOUT = 2.0


def probe(host, port):
    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
    except Exception:
        return {"port": port, "open": False, "ms": 0, "banner": ""}
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
    return {"port": port, "open": True, "ms": elapsed, "banner": banner}


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
    for result in sorted(results, key=lambda item: item["port"]):
        label = "Port " + str(result["port"]) + " (" + names[result["port"]] + ")"
        if result["open"]:
            rows.append((label, "Open (" + str(result["ms"]) + " ms)"))
            if result["banner"]:
                rows.append((label + " banner", short(result["banner"], 160)))
        else:
            rows.append((label, "Closed or filtered"))
    web_ports = [item["port"] for item in opened if item["port"] in WEB_PROBE_PORTS]
    for port in sorted(web_ports):
        rows.append(("Port " + str(port) + " web", probe_web_port(host, port)))
    return {"rows": rows}
