import platform
import re
import socket
import subprocess

from domainscan.helpers import BROWSER_UA, fetch_json, no_window_flags


IPAPI_FIELDS = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"


def collect(ips, host=""):
    rows = []
    unique = []
    for ip in ips or []:
        if ip and ip not in unique:
            unique.append(ip)
    if not unique:
        rows.append(("IP addresses", "None resolved"))
        if host:
            rows.append(("ICMP ping", ping(host)))
        return {"rows": rows}
    rows.append(("IP address count", str(len(unique))))
    rows.append(("Dual stack", dual_stack(unique)))
    for ip in unique[:2]:
        rows.append((ip + " routable", "Yes, public IP" if routable(ip) else "No (private or reserved)"))
    if host:
        rows.append(("ICMP ping", ping(host)))
        rows.append(("TCP latency", summarize_latency(host)))
    shown = unique[:6]
    if len(unique) > 6:
        rows.append(("IP note", "Showing first 6 of " + str(len(unique))))
    for index, ip in enumerate(shown, 1):
        rows.extend(describe_ip(ip, index))
    return {"rows": rows}


def ping(host):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "2000", host]
    else:
        command = ["ping", "-c", "1", "-W", "2", host]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=8, creationflags=no_window_flags())
    except FileNotFoundError:
        return "ping tool not available"
    except Exception:
        return "Ping failed"
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return "No reply (filtered or offline)"
    match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)
    if match:
        return "Reply in " + match.group(1) + " ms"
    return "Reply received"


def summarize_latency(host, timeout=5):
    import time
    best = None
    for port in (80, 443):
        start = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            elapsed = (time.monotonic() - start) * 1000
        except Exception:
            continue
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
        if best is None or elapsed < best:
            best = elapsed
    if best is None:
        return "No TCP answer on 80/443"
    if best < 50:
        return str(int(best)) + " ms (excellent)"
    if best < 150:
        return str(int(best)) + " ms (good)"
    return str(int(best)) + " ms (slow)"


def dual_stack(ips):
    v4 = any(":" not in ip for ip in ips)
    v6 = any(":" in ip for ip in ips)
    if v4 and v6:
        return "Yes (A and AAAA records)"
    if v6:
        return "No (IPv6 only)"
    return "No (IPv4 only)"


def routable(ip):
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False


def map_link(lat, lon):
    return "https://www.openstreetmap.org/?mlat=" + str(lat) + "&mlon=" + str(lon) + "&zoom=10"


def reverse_dns(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def describe_ip(ip, index):
    prefix = "IP " + str(index) + " "
    rows = []
    rows.append((prefix + "address", ip))
    if ":" in ip:
        rows.append((prefix + "version", "IPv6"))
    else:
        rows.append((prefix + "version", "IPv4"))
    reverse = reverse_dns(ip)
    if reverse:
        rows.append((prefix + "reverse DNS", reverse))
        if ":" not in ip:
            try:
                forward = socket.gethostbyname(reverse)
                if forward == ip:
                    rows.append((prefix + "forward confirm", "Matches (" + forward + ")"))
                else:
                    rows.append((prefix + "forward confirm", "Mismatch, forward resolves to " + forward))
            except Exception:
                rows.append((prefix + "forward confirm", "Reverse name does not resolve forward"))
    else:
        rows.append((prefix + "reverse DNS", "No PTR record"))
    geo, source = lookup_geo(ip)
    if not geo:
        rows.append((prefix + "geolocation", "Lookup failed"))
        return rows
    rows.append((prefix + "geo source", source))
    mapping = [
        ("continent", "continent"),
        ("country", "country"),
        ("countryCode", "country code"),
        ("regionName", "region"),
        ("region", "region code"),
        ("city", "city"),
        ("district", "district"),
        ("zip", "postal code"),
        ("lat", "latitude"),
        ("lon", "longitude"),
        ("timezone", "timezone"),
        ("currency", "currency"),
        ("isp", "ISP"),
        ("org", "organization"),
        ("as", "ASN"),
        ("asname", "AS name"),
        ("mobile", "mobile network"),
        ("proxy", "proxy or VPN"),
        ("hosting", "hosting range"),
    ]
    for key, label in mapping:
        value = geo.get(key, "")
        if value == "" or value is None:
            continue
        if isinstance(value, bool):
            if value:
                value = "Yes"
            else:
                value = "No"
        rows.append((prefix + label, str(value)))
    if geo.get("lat", "") != "" and geo.get("lon", "") != "":
        rows.append((prefix + "map", map_link(geo.get("lat"), geo.get("lon"))))
    if index == 1:
        rows.extend(second_source_rows(ip, geo, source, prefix))
    return rows


def second_source_rows(ip, primary, source, prefix):
    rows = []
    try:
        if source == "ip-api.com":
            data = fetch_json("https://ipwho.is/" + ip, timeout=8)
            if data.get("success") is False:
                return rows
            other = normalize_ipwho(data)
            other_name = "ipwho.is"
        else:
            url = "http://ip-api.com/json/" + ip
            data = fetch_json(url, params={"fields": IPAPI_FIELDS}, timeout=8)
            if data.get("status") != "success":
                return rows
            other = data
            other_name = "ip-api.com"
    except Exception:
        return rows
    matches = 0
    compared = 0
    for key in ("countryCode", "as"):
        first = str(primary.get(key, "") or "")
        second = str(other.get(key, "") or "")
        if not first or not second:
            continue
        compared += 1
        if key == "as":
            first = asn_number(first)
            second = asn_number(second)
        else:
            first = first.upper().strip()
            second = second.upper().strip()
        if first and first == second:
            matches += 1
        else:
            rows.append((prefix + "mismatch " + key, str(primary.get(key)) + " vs " + str(other.get(key)) + " (" + other_name + ")"))
    if compared and matches == compared:
        rows.append((prefix + "cross-check", "Country and ASN agree with " + other_name))
    elif compared:
        rows.append((prefix + "cross-check", "Sources disagree (see mismatch rows)"))
    return rows


def asn_number(text):
    import re
    match = re.search(r"(\d+)", str(text or ""))
    if match:
        return match.group(1)
    return ""


def lookup_geo(ip):
    try:
        url = "http://ip-api.com/json/" + ip
        params = {"fields": IPAPI_FIELDS}
        data = fetch_json(url, params=params, timeout=8)
        if data.get("status") == "success":
            return data, "ip-api.com"
    except Exception:
        pass
    try:
        data = fetch_json("https://ipwho.is/" + ip, timeout=8)
        if data.get("success") is False:
            return None, ""
        return normalize_ipwho(data), "ipwho.is"
    except Exception:
        pass
    return None, ""


def normalize_ipwho(data):
    connection = data.get("connection", {}) or {}
    timezone = data.get("timezone", {}) or {}
    asn = connection.get("asn", "")
    if isinstance(timezone, dict):
        zone = timezone.get("id", "")
    else:
        zone = str(timezone)
    if asn:
        asn_text = "AS" + str(asn)
    else:
        asn_text = ""
    return {
        "continent": data.get("continent", ""),
        "country": data.get("country", ""),
        "countryCode": data.get("country_code", ""),
        "regionName": data.get("region", ""),
        "city": data.get("city", ""),
        "zip": data.get("postal", ""),
        "lat": data.get("latitude", ""),
        "lon": data.get("longitude", ""),
        "timezone": zone,
        "isp": connection.get("isp", ""),
        "org": connection.get("org", ""),
        "as": asn_text,
        "asname": connection.get("domain", ""),
    }
