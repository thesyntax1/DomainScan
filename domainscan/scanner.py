import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from domainscan import __version__
from domainscan import bgp_check, content_check, crawl_check, cross_check, dns_check, files_check, helpers, history_check, http_check, js_check, mail_check, network_check, ports_check, reputation_check, subdomain_check, web_extra_check, whois_check


def safe_run(func):
    try:
        return func()
    except Exception as exc:
        return {"rows": [("Status", "Check failed (" + exc.__class__.__name__ + ": " + helpers.short(str(exc), 160) + ")")]}


def run_scan(raw_target, on_progress=None, include_ports=True, include_subdomains=True, timeout=12, crawl_pages=15, js_files=6, subdomain_web=20):
    started = time.perf_counter()

    def emit(percent, message):
        if on_progress:
            try:
                on_progress(percent, message)
            except Exception:
                pass

    emit(3, "Parsing target")
    info = helpers.parse_target(raw_target)
    host = info["host"]
    parts = helpers.split_domain(host, info["is_ip"])
    if info["is_ip"]:
        apex = ""
    else:
        apex = parts["registrable"]
    fetch_url = info["base_url"] + info["path"]
    sections = {}
    sections["Target"] = helpers.describe_target(info)

    emit(8, "Querying DNS records")
    try:
        dns_result = dns_check.collect(host, apex)
    except Exception as exc:
        dns_result = {"rows": [("DNS status", "Check failed (" + exc.__class__.__name__ + ")")], "data": {}}
    sections["DNS"] = dns_result["rows"]
    dns_data = dns_result.get("data", {})
    ips = (dns_data.get("a") or []) + (dns_data.get("aaaa") or [])

    jobs = [
        ("WHOIS / RDAP", "Querying WHOIS and RDAP", lambda: whois_check.collect(apex if apex else host, host)),
        ("Subdomains", "Discovering subdomains", lambda: subdomain_check.collect(apex, include_subdomains)),
        ("Network", "Looking up IP and geolocation", lambda: network_check.collect(ips, host)),
        ("BGP", "Looking up BGP and ASN", lambda: bgp_check.collect(ips)),
        ("Reputation", "Checking blocklists", lambda: reputation_check.collect(ips)),
        ("Website", "Fetching website", lambda: http_check.collect_http(fetch_url, timeout)),
        ("TLS", "Checking TLS certificate", lambda: http_check.collect_tls(host, 443)),
        ("Site Files", "Fetching robots and sitemaps", lambda: files_check.collect(info["base_url"], timeout)),
        ("Mail", "Checking mail authentication", lambda: mail_check.collect(host, apex, dns_data)),
        ("Web History", "Checking web archive", lambda: history_check.collect(host, fetch_url)),
        ("Ports", "Probing common ports", lambda: ports_check.collect(host, include_ports)),
    ]
    results = {}
    total = len(jobs)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {}
        for section, message, func in jobs:
            futures[pool.submit(safe_run, func)] = (section, message)
        done = 0
        for future in as_completed(futures):
            section, message = futures[future]
            results[section] = future.result()
            done += 1
            emit(10 + int(62 * done / total), message)
    sections["WHOIS / RDAP"] = results["WHOIS / RDAP"]["rows"]
    sections["Subdomains"] = results["Subdomains"]["rows"]
    confirmed = results["Subdomains"].get("confirmed", {}) or {}
    sections["Network"] = results["Network"]["rows"]
    sections["BGP"] = results["BGP"]["rows"]
    sections["Reputation"] = results["Reputation"]["rows"]
    web = results["Website"]
    sections["Website"] = web["rows"]
    sections["TLS"] = results["TLS"]["rows"]
    sections["Site Files"] = results["Site Files"]["rows"]
    sections["Mail"] = results["Mail"]["rows"]
    sections["Web History"] = results["Web History"]["rows"]
    sections["Ports"] = results["Ports"]["rows"]

    emit(76, "Analyzing page content")
    try:
        content_result = content_check.collect(web.get("html", ""), web.get("final_url", fetch_url), web.get("headers", {}), web.get("cookies", []))
        sections["Content"] = content_result["rows"]
        sections["Technologies"] = content_result["tech"]
    except Exception as exc:
        sections["Content"] = [("Status", "Check failed (" + exc.__class__.__name__ + ")")]
        sections["Technologies"] = [("Status", "Skipped")]

    emit(84, "Running extra checks")
    html = web.get("html", "")
    final_url = web.get("final_url", fetch_url)
    post_jobs = [
        ("Web Extras", lambda: web_extra_check.collect(info["base_url"], web.get("headers", {}), timeout)),
        ("Crawl", lambda: crawl_check.collect(final_url, timeout, crawl_pages) if html else {"rows": [("Crawl", "Skipped (no page content)")]}),
        ("JS Analysis", lambda: js_check.collect(final_url, html, timeout, js_files) if html else {"rows": [("JS analysis", "Skipped (no page content)")]}),
        ("Subdomain Web", lambda: subdomain_check.probe_web(confirmed, subdomain_web, timeout) if confirmed and subdomain_web > 0 else {"rows": [("Subdomain web", "Skipped")]}),
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}
        for section, func in post_jobs:
            futures[pool.submit(safe_run, func)] = section
        for future in as_completed(futures):
            sections[futures[future]] = future.result()["rows"]

    emit(93, "Running cross-checks")
    whois_ns = results["WHOIS / RDAP"].get("nameservers", []) or []
    try:
        cross_result = cross_check.collect(info, apex, dns_data, web, whois_ns, timeout)
        sections["Cross-Checks"] = cross_result["rows"]
    except Exception as exc:
        sections["Cross-Checks"] = [("Status", "Check failed (" + exc.__class__.__name__ + ")")]

    emit(96, "Finishing")
    duration = time.perf_counter() - started
    ordered = {}
    for section in ("Target", "DNS", "Subdomains", "Subdomain Web", "WHOIS / RDAP", "Network", "BGP", "Reputation", "Website", "Web Extras", "TLS", "Mail", "Content", "Crawl", "JS Analysis", "Technologies", "Site Files", "Web History", "Ports", "Cross-Checks"):
        if section in sections:
            ordered[section] = sections[section]
    ordered["Summary"] = build_summary(info, ordered, duration)
    emit(100, "Scan complete")
    findings = 0
    for items in ordered.values():
        findings += len(items)
    return {
        "target": info,
        "sections": ordered,
        "meta": {
            "version": __version__,
            "duration_seconds": round(duration, 1),
            "scanned_at": helpers.now_utc(),
            "findings": findings,
        },
    }


def build_summary(info, sections, duration):
    rows = []
    rows.append(("Target", info["host"]))
    rows.append(("Scanned at", helpers.now_utc()))
    rows.append(("Duration", str(round(duration, 1)) + " seconds"))
    total = 0
    for section, items in sections.items():
        rows.append((section + " findings", str(len(items))))
        total += len(items)
    rows.append(("Total findings", str(total)))
    rows.append(("Tool", "DomainScan " + __version__))
    return rows
