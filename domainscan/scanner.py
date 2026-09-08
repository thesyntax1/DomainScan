import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from domainscan import __version__
from domainscan import a11y_check, bgp_check, commoncrawl_check, content_check, crawl_check, cross_check, crtsh_check, dns_check, exposure_check, files_check, grade_check, helpers, history_check, http_check, js_check, mail_check, network_check, perf_check, ports_check, privacy_check, reputation_check, seo_check, subdomain_check, threat_check, typo_check, wayback_check, web_extra_check, whois_check


def safe_run(func):
    # Each check already retries transient network/DNS failures internally
    # (helpers.fetch_json / fetch_text / dns_check.query). Re-running the whole
    # check here only doubled slow sections, so a single guarded attempt is
    # enough and keeps every profile snappy.
    try:
        return func()
    except Exception as exc:
        return {"rows": [("Status", "Check failed (" + exc.__class__.__name__ + ": " + helpers.short(str(exc), 160) + ")")]}


def run_scan(raw_target, on_progress=None, include_ports=True, include_subdomains=True, timeout=12, crawl_pages=15, js_files=6, subdomain_web=20, include_recon=True, cancel_event=None):
    started = time.perf_counter()

    def cancelled():
        return cancel_event is not None and cancel_event.is_set()

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
    if cancelled():
        return compose_result(info, sections, started, cancelled=True)

    emit(8, "Querying DNS records")
    try:
        dns_result = dns_check.collect(host, apex, extras=include_recon, cancel_event=cancel_event)
    except Exception as exc:
        dns_result = {"rows": [("DNS status", "Check failed (" + exc.__class__.__name__ + ")")], "data": {}}
    sections["DNS"] = dns_result["rows"]
    dns_data = dns_result.get("data", {})
    ips = (dns_data.get("a") or []) + (dns_data.get("aaaa") or [])
    if cancelled():
        return compose_result(info, sections, started, cancelled=True)

    jobs = [
        ("WHOIS / RDAP", "Querying WHOIS and RDAP", lambda: whois_check.collect(apex if apex else host, host)),
        ("Subdomains", "Discovering subdomains", lambda: subdomain_check.collect(apex, include_subdomains)),
        ("Network", "Looking up IP and geolocation", lambda: network_check.collect(ips, host)),
        ("BGP", "Looking up BGP and ASN", lambda: bgp_check.collect(ips) if include_recon else {"rows": [("BGP", "Skipped (Quick profile)")]}),
        ("Reputation", "Checking blocklists", lambda: reputation_check.collect(ips, domain=apex) if include_recon else {"rows": [("Blocklists", "Skipped (Quick profile)")]}),
        ("Certificates", "Querying certificate logs", lambda: crtsh_check.collect(apex, timeout) if include_recon else {"rows": [("Certificates", "Skipped (Quick profile)")]}),
        ("Typosquat", "Checking lookalike domains", lambda: typo_check.collect(apex, include_recon)),
        ("Threat Intel", "Querying threat feeds", lambda: threat_check.collect(host, apex, timeout) if include_recon else {"rows": [("Threat Intel", "Skipped (Quick profile)")]}),
        ("Common Crawl", "Querying Common Crawl", lambda: commoncrawl_check.collect(host, timeout) if include_recon else {"rows": [("Common Crawl", "Skipped (Quick profile)")]}),
        ("Website", "Fetching website", lambda: http_check.collect_http(fetch_url, timeout)),
        ("TLS", "Checking TLS certificate", lambda: http_check.collect_tls(host, 443, deep=include_recon)),
        ("Site Files", "Fetching robots and sitemaps", lambda: files_check.collect(info["base_url"], timeout)),
        ("Mail", "Checking mail authentication", lambda: mail_check.collect(host, apex, dns_data, deep=include_recon)),
        ("Web History", "Checking web archive", lambda: history_check.collect(host, fetch_url) if include_recon else {"rows": [("Web History", "Skipped (Quick profile)")]}),
        ("Ports", "Probing common ports", lambda: ports_check.collect(host, include_ports)),
    ]
    results = {}
    total = len(jobs)
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        futures = {}
        for section, message, func in jobs:
            if cancelled():
                break
            futures[pool.submit(safe_run, func)] = (section, message)
        done = 0
        for future in as_completed(futures):
            if cancelled():
                break
            section, message = futures[future]
            try:
                results[section] = future.result()
            except Exception:
                results[section] = {"rows": [("Status", "Check failed")]}
            done += 1
            emit(10 + int(62 * done / total), message)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    def result_rows(section, key=None):
        entry = results.get(section) or {}
        return entry.get("rows", [("Status", "Skipped (scan cancelled)")])

    sections["WHOIS / RDAP"] = result_rows("WHOIS / RDAP")
    sections["Subdomains"] = result_rows("Subdomains")
    confirmed = (results.get("Subdomains") or {}).get("confirmed", {}) or {}
    sections["Network"] = result_rows("Network")
    sections["BGP"] = result_rows("BGP")
    sections["Reputation"] = result_rows("Reputation")
    web = results.get("Website") or {"rows": [("Website", "Skipped (scan cancelled)")], "html": "", "final_url": fetch_url, "headers": {}, "cookies": []}
    sections["Website"] = web["rows"]
    sections["TLS"] = result_rows("TLS")
    sections["Site Files"] = result_rows("Site Files")
    sections["Mail"] = result_rows("Mail")
    sections["Web History"] = result_rows("Web History")
    sections["Ports"] = result_rows("Ports")
    sections["Certificates"] = result_rows("Certificates")
    sections["Typosquat"] = result_rows("Typosquat")
    sections["Threat Intel"] = result_rows("Threat Intel")
    sections["Common Crawl"] = result_rows("Common Crawl")
    if cancelled():
        return compose_result(info, sections, started, cancelled=True)

    emit(76, "Analyzing page content")
    if not cancelled():
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
    sitemap_urls = (results.get("Site Files") or {}).get("sitemap_urls", []) or []
    post_jobs = [
        ("Web Extras", lambda: web_extra_check.collect(info["base_url"], web.get("headers", {}), timeout, deep=include_recon)),
        ("Crawl", lambda: crawl_check.collect(final_url, timeout, crawl_pages, sitemap_urls) if html else {"rows": [("Crawl", "Skipped (no page content)")]}),
        ("JS Analysis", lambda: js_check.collect(final_url, html, timeout, js_files) if html else {"rows": [("JS analysis", "Skipped (no page content)")]}),
        ("Subdomain Web", lambda: subdomain_check.probe_web(confirmed, subdomain_web, timeout) if confirmed and subdomain_web > 0 else {"rows": [("Subdomain web", "Skipped")]}),
        ("Exposures", lambda: exposure_check.collect(info["base_url"], timeout, include_recon)),
        ("SEO", lambda: seo_check.collect(html, final_url, web.get("headers", {}), timeout) if html else {"rows": [("SEO audit", "Skipped (no page content)")]}),
        ("Accessibility", lambda: a11y_check.collect(html) if html else {"rows": [("Accessibility", "Skipped (no page content)")]}),
        ("Performance", lambda: perf_check.collect(web, html, final_url) if html else {"rows": [("Performance", "Skipped (no page content)")]}),
        ("Privacy", lambda: privacy_check.collect(html, final_url, web.get("headers", {}), web.get("cookies", [])) if html else {"rows": [("Privacy audit", "Skipped (no page content)")]}),
        ("Archive", lambda: wayback_check.collect(host, timeout, html) if include_recon else {"rows": [("Archive", "Skipped (Quick profile)")]}),
    ]
    pool = ThreadPoolExecutor(max_workers=4)
    try:
        futures = {}
        for section, func in post_jobs:
            if cancelled():
                break
            futures[pool.submit(safe_run, func)] = section
        for future in as_completed(futures):
            if cancelled():
                break
            section = futures[future]
            try:
                sections[section] = future.result()["rows"]
            except Exception:
                sections[section] = [("Status", "Check failed")]
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if cancelled():
        return compose_result(info, sections, started, cancelled=True)

    emit(93, "Running cross-checks")
    whois_ns = (results.get("WHOIS / RDAP") or {}).get("nameservers", []) or []
    try:
        cross_result = cross_check.collect(info, apex, dns_data, web, whois_ns, timeout)
        sections["Cross-Checks"] = cross_result["rows"]
    except Exception as exc:
        sections["Cross-Checks"] = [("Status", "Check failed (" + exc.__class__.__name__ + ")")]

    emit(96, "Finishing")
    try:
        sections["Grade"] = grade_check.collect({"sections": sections})["rows"]
    except Exception:
        sections["Grade"] = [("Security grade", "Could not compute")]
    return compose_result(info, sections, started, cancelled=False)


SECTION_ORDER = (
    "Target", "Grade", "DNS", "Subdomains", "Subdomain Web", "Typosquat",
    "WHOIS / RDAP", "Network", "BGP", "Reputation", "Website", "Web Extras",
    "Exposures", "TLS", "Certificates", "Mail", "Content", "SEO",
    "Accessibility", "Performance", "Privacy", "Crawl", "JS Analysis",
    "Technologies", "Site Files", "Web History", "Archive", "Common Crawl",
    "Threat Intel", "Ports", "Cross-Checks",
)


def compose_result(info, sections, started, cancelled=False):
    duration = time.perf_counter() - started
    ordered = {}
    for section in SECTION_ORDER:
        if section in sections:
            ordered[section] = sections[section]
    summary = build_summary(info, ordered, duration)
    if cancelled:
        summary = [("Status", "Scan cancelled by user")] + summary
    ordered["Summary"] = summary
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
            "cancelled": bool(cancelled),
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
