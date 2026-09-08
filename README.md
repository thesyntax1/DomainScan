<div align="center">

<img src="domainscan/assets/logo.png" alt="DomainScan logo" width="128" height="128">

# DomainScan

**Legal, fast, offline-friendly website &amp; domain intelligence — in one desktop window.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()
[![Version](https://img.shields.io/badge/Version-1.9.0-2f7cf6)]()
[![Tests](https://img.shields.io/badge/Tests-268%20passing-success)]()

</div>

DomainScan is a desktop tool that collects **publicly available information** about a domain or website and presents it in one window. Enter a domain, run the scan, browse the findings, export a report. It is built to be honest about what it finds: anything that cannot be resolved is reported as *missing*, never guessed or fabricated.

---

## ✨ Highlights

- 🔍 **Hundreds of findings** across 30+ sections (DNS, TLS, mail auth, WHOIS/RDAP, subdomains, ports, content, SEO, privacy, BGP, reputation and more).
- ⚡ **Fast profiles** — `Quick` skips slow recon and deep probes so a scan returns in seconds; `Standard` and `Deep` go further.
- 🌍 **Multilingual UI** — English, Türkçe, Español, Deutsch (switched live from the header).
- 📤 **Export** to JSON, CSV, TXT or styled HTML.
- 🧪 **Fully offline test suite** (268 tests, no network needed).
- 🛡️ **Ethical by design** — passive/light checks only, plus a prominent authorization reminder.

## What it collects

- Target breakdown (normalized URL, registrable domain, subdomain, suffix)
- Security grade (A+ to F score with transparent deductions and top recommendations)
- DNS records (A, AAAA, CNAME with chain following, MX, NS, TXT, SOA, CAA, DS, DNSKEY, SRV, HTTPS, SVCB, TLSA, SSHFP, NAPTR, DNAME)
- DNS extras (SOA timers, CAA with issuewild/critical detail, DS/DNSKEY linkage verification, RRSIG expiry, NSEC zone walking, TLSA, SSHFP, SRV, NAPTR, HTTPS/SVCB, LOC parsing, 5-resolver propagation comparison, DoH comparison, DNSSEC validation flags, zone transfer, open recursion test, NS diversity, NSID/version)
- Subdomain discovery (certificate transparency, passive DNS incl. OTX, AnubisDB and RapidDNS, DNS brute-force, wildcard detection, wildcard-artifact filtering, depth stats, takeover review with HTTP verification)
- Subdomain web probing (HTTP status, server and title per subdomain)
- WHOIS / RDAP (authoritative TLD RDAP via IANA bootstrap, port-43 fallback with raw record, EPP status meanings, IP/RIR WHOIS, NS resolution with lame-delegation notes, TLD manager, domain age, abuse contact summary, contacts)
- Typosquat check (40 lookalike variants with DNS probing, IDN homoglyphs, live page titles)
- Certificate history (CT log search via crt.sh and Cert Spotter: issuers, expiries, wildcards)
- Web archive (Wayback CDX: captures, timespan, content types, archived subdomains, byte totals, homepage drift vs current page, interesting paths)
- Threat intelligence (urlscan.io verdicts, ThreatFox and URLhaus malware lookups)
- Common Crawl (third-party web archive index: captures, content types, subdomains)
- IP and network (ping, TCP latency, reverse DNS, ASN, ISP, geolocation with map link and dual-provider cross-check, dual-stack and routable checks)
- BGP routing (prefix with size, origin ASN, announced prefixes, peers, prefix use, PeeringDB/RDAP enrichment)
- Reputation (IPv4 blocklists across 7 DNSBLs plus domain blocklists SURBL/DBL/SEM)
- Website (redirects, headers, cookies with flag and prefix analysis, CSP/Permissions/Link/Server-Timing parsing, X-header inventory, security headers, compression ratio, TTFB, HTTP version, clock skew, cache validators)
- Extra web checks (HTTP methods, TRACE, clickjacking, CORS with null-origin probe, WAF fingerprints, CDN detection, open redirect test, host injection test, Alt-Svc, HSTS preload, live preload-list status, IPv6, 404 handling, client-side redirect chains, WebSocket and Socket.IO probes, sensitive paths, API discovery with GraphQL introspection, Swagger and wp-json parsing)
- Exposure scan (80 sensitive paths with body-signature verification: git, env, backups, cloud keys, consoles, actuators, container and API descriptors, debug logs, CI files)
- TLS certificate (issuer, validity, 398-day compliance, SANs, fingerprints, trust, ALPN/HTTP2, legacy and TLS 1.3 probes, openssl chain with key size/usage/SCT/Must-Staple parsing, OCSP stapling, session resumption, weak cipher probes incl. 3DES/RC4 offers, accepted cipher-group enumeration with verdict)
- Mail authentication (SPF with lookup count, include/redirect chain walk and issue detection, DMARC with external-report auth, DKIM selectors, BIMI logo and SVG validation, MTA-STS verdict, TLS-RPT, MX health incl. CNAME/private-IP checks, ESMTP extensions, STARTTLS certificates, DANE, SMTP relay probe, spoofability verdict)
- Page content (title, meta tags, links, images, scripts with SRI audit, forms with CSRF/upload analysis, login forms, jQuery version, generator version disclosure, color-contrast WCAG check, error disclosure, DOM stats, PWA markers, mixed content, external resource counts, JS paths, HTML comments, JSON-LD, SEO basics, contacts)
- SEO audit (titles, descriptions, canonical, hreflang with BCP 47 and self-reference validation, Open Graph, headings, technical checks with live validation)
- Accessibility audit (language, alt text, labels, buttons, landmarks, skip links, scored)
- Performance audit (TTFB, compression, render-blocking resources, image optimization, scored)
- Privacy audit (tracker list, fingerprinting markers, referrer policy, consent banners)
- Mini crawler (same-site pages, titles, timings, status codes, broken links, duplicate titles, thin-content detection, tracking/query-parameter audit, external domains)
- JS analysis (endpoint extraction, secret scanning with redacted previews, hardcoded JWT detection with claim listing, framework and library versions, dangerous sinks incl. Function/setInterval/merge calls, source-map disclosure)
- Technologies (200+ markers: servers, hosting, CMS, frameworks, libraries, analytics, ads, chat, payment, bot protection, consent managers)
- Site files (robots.txt with sensitive-path review, sitemap.xml with index recursion and date ranges, security.txt with RFC 9116 checks, ads.txt parsing with format validation, humans.txt, crossdomain policy, favicon with hash, manifest, well-known enumeration, CMS version files)
- Web history (first and latest archive captures, active years)
- TCP ports (32 ports with open/closed/filtered states, risk ratings, banners with version parsing, service CVE advisories, FTP anonymous test, TLS detection, UDP DNS/NTP/SSDP probes, web probing)
- Cross-checks (DNS vs WHOIS NS consistency, DNSSEC completeness, SOA serial verdict, SPF include validation, DMARC mailbox check, CAA-vs-issuer match, null-MX note, www-vs-apex, certificate coverage, cookie audit)

A typical scan returns several hundred findings. Anything that cannot be resolved is reported as missing, never guessed. All remote lookups use shared retry helpers with backoff, DNS queries rotate resolvers with TCP fallback, and scan comparison includes a multi-run findings trend.

## Scan profiles

| Profile  | What it runs |
| -------- | ------------ |
| **Quick** | Core DNS records, WHOIS/RDAP, IP &amp; geolocation, website headers, basic TLS certificate, site files, DNS-based mail auth (SPF/DMARC/DKIM), content/SEO/accessibility/performance/privacy audits, cross-checks and the security grade. Skips ports, subdomains, crawling, JS analysis, BGP, blocklists, certificate history, typosquat, threat feeds, web archive and the slow deep probes (openssl chain/OCSP/cipher enumeration, SMTP probing, DNS resolver comparison/AXFR/NS identity). |
| **Standard** | Everything in Quick plus ports, subdomains, crawling (15 pages), JS analysis (6 files), subdomain web probing and all recon/deep sections. |
| **Deep** | Standard with raised limits: 40 crawl pages, 12 JS files, 40 subdomain web probes. |

## Requirements

- Python 3.9 or newer (3.11 recommended)
- tkinter (ships with standard Python on Windows and macOS; on Debian/Ubuntu install `python3-tk`)

## Install

```bash
git clone https://github.com/thesyntax1/DomainScan.git
cd DomainScan
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Type a domain or URL (for example `example.com`) and press **Scan**. The Tools menu offers a standalone WHOIS lookup for any domain or IP. The Scan menu opens **Scan History** (load or compare earlier scans) and **Watch Target** (rescan periodically and report changes). The interface language can be switched from the header (🇬🇧 English, 🇹🇷 Türkçe, 🇪🇸 Español, 🇩🇪 Deutsch); menus, buttons, dialogs and section names follow immediately and the choice is remembered. Finding details stay in English as technical labels.

Every scan is saved under `~/.domainscan/history/` (older runs are pruned to the latest 20) and can be compared with earlier scans from the Scan menu.

## Windows executable

No Python needed: download `DomainScan.exe` from the [Releases](https://github.com/thesyntax1/DomainScan/releases) page. Every `v*` tag is built automatically with PyInstaller on GitHub Actions and attached to its release. The binary is unsigned, so Windows SmartScreen may ask for confirmation on first run.

## Export

Reports can be saved as JSON, CSV, plain text or styled HTML from the buttons above the results.

## Tests

```bash
python -m unittest discover -s tests
```

The suite (268 tests) runs fully offline using a local HTTP server, a local TLS server and canned DNS/WHOIS responses.

---

## ⚖️ Legal &amp; ethical note — please read

DomainScan only reads **publicly available data** and performs **light, non-intrusive checks**. It never sends mail content, never uploads payloads, never exploits a vulnerability, and never attempts to access anything that is not already exposed over the public network.

A small number of checks are *active* (they open a connection to a service that the target is already publishing), for example:

- TCP port reachability, TLS handshake and banner capture
- SMTP `EHLO`/`VRFY`/`EXPN` and a relay probe that **stops at `RCPT TO`** (no message data is ever sent)
- Zone-transfer (AXFR) and open-resolver detection

**Only scan domains you own or are explicitly authorized to test.** Unauthorized scanning of infrastructure you do not control may violate your provider's terms of service or the law in your jurisdiction. You are responsible for how you use this tool.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Open an issue to discuss what you would like to change.
2. Keep scans non-intrusive and report missing data instead of inventing it.
3. Run `python -m unittest discover -s tests` before submitting — all tests are offline.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🙏 Acknowledgments

DomainScan builds on [requests](https://github.com/psf/requests), [dnspython](https://www.dnspython.org/), [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) and [tldextract](https://github.com/john-kurkowski/tldextract), and queries many free public data sources (IANA RDAP, crt.sh, urlscan.io, abuse.ch, BGPView, PeeringDB, ip-api.com, ipwho.is, Cloudflare DoH, the Internet Archive and more).
