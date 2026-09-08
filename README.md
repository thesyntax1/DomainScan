# DomainScan

DomainScan is a desktop tool that collects publicly available information about a domain or website and presents it in one window. Enter a domain, run the scan, browse the findings, export a report.

## What it collects

- Target breakdown (normalized URL, registrable domain, subdomain, suffix)
- DNS records (A, AAAA, CNAME with chain following, MX, NS, TXT, SOA, CAA, DS, DNSKEY, SRV, HTTPS, SVCB, TLSA, SSHFP, NAPTR, DNAME)
- DNS extras (SOA timers, CAA, DS, DNSKEY, TLSA, SSHFP, SRV, NAPTR, HTTPS/SVCB, LOC parsing, multi-resolver comparison, DoH comparison, DNSSEC validation flags, zone transfer, open recursion test, NS diversity)
- Subdomain discovery (certificate transparency, passive DNS, DNS brute-force, wildcard detection, wildcard-artifact filtering, depth stats, takeover review)
- Subdomain web probing (HTTP status, server and title per subdomain)
- WHOIS / RDAP (authoritative TLD RDAP via IANA bootstrap, port-43 fallback with raw record, EPP status meanings, IP/RIR WHOIS, NS resolution with lame-delegation notes, TLD manager, domain age, contacts)
- Typosquat check (40 lookalike variants with DNS probing)
- Certificate history (CT log search via crt.sh: issuers, expiries, wildcards)
- Web archive (Wayback CDX: captures, timespan, content types, interesting paths)
- IP and network (ping, reverse DNS, ASN, ISP, geolocation with map link, dual-stack and routable checks)
- BGP routing (prefix with size, origin ASN, announced prefixes, peers, prefix use, PeeringDB/RDAP enrichment)
- Reputation (IPv4 blocklists across 7 DNSBLs plus domain blocklists SURBL/DBL/SEM)
- Website (redirects, headers, cookies with flag and prefix analysis, CSP/Permissions/Link/Server-Timing parsing, X-header inventory, security headers, compression ratio, TTFB, HTTP version, clock skew, cache validators)
- Extra web checks (HTTP methods, TRACE, clickjacking, CORS with null-origin probe, WAF fingerprints, CDN detection, open redirect test, host injection test, Alt-Svc, HSTS preload, IPv6, 404 handling, sensitive paths, API discovery with GraphQL introspection, Swagger and wp-json parsing)
- Exposure scan (50 sensitive paths with body-signature verification: git, env, backups, cloud keys, consoles, actuators)
- TLS certificate (issuer, validity, 398-day compliance, SANs, fingerprints, trust, ALPN/HTTP2, legacy and TLS 1.3 probes, openssl chain with key size/usage/SCT/Must-Staple parsing, OCSP stapling, session resumption, weak cipher probes)
- Mail authentication (SPF with lookup count and issue detection, DMARC with external-report auth, DKIM selectors, BIMI logo fetch, MTA-STS verdict, TLS-RPT, MX health incl. CNAME/private-IP checks, ESMTP extensions, STARTTLS certificates, DANE)
- Page content (title, meta tags, links, images, scripts with SRI audit, forms with CSRF/upload analysis, login forms, jQuery version, error disclosure, DOM stats, PWA markers, mixed content, external resource counts, JS paths, HTML comments, JSON-LD, SEO basics, contacts)
- SEO audit (titles, descriptions, canonical, hreflang, Open Graph, headings, technical checks with live validation)
- Accessibility audit (language, alt text, labels, buttons, landmarks, skip links, scored)
- Performance audit (TTFB, compression, render-blocking resources, image optimization, scored)
- Privacy audit (tracker list, fingerprinting markers, referrer policy, consent banners)
- Mini crawler (same-site pages, titles, timings, status codes, broken links, duplicate titles, external domains)
- JS analysis (endpoint extraction, secret scanning with redacted previews, framework and library versions, dangerous sinks, source-map disclosure)
- Technologies (200+ markers: servers, hosting, CMS, frameworks, libraries, analytics, ads, chat, payment, bot protection, consent managers)
- Site files (robots.txt with sensitive-path review, sitemap.xml with date ranges, security.txt with RFC 9116 checks, ads.txt parsing, humans.txt, crossdomain policy, favicon with hash, manifest, well-known enumeration, CMS version files)
- Web history (first and latest archive captures, active years)
- TCP ports (32 ports with open/closed/filtered states, risk ratings, banners with version parsing, FTP anonymous test, TLS detection, UDP DNS probe, web probing)
- Cross-checks (DNS vs WHOIS NS consistency, DNSSEC completeness, SOA serial verdict, SPF include validation, DMARC mailbox check, CAA-vs-issuer match, null-MX note, www-vs-apex, certificate coverage, cookie audit)

A typical scan returns several hundred findings. Anything that cannot be resolved is reported as missing, never guessed.

## Scan profiles

Quick skips ports, subdomains, crawling, JS analysis and recon sections (archive, certificate history, typosquat, exposures). Standard runs everything with moderate limits. Deep raises crawl, JS and subdomain limits. Pick a profile in the desktop app or with `--profile` on the command line.

## Requirements

- Python 3.9 or newer (3.11 recommended)
- tkinter (ships with standard Python on Windows and macOS; on Debian/Ubuntu install `python3-tk`)

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Type a domain or URL (for example `example.com`) and press Scan. The Tools menu offers a standalone WHOIS lookup for any domain or IP.

## Command line

```bash
python main.py example.com --profile Standard --export report.html
```

Run `python main.py --help` for all options. Every scan is saved under `~/.domainscan/history/` and can be compared with earlier scans from the Compare button.

## Export

Reports can be saved as JSON, CSV, plain text or styled HTML from the buttons above the results.

## Tests

```bash
python -m unittest discover -s tests
```

The suite runs fully offline using a local HTTP server, a local TLS server and canned DNS/WHOIS responses.

## Legal note

DomainScan only reads public data and performs light, non-intrusive checks. Only scan domains you own or are authorized to test.
