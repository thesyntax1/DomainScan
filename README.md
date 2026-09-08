# DomainScan

DomainScan is a desktop tool that collects publicly available information about a domain or website and presents it in one window. Enter a domain, run the scan, browse the findings, export a report.

## What it collects

- Target breakdown (normalized URL, registrable domain, subdomain, suffix)
- DNS records (A, AAAA, CNAME with chain following, MX, NS, TXT, SOA, CAA, DS, DNSKEY, SRV, HTTPS, SVCB, TLSA, SSHFP, NAPTR, DNAME)
- DNS extras (SOA/CAA/DS/DNSKEY parsing, multi-resolver comparison, zone transfer test)
- Subdomain discovery (certificate transparency, passive DNS, DNS brute-force, wildcard detection, wildcard-artifact filtering, depth stats, takeover review)
- Subdomain web probing (HTTP status, server and title per subdomain)
- WHOIS / RDAP (authoritative TLD RDAP via IANA bootstrap, port-43 fallback with raw record, EPP status meanings, IP/RIR WHOIS, NS resolution with lame-delegation notes, TLD manager, domain age, contacts)
- IP and network (ping, reverse DNS, ASN, ISP, geolocation with map link, dual-stack and routable checks)
- BGP routing (prefix with size, origin ASN, announced prefixes, peers, prefix use)
- Reputation (IPv4 blocklist checks across major DNSBLs)
- Website (redirects, headers, cookies with flag analysis, security headers, compression, timing, clock skew, cache validators)
- Extra web checks (HTTP methods, TRACE, clickjacking, CORS, WAF probe, Alt-Svc, HSTS preload, IPv6, 404 handling, sensitive paths, API discovery)
- TLS certificate (issuer, validity, SANs, fingerprints, trust, ALPN/HTTP2, legacy and TLS 1.3 probes, openssl chain and weak cipher probes)
- Mail authentication (SPF with lookup count and issue detection, DMARC, DKIM, BIMI, MTA-STS policy, TLS-RPT, MX reachability, STARTTLS, DANE)
- Page content (title, meta tags, links, images, scripts, forms, login forms, mixed content, external resource counts, JS paths, HTML comments, JSON-LD, SEO basics, contacts)
- Mini crawler (same-site pages, titles, broken links)
- JS analysis (endpoint extraction, secret scanning with redacted previews)
- Technologies (server, hosting, CMS, forums, shops, JS libraries, analytics, ads, chat, payment, CDN markers)
- Site files (robots.txt, sitemap.xml with robots fallback, security.txt, ads.txt, humans.txt, crossdomain policy, favicon with hash, manifest)
- Web history (first and latest archive captures, active years)
- Common TCP ports (open/closed/filtered states with banners and web probing on open web ports)
- Cross-checks (DNS vs WHOIS NS consistency, DNSSEC completeness, SOA serial verdict, SPF include validation, DMARC mailbox check, www-vs-apex, certificate coverage, cookie audit)

A typical scan returns several hundred findings. Anything that cannot be resolved is reported as missing, never guessed.

## Scan profiles

Quick skips ports, subdomains, crawling and JS analysis. Standard runs everything with moderate limits. Deep raises crawl, JS and subdomain limits. Pick a profile in the desktop app or with `--profile` on the command line.

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
