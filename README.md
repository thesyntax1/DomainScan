# DomainScan

DomainScan is a desktop tool that collects publicly available information about a domain or website and presents it in one window. Enter a domain, run the scan, browse the findings, export a report.

## What it collects

- Target breakdown (normalized URL, registrable domain, subdomain, suffix)
- DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DS, DNSKEY, SRV)
- WHOIS / RDAP (registrar, dates, statuses, contacts, nameservers)
- IP and network (reverse DNS, ASN, ISP, geolocation)
- Website (redirects, headers, cookies, security headers, timing)
- TLS certificate (issuer, validity, SANs, fingerprints, trust)
- Mail authentication (SPF, DMARC, DKIM, BIMI, MTA-STS, MX reachability)
- Page content (title, meta tags, links, images, scripts, forms, contacts)
- Technologies (server, CMS, JS libraries, analytics, CDN markers)
- Site files (robots.txt, sitemap.xml, security.txt, ads.txt, favicon, manifest)
- Common TCP ports (connect check with banners where offered)

A typical scan returns a few hundred findings. Anything that cannot be resolved is reported as missing, never guessed.

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

Type a domain or URL (for example `example.com`) and press Scan.

## Export

Reports can be saved as JSON, CSV or plain text from the buttons above the results.

## Tests

```bash
python -m unittest discover -s tests
```

The suite runs fully offline using a local HTTP server, a local TLS server and canned DNS/WHOIS responses.

## Legal note

DomainScan only reads public data and performs light, non-intrusive checks. Only scan domains you own or are authorized to test.
