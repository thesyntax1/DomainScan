import base64
import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver

from domainscan import a11y_check, bgp_check, commoncrawl_check, content_check, crawl_check, cross_check, crtsh_check, dns_check, exposure_check, files_check, grade_check, helpers, history_check, history_store, http_check, i18n, js_check, mail_check, network_check, perf_check, ports_check, privacy_check, profiles, rdap_check, reputation_check, scanner, seo_check, subdomain_check, threat_check, typo_check, wayback_check, web_extra_check, whois_check


SAMPLE_WHOIS = """   Domain Name: EXAMPLE.COM
   Registrar: RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY
   Registrar IANA ID: 376
   Registrar Abuse Contact Email: abuse@example.com
   Registrar Abuse Contact Phone: +1.3105551212
   Domain Status: clientDeleteProhibited https://icann.org/epp
   Domain Status: clientTransferProhibited https://icann.org/epp
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   Creation Date: 1995-08-14T04:00:00Z
   Updated Date: 2023-08-14T07:01:44Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   DNSSEC: unsigned
"""

SAMPLE_RDAP = {
    "handle": "EXAMPLE-COM",
    "ldhName": "example.com",
    "port43": "whois.example-registrar.com",
    "status": ["clientDeleteProhibited", "clientTransferProhibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2023-08-14T07:01:44Z"},
    ],
    "nameservers": [
        {"ldhName": "A.IANA-SERVERS.NET", "ipAddresses": {"v4": ["199.43.135.53"]}},
        {"ldhName": "B.IANA-SERVERS.NET"},
    ],
    "secureDNS": {"delegationSigned": False},
    "entities": [
        {
            "handle": "REG-1",
            "roles": ["registrar"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Example Registrar Inc."],
                ["org", {}, "text", "Example Registrar Inc."],
                ["email", {}, "text", "abuse@example-registrar.com"],
                ["tel", {}, "text", "+1.3105551212"],
            ]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["email", {}, "text", "abuse@example-registrar.com"],
                    ]],
                }
            ],
        }
    ],
}

SAMPLE_HTML = """<html lang="en"><head>
<title>Test Shop</title>
<meta charset="utf-8">
<meta name="description" content="A test store">
<meta name="generator" content="WordPress 6.4.2">
<meta property="og:title" content="Test Shop">
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
<script src="/wp-content/themes/shop/app.js"></script>
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></script>
<link rel="stylesheet" href="https://cdn.example.com/bootstrap-5.3.0/css/bootstrap.min.css">
</head><body>
<h1>Welcome to the test shop</h1>
<p>Contact us at hello@example.com or +1 (555) 123-4567.</p>
<a href="/about">About</a>
<a href="https://facebook.com/testshop">Facebook</a>
<a href="mailto:sales@example.com">Mail</a>
<img src="logo.png" alt="Logo">
<img src="banner.png">
<form action="/search" method="get"><input name="q"></form>
</body></html>"""


class FakeRdata:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeRrset:
    ttl = 300


class FakeAnswer(list):
    rrset = FakeRrset()


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping

    def resolve(self, name, rtype):
        key = (str(name).rstrip("."), rtype)
        if key in self.mapping:
            return FakeAnswer([FakeRdata(item) for item in self.mapping[key]])
        raise dns.resolver.NoAnswer()


def rows_to_dict(rows):
    out = {}
    for key, value in rows:
        out[key] = value
    return out


class TargetTest(unittest.TestCase):
    def test_plain_domain(self):
        info = helpers.parse_target("example.com")
        self.assertEqual(info["host"], "example.com")
        self.assertEqual(info["scheme"], "https")
        self.assertEqual(info["port"], 443)
        self.assertFalse(info["is_ip"])

    def test_full_url(self):
        info = helpers.parse_target("http://sub.example.com:8080/path?q=1")
        self.assertEqual(info["host"], "sub.example.com")
        self.assertEqual(info["port"], 8080)
        self.assertEqual(info["path"], "/path?q=1")

    def test_ip_target(self):
        info = helpers.parse_target("93.184.216.34")
        self.assertTrue(info["is_ip"])

    def test_invalid_targets(self):
        with self.assertRaises(ValueError):
            helpers.parse_target("")
        with self.assertRaises(ValueError):
            helpers.parse_target("http://")

    def test_split_domain(self):
        parts = helpers.split_domain("a.b.example.com", False)
        self.assertEqual(parts["registrable"], "example.com")
        self.assertEqual(parts["subdomain"], "a.b")

    def test_short(self):
        self.assertEqual(helpers.short("abc", 10), "abc")
        self.assertTrue(helpers.short("x" * 50, 10).endswith("..."))
        self.assertEqual(len(helpers.short("x" * 50, 10)), 10)

    def test_now_utc(self):
        self.assertTrue(helpers.now_utc().endswith("UTC"))


class DnsTest(unittest.TestCase):
    def test_clean_txt(self):
        self.assertEqual(dns_check.clean_txt('"v=spf1" "extra"'), "v=spf1 extra")
        self.assertEqual(dns_check.clean_txt("plain"), "plain")

    def test_query_type_with_fake(self):
        resolver = FakeResolver({("example.com", "A"): ["93.184.216.34", "93.184.216.35"]})
        rows = []
        records = dns_check.query_type(resolver, "example.com", "A", rows, "")
        self.assertEqual(records, ["93.184.216.34", "93.184.216.35"])
        data = rows_to_dict(rows)
        self.assertEqual(data["A record count"], "2")
        self.assertEqual(data["A TTL"], "300 seconds")

    def test_query_type_missing(self):
        resolver = FakeResolver({})
        rows = []
        records = dns_check.query_type(resolver, "example.com", "MX", rows, "")
        self.assertEqual(records, [])
        self.assertEqual(rows[0][1], "None found")


class WhoisParseTest(unittest.TestCase):
    def test_port43_text(self):
        rows = whois_check.parse_whois_text(SAMPLE_WHOIS)
        data = rows_to_dict(rows)
        self.assertIn("RESERVED-INTERNET", data["Registrar"])
        self.assertEqual(data["Registrar IANA ID"], "376")
        self.assertEqual(data["Creation date"], "1995-08-14T04:00:00Z")
        self.assertEqual(data["Expiry date"], "2026-08-13T04:00:00Z")
        self.assertEqual(data["Status count"], "2")
        self.assertEqual(data["Nameserver count"], "2")
        self.assertEqual(data["Abuse email"], "abuse@example.com")
        self.assertEqual(data["DNSSEC"], "unsigned")

    def test_rdap(self):
        rows = whois_check.parse_rdap(SAMPLE_RDAP)
        data = rows_to_dict(rows)
        self.assertEqual(data["WHOIS source"], "RDAP")
        self.assertEqual(data["Domain name"], "example.com")
        self.assertEqual(data["Status count"], "2")
        self.assertEqual(data["Date registration"], "1995-08-14T04:00:00Z")
        self.assertEqual(data["Nameserver count"], "2")
        self.assertEqual(data["Nameserver 1 IPv4"], "199.43.135.53")
        self.assertEqual(data["DNSSEC delegation"], "Unsigned")
        self.assertEqual(data["Registrar name"], "Example Registrar Inc.")
        self.assertEqual(data["Registrar abuse email"], "abuse@example-registrar.com")


class MailParseTest(unittest.TestCase):
    def test_spf(self):
        rows = mail_check.describe_spf(["v=spf1 include:_spf.google.com ip4:192.0.2.0/24 ~all"])
        data = rows_to_dict(rows)
        self.assertEqual(data["SPF mechanism count"], "3")
        self.assertIn("SoftFail", data["SPF default policy"])

    def test_spf_missing(self):
        rows = mail_check.describe_spf(["google-site-verification=abc"])
        data = rows_to_dict(rows)
        self.assertEqual(data["SPF"], "No SPF record published")

    def test_spf_strict(self):
        rows = mail_check.describe_spf(["v=spf1 mx -all"])
        data = rows_to_dict(rows)
        self.assertIn("Fail (strict)", data["SPF default policy"])

    def test_dmarc(self):
        resolver = FakeResolver({("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"']})
        rows = mail_check.describe_dmarc(resolver, "example.com")
        data = rows_to_dict(rows)
        self.assertEqual(data["DMARC policy"], "Reject (block)")
        self.assertEqual(data["DMARC rua"], "mailto:dmarc@example.com")
        self.assertEqual(data["DMARC pct"], "100")

    def test_dmarc_missing(self):
        rows = mail_check.describe_dmarc(FakeResolver({}), "example.com")
        data = rows_to_dict(rows)
        self.assertIn("No DMARC record", data["DMARC"])

    def test_dkim(self):
        key = base64.b64encode(b"K" * 64).decode("ascii")
        resolver = FakeResolver({("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=' + key + '"']})
        rows = mail_check.describe_dkim(resolver, "example.com")
        data = rows_to_dict(rows)
        self.assertEqual(data["DKIM keys found"], "1")
        self.assertEqual(data["DKIM google key"], "~512-bit RSA")

    def test_bimi_mtasts(self):
        resolver = FakeResolver({
            ("default._bimi.example.com", "TXT"): ['"v=BIMI1; l=https://example.com/logo.svg"'],
            ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=20240101"'],
        })
        rows = mail_check.describe_bimi_mtasts(resolver, "example.com")
        data = rows_to_dict(rows)
        self.assertIn("BIMI1", data["BIMI"])
        self.assertIn("STSv1", data["MTA-STS"])

    def test_null_mx(self):
        rows = mail_check.describe_mx(["0 ."])
        self.assertIn("Null MX", rows[0][1])

    def test_no_mx(self):
        rows = mail_check.describe_mx([])
        self.assertEqual(rows[0][1], "None (domain cannot receive mail)")


class ContentParseTest(unittest.TestCase):
    def test_full_analysis(self):
        result = content_check.collect(SAMPLE_HTML, "https://example.com/shop", {}, [])
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["Page title"], "Test Shop")
        self.assertEqual(data["Page language"], "en")
        self.assertEqual(data["Meta generator"], "WordPress 6.4.2")
        self.assertEqual(data["OG title"], "Test Shop")
        self.assertEqual(data["H1 count"], "1")
        self.assertEqual(data["Link count"], "3")
        self.assertEqual(data["Internal links"], "1")
        self.assertEqual(data["External links"], "1")
        self.assertEqual(data["Mailto links"], "1")
        self.assertEqual(data["Image count"], "2")
        self.assertEqual(data["Images without alt"], "1")
        self.assertEqual(data["External scripts"], "3")
        self.assertEqual(data["Stylesheet count"], "1")
        self.assertEqual(data["Form count"], "1")
        self.assertEqual(data["Form 1"], "GET /search")
        self.assertEqual(data["Email addresses found"], "2")
        self.assertEqual(data["Social profiles"], "1")
        self.assertIn("facebook.com/testshop", data["Social: Facebook"])

    def test_tech_detection(self):
        headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1.2"}
        cookies = [{"name": "PHPSESSID", "value": "x", "domain": "", "secure": False}]
        metas = {"generator": "WordPress 6.4.2"}
        found = content_check.detect_tech(SAMPLE_HTML, headers, cookies, metas)
        data = rows_to_dict(found)
        self.assertIn("Tech: nginx", data)
        self.assertIn("Tech: PHP", data)
        self.assertIn("Tech: jQuery 3.6.0", data)
        self.assertIn("Tech: WordPress 6.4.2", data)
        self.assertIn("Tech: Google Tag Manager", data)
        self.assertIn("Tech: Bootstrap 5.3.0", data)

    def test_empty_body(self):
        result = content_check.collect("", "https://example.com/", {}, [])
        self.assertEqual(result["rows"][0][1], "Empty response body")
        self.assertEqual(len(result["tech"]), 1)


class LocalServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), LocalHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_http_fetch(self):
        result = http_check.collect_http(self.base + "/old", timeout=5)
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["Redirect count"], "1")
        self.assertIn("301", data["Redirect 1"])
        self.assertEqual(data["HTTP status"], "200 OK")
        self.assertEqual(data["Cookie count"], "1")
        self.assertIn("abc123", data["Cookie: session"])
        self.assertIn("Present", data["Security: HSTS"])
        self.assertEqual(data["Security headers score"], "1 of 9 present")
        self.assertIn("Hello", result["html"])

    def test_site_files(self):
        result = files_check.collect(self.base, timeout=5)
        data = rows_to_dict(result["rows"])
        self.assertIn("Present", data["robots.txt"])
        self.assertEqual(data["robots.txt disallow count"], "2")
        self.assertEqual(data["robots.txt disallow 1"], "/admin/")
        self.assertEqual(data["Sitemap URL count"], "2")
        self.assertEqual(data["Sitemap URL 1"], "http://localhost/page1")
        self.assertEqual(data["security.txt Contact"], "mailto:security@example.com")
        self.assertEqual(data["ads.txt"], "Present (1 entries, 0 variables)")
        self.assertIn("Present", data["Favicon"])
        self.assertEqual(data["Manifest app name"], "Test App")
        self.assertEqual(data["Manifest icons"], "1")


class LocalHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_body(self, body, content_type="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/":
            self.send_body("<html><head><title>Local</title></head><body><p>Hello</p><a href=\"/page1\">p1</a><a href=\"/page2\">p2</a><a href=\"/missing\">m</a></body></html>", extra={
                "X-Test-Header": "test-value",
                "Strict-Transport-Security": "max-age=31536000",
                "Set-Cookie": "session=abc123; Path=/; HttpOnly",
            })
        elif self.path == "/robots.txt":
            self.send_body("User-agent: *\nDisallow: /admin/\nDisallow: /private/\nAllow: /public/\nSitemap: http://localhost/sitemap.xml\n", "text/plain")
        elif self.path == "/sitemap.xml":
            self.send_body('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://localhost/page1</loc></url><url><loc>http://localhost/page2</loc></url></urlset>', "application/xml")
        elif self.path == "/.well-known/security.txt":
            self.send_body("Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\n", "text/plain")
        elif self.path == "/ads.txt":
            self.send_body("google.com, pub-123, DIRECT\n", "text/plain")
        elif self.path == "/page1":
            self.send_body("<html><head><title>Page One</title></head><body><a href=\"/page2\">p2</a></body></html>")
        elif self.path == "/page2":
            self.send_body("<html><head><title>Page Two</title></head><body><p>End</p></body></html>")
        elif self.path == "/app.js":
            self.send_body('fetch("/api/v2/items");var key="AKIAIOSFODNN7EXAMPLE";', "application/javascript")
        elif self.path == "/.well-known/openid-configuration":
            self.send_body('{"issuer": "https://auth.local", "jwks_uri": "https://auth.local/keys"}', "application/json")
        elif self.path == "/graphql":
            body = b'{"errors": [{"message": "GET query missing"}]}'
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/.well-known/mta-sts.txt":
            self.send_body("version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\n", "text/plain")
        elif self.path == "/favicon.ico":
            self.send_body(b"\x00\x01\x02\x03\x04\x05", "image/x-icon")
        elif self.path == "/site.webmanifest":
            self.send_body('{"name": "Test App", "short_name": "Test", "theme_color": "#ffffff", "icons": [{"src": "icon.png"}]}', "application/manifest+json")
        else:
            self.send_response(404)
            self.end_headers()


class PortsTest(unittest.TestCase):
    def test_open_and_closed(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            result = ports_check.probe("127.0.0.1", port)
            self.assertTrue(result["open"])
        finally:
            server.close()
        result = ports_check.probe("127.0.0.1", port)
        self.assertFalse(result["open"])

    def test_disabled(self):
        result = ports_check.collect("127.0.0.1", enabled=False)
        self.assertIn("Skipped", result["rows"][0][1])


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TlsLocalTest(unittest.TestCase):
    def test_self_signed(self):
        tmp = tempfile.mkdtemp()
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "key.pem", "-out", "cert.pem", "-days", "2", "-nodes", "-subj", "/CN=localhost"], cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=True)
            proc = subprocess.Popen(["openssl", "s_server", "-accept", "127.0.0.1:18443", "-cert", "cert.pem", "-key", "key.pem", "-quiet"], cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                ready = False
                for _ in range(50):
                    try:
                        sock = socket.create_connection(("127.0.0.1", 18443), timeout=1)
                        sock.close()
                        ready = True
                        break
                    except Exception:
                        time.sleep(0.2)
                self.assertTrue(ready)
                result = http_check.collect_tls("127.0.0.1", 18443)
                data = rows_to_dict(result["rows"])
                self.assertIn("Yes", data["TLS reachable"])
                self.assertIn("No", data["Chain trusted"])
                self.assertIn("Fingerprint SHA-256", data)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ExportTest(unittest.TestCase):
    def make_result(self):
        return {
            "target": {"host": "example.com"},
            "sections": {
                "Target": [("Host", "example.com")],
                "DNS": [("A record 1", "93.184.216.34")],
            },
            "meta": {"version": "1.0.0", "duration_seconds": 1.2, "scanned_at": "2026-01-01 00:00:00 UTC", "findings": 2},
        }

    def test_all_formats(self):
        result = self.make_result()
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "r.json")
            helpers.export_json(json_path, result)
            with open(json_path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["sections"]["DNS"][0]["value"], "93.184.216.34")
            csv_path = os.path.join(tmp, "r.csv")
            helpers.export_csv(csv_path, result)
            with open(csv_path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("Section,Item,Value", text)
            self.assertIn("93.184.216.34", text)
            txt_path = os.path.join(tmp, "r.txt")
            helpers.export_txt(txt_path, result)
            with open(txt_path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("DomainScan report", text)
            self.assertIn("A record 1: 93.184.216.34", text)


class ZAppStubTest(unittest.TestCase):
    def test_gui_logic_without_display(self):
        from unittest import mock
        fake_tkinter = mock.MagicMock()
        sys.modules["tkinter"] = fake_tkinter
        sys.modules.pop("domainscan.app", None)
        try:
            from domainscan import app as app_module
            root = mock.MagicMock()
            app = app_module.DomainScanApp(root)
            app.tree.get_children.return_value = []
            app.search_entry.get.return_value = ""
            app.section_box.get.return_value = "All sections"
            result = {
                "target": {"host": "example.com"},
                "sections": {
                    "Target": [("Host", "example.com"), ("Port", "443 (default)")],
                    "DNS": [("A record 1", "93.184.216.34")],
                },
                "meta": {"version": "1.0.0", "duration_seconds": 1.2, "scanned_at": "now", "findings": 3},
            }
            app.finish_scan(result)
            self.assertEqual(len(app.all_rows), 3)
            app.search_entry.get.return_value = "93.184"
            app.section_box.get.return_value = "All sections"
            app.apply_filter()
            app.search_entry.get.return_value = ""
            app.section_box.get.return_value = "DNS"
            app.apply_filter()

            def fake_item(*args):
                if len(args) == 1:
                    return {"values": ["A record 1", "93.184.216.34"]}
                return "DNS"

            app.tree.item.side_effect = fake_item
            app.tree.selection.return_value = ["row1"]
            app.tree.parent.return_value = "parent1"
            app.on_select()
            app.copy_value()
            app.clear_all()
            app.export_json()
            self.assertIsNone(app.result)
        finally:
            sys.modules.pop("tkinter", None)
            sys.modules.pop("domainscan.app", None)


class HashTest(unittest.TestCase):
    def test_murmur_vectors(self):
        self.assertEqual(helpers.murmur3_32(b""), 0)
        self.assertEqual(helpers.murmur3_32(b"hello"), 613153351)
        self.assertEqual(helpers.murmur3_32(b"hello"), helpers.murmur3_32("hello"))

    def test_favicon_hash(self):
        self.assertEqual(helpers.favicon_hash(b"\x00\x01\x02\x03\x04\x05"), 1045060958)
        value = helpers.favicon_hash(b"something")
        self.assertTrue(-2 ** 31 <= value < 2 ** 31)


class WhoisDateTest(unittest.TestCase):
    def test_parse_formats(self):
        first = whois_check.parse_date_flexible("1995-08-14T04:00:00Z")
        self.assertEqual((first.year, first.month, first.day), (1995, 8, 14))
        second = whois_check.parse_date_flexible("2024-01-31")
        self.assertEqual((second.year, second.month, second.day), (2024, 1, 31))
        third = whois_check.parse_date_flexible("14-Aug-1995")
        self.assertEqual((third.year, third.month, third.day), (1995, 8, 14))
        self.assertIsNone(whois_check.parse_date_flexible("not a date"))

    def test_age_rows(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        created = (now - datetime.timedelta(days=3650)).strftime("%Y-%m-%d")
        expires = (now + datetime.timedelta(days=300)).strftime("%Y-%m-%d")
        data = rows_to_dict(whois_check.age_rows(created, expires))
        self.assertIn("days", data["Domain age"])
        self.assertIn("Expires in", data["Domain expiry"])
        past = (now - datetime.timedelta(days=10)).strftime("%Y-%m-%d")
        data = rows_to_dict(whois_check.age_rows(created, past))
        self.assertIn("Expired", data["Domain expiry"])


class DnsParseTest(unittest.TestCase):
    def test_parse_soa(self):
        rows = dns_check.parse_soa(["ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 3600"])
        data = rows_to_dict(rows)
        self.assertEqual(data["SOA primary NS"], "ns1.example.com.")
        self.assertEqual(data["SOA contact"], "admin@example.com")
        self.assertEqual(data["SOA serial"], "2024010101")
        self.assertEqual(dns_check.parse_soa([]), [])

    def test_parse_caa(self):
        rows = dns_check.parse_caa(['0 issue "letsencrypt.org"', '0 issuewild ";"'])
        data = rows_to_dict(rows)
        self.assertIn("letsencrypt.org", data["CAA policy 1"])
        self.assertIn("Yes", data["CAA restricts issuance"])
        rows = dns_check.parse_caa([])
        self.assertIn("No CAA records", rows[0][1])


class FakeSMTPServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def run(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(5)
            conn.sendall(b"220 fake.test ESMTP\r\n")
            data = conn.recv(1024)
            if b"EHLO" in data.upper():
                conn.sendall(b"250-fake.test\r\n250-STARTTLS\r\n250 HELP\r\n")
            try:
                conn.recv(1024)
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        finally:
            try:
                self.sock.close()
            except Exception:
                pass


class MailExtraTest(unittest.TestCase):
    def test_spf_lookups(self):
        tokens = ["include:_spf.google.com", "ip4:192.0.2.0/24", "mx", "~all"]
        self.assertEqual(mail_check.spf_lookups(tokens), 2)
        rows = mail_check.describe_spf(["v=spf1 " + " ".join(tokens)])
        data = rows_to_dict(rows)
        self.assertEqual(data["SPF DNS lookups"], "2 of max 10")

    def test_tlsrpt(self):
        resolver = FakeResolver({("_smtp._tls.example.com", "TXT"): ['"v=TLSRPTv1; rua=mailto:x@y"']})
        rows = mail_check.describe_tlsrpt(resolver, "example.com")
        self.assertIn("TLSRPTv1", rows[0][1])

    def test_autoconfig(self):
        resolver = FakeResolver({("autodiscover.example.com", "A"): ["192.0.2.10"]})
        rows = mail_check.describe_autoconfig(resolver, "example.com")
        data = rows_to_dict(rows)
        self.assertEqual(data["autodiscover.example.com"], "192.0.2.10")
        self.assertEqual(data["autoconfig.example.com"], "No A record")

    def test_starttls_offered(self):
        server = FakeSMTPServer()
        server.start()
        try:
            self.assertEqual(mail_check.smtp_starttls("127.0.0.1", port=server.port), "Offered")
        finally:
            server.join(timeout=5)

    def test_starttls_unreachable(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        self.assertEqual(mail_check.smtp_starttls("127.0.0.1", port=port), "Unreachable")


HTML2 = """<html><head><title>T2</title>
<meta name="description" content="abcdefghijklmnopqrstuvwxyz0123">
<meta property="og:title" content="T2"><meta property="og:type" content="website">
<link rel="canonical" href="https://example.com/t2">
<link rel="alternate" hreflang="en" href="https://example.com/t2">
<link rel="alternate" hreflang="tr" href="https://example.com/tr/t2">
</head><body>
<!-- TODO: remove debug key, password=123 -->
<form action="https://evil.example/collect" method="post"><input type="password" name="p"></form>
<img src="http://cdn.example/pic.png">
<script>fetch("/api/users");var x="/static/app.js";</script>
<button onclick="go()">Go</button>
</body></html>"""


class ContentExtraTest(unittest.TestCase):
    def test_deep_rows(self):
        result = content_check.collect(HTML2, "https://example.com/t2", {}, [])
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["Password fields"], "1")
        self.assertEqual(data["External form targets"], "1")
        self.assertIn("evil.example", data["External form 1"])
        self.assertEqual(data["Mixed content refs"], "1")
        self.assertEqual(data["HTML comments"], "1")
        self.assertIn("password", data["Comment keywords"])
        self.assertEqual(data["JS paths (inline)"], "2")
        self.assertEqual(data["Inline event handlers"], "1")
        self.assertEqual(data["Canonical URL"], "https://example.com/t2")
        self.assertEqual(data["Hreflang count"], "2")
        self.assertEqual(data["Hreflang langs"], "en, tr")
        self.assertEqual(data["OG completeness"], "2 of 4")
        self.assertEqual(data["Description length"], "30 characters")


class ReputationParseTest(unittest.TestCase):
    def test_listed_and_clean(self):
        resolver = FakeResolver({("34.216.184.93.zen.spamhaus.org", "A"): ["127.0.0.4"]})
        rows = reputation_check.collect(["93.184.216.34"], resolver=resolver)["rows"]
        data = rows_to_dict(rows)
        self.assertIn("Listed", data["93.184.216.34 on Spamhaus ZEN"])
        self.assertIn("XBL", data["93.184.216.34 on Spamhaus ZEN"])
        self.assertEqual(data["93.184.216.34 on SpamCop"], "Clean")
        self.assertEqual(data["DNSBL listings"], "1 of 7 checks")


class BgpParseTest(unittest.TestCase):
    def test_parsers(self):
        rows = []
        asn = bgp_check.parse_ip_info({"prefix": "93.184.216.0/24", "asn": 15133, "name": "EDGECAST", "country_code": "US"}, "93.184.216.34", rows)
        self.assertEqual(asn, 15133)
        data = rows_to_dict(rows)
        self.assertEqual(data["93.184.216.34 prefix"], "93.184.216.0/24")
        self.assertEqual(data["93.184.216.34 origin ASN"], "AS15133")
        bgp_check.parse_asn_info({"ipv4_prefixes": [{}, {}], "ipv6_prefixes": [{}]}, 15133, rows)
        data = rows_to_dict(rows)
        self.assertEqual(data["AS15133 IPv4 prefixes"], "2")
        bgp_check.parse_peers([{"asn": 6939, "name": "Hurricane Electric", "country_code": "US"}], 15133, rows)
        data = rows_to_dict(rows)
        self.assertEqual(data["AS15133 peer count"], "1")
        self.assertIn("AS6939", data["AS15133 peer 1"])


class HistoryParseTest(unittest.TestCase):
    def test_available(self):
        data = {"archived_snapshots": {"closest": {"url": "http://web.archive.org/web/20240101120000/https://example.com/", "timestamp": "20240101120000", "status": "200"}}}
        rows = history_check.parse_available(data)
        parsed = rows_to_dict(rows)
        self.assertEqual(parsed["Latest snapshot"], "2024-01-01 12:00:00 (HTTP 200)")
        rows = history_check.parse_available({})
        self.assertIn("No snapshots", rows[0][1])

    def test_first_and_years(self):
        rows = history_check.parse_first([["timestamp", "original", "statuscode"], ["20020101000000", "http://example.com/", "200"]])
        self.assertIn("2002-01-01 00:00:00", rows[0][1])
        rows = history_check.parse_years([["timestamp"], ["20200101000000"], ["20210101000000"], ["20210601000000"]])
        data = rows_to_dict(rows)
        self.assertEqual(data["Archived years"], "2")
        self.assertEqual(data["Active years"], "2020, 2021")
        self.assertEqual(history_check.format_timestamp("20240101120000"), "2024-01-01 12:00:00")
        self.assertEqual(history_check.format_timestamp(""), "Unknown date")


class SubdomainParseTest(unittest.TestCase):
    def test_crt(self):
        certs, names, wild = subdomain_check.parse_crt([{"name_value": "a.example.com\n*.example.com\n"}, {"name_value": "b.example.com"}])
        self.assertEqual(certs, 2)
        self.assertEqual(names, {"a.example.com", "b.example.com"})
        self.assertEqual(wild, 1)

    def test_sonar(self):
        self.assertEqual(subdomain_check.parse_sonar(["X.EXAMPLE.COM ", ""]), {"x.example.com"})

    def test_hostsearch(self):
        text = "c.example.com,1.2.3.4\nerror limit reached\nbad line\n"
        self.assertEqual(subdomain_check.parse_hostsearch(text), {"c.example.com"})

    def test_takeover_match(self):
        self.assertTrue(subdomain_check.is_takeover_candidate("x.github.io"))
        self.assertTrue(subdomain_check.is_takeover_candidate("github.io"))
        self.assertFalse(subdomain_check.is_takeover_candidate("example.com"))
        self.assertFalse(subdomain_check.is_takeover_candidate("notgithub.io.evil.com"))


class CookieFlagTest(unittest.TestCase):
    def test_parse(self):
        info = http_check.parse_set_cookie("a=1; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(info["name"], "a")
        self.assertTrue(info["secure"])
        self.assertTrue(info["httponly"])
        self.assertEqual(info["samesite"], "Lax")
        info = http_check.parse_set_cookie("b=2")
        self.assertFalse(info["secure"])
        self.assertFalse(info["httponly"])

    def test_rows(self):
        rows = http_check.cookie_flag_rows(["a=1; Secure; HttpOnly", "b=2"])
        data = rows_to_dict(rows)
        self.assertEqual(data["Cookies missing Secure"], "1")
        self.assertEqual(data["Cookies missing HttpOnly"], "1")


class WebExtraLocalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), LocalHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_collect(self):
        headers = {"Alt-Svc": 'h3=":443"; ma=86400'}
        result = web_extra_check.collect(self.base, headers, timeout=5)
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["OPTIONS status"], "200")
        self.assertEqual(data["Allowed methods"], "GET, HEAD, OPTIONS")
        self.assertEqual(data["PUT status"], "501")
        self.assertIn("Disabled or blocked", data["TRACE method"])
        self.assertIn("Yes", data["HTTP/3 advertised"])
        self.assertEqual(data["404 probe status"], "404")
        self.assertEqual(data["404 handling"], "Standard 404 page")
        self.assertEqual(data["/.git/HEAD"], "Not found")
        self.assertEqual(data["IPv6 web"], "No AAAA record")

    def test_pure_helpers(self):
        self.assertIn("Yes", web_extra_check.parse_alt_svc('h3=":443"; ma=86400'))
        self.assertIn("No", web_extra_check.parse_alt_svc(""))
        self.assertIn("EXPOSED", web_extra_check.verdict_sensitive(200, "ref: refs/heads/main", "ref:"))
        self.assertEqual(web_extra_check.verdict_sensitive(404, "", None), "Not found")
        self.assertIn("Protected", web_extra_check.verdict_sensitive(403, "", None))

    def test_favicon_hash_row(self):
        result = files_check.collect(self.base, timeout=5)
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["Favicon hash"], "1045060958 (Shodan-compatible)")


class TlsProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "key.pem", "-out", "cert.pem", "-days", "2", "-nodes", "-subj", "/CN=localhost"], cwd=cls.tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=True)
        cls.proc = subprocess.Popen(["openssl", "s_server", "-accept", "127.0.0.1:18444", "-cert", "cert.pem", "-key", "key.pem", "-quiet"], cwd=cls.tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                sock = socket.create_connection(("127.0.0.1", 18444), timeout=1)
                sock.close()
                break
            except Exception:
                time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not available")
    def test_probes(self):
        result = http_check.collect_tls("127.0.0.1", 18444)
        data = rows_to_dict(result["rows"])
        self.assertIn("ALPN protocol", data)
        self.assertIn("Legacy TLS", data)
        self.assertIn("TLS 1.3", data)
        self.assertIn("HTTP/2", data)


class PingTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ping"), "ping not available")
    def test_localhost(self):
        result = network_check.ping("127.0.0.1")
        self.assertTrue("Reply" in result or "No reply" in result)


class NoSitemapHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        host = self.headers.get("Host", "localhost")
        if self.path == "/robots.txt":
            body = ("User-agent: *\nSitemap: http://" + host + "/custom-sitemap.xml\n").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/custom-sitemap.xml":
            body = b'<urlset><url><loc>http://localhost/only</loc></url></urlset>'
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/security.txt":
            body = b"Contact: mailto:root@example.com\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


class LocalBase(unittest.TestCase):
    handler = LocalHandler

    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), cls.handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()


class ProfileTest(unittest.TestCase):
    def test_profiles(self):
        self.assertIn("Deep", profiles.profile_names())
        self.assertEqual(profiles.get_profile("Quick")["crawl_pages"], 0)
        self.assertEqual(profiles.get_profile("Deep")["subdomain_web"], 40)
        self.assertEqual(profiles.get_profile("Nope")["timeout"], 12)


class HistoryStoreTest(unittest.TestCase):
    def make_result(self, stamp, extra=None):
        sections = {"Target": [("Host", "example.com")], "DNS": [("A record 1", "93.184.216.34")]}
        if extra:
            sections["DNS"].append(extra)
        return {
            "target": {"host": "example.com"},
            "sections": sections,
            "meta": {"version": "1.2.0", "duration_seconds": 1.0, "scanned_at": stamp, "findings": 2},
        }

    def test_save_list_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.make_result("2026-01-01 00:00:00 UTC")
            path = history_store.save_run(first, tmp)
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(len(history_store.list_runs("example.com", tmp)), 1)
            loaded = history_store.load_run(path)
            self.assertEqual(loaded["sections"]["DNS"][0][1], "93.184.216.34")

    def test_previous_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            history_store.save_run(self.make_result("2026-01-01 00:00:00 UTC"), tmp)
            time.sleep(1.1)
            second = self.make_result("2026-01-02 00:00:00 UTC", ("AAAA record 1", "::1"))
            second["sections"]["Target"] = [("Host", "example.com"), ("Port", "443")]
            history_store.save_run(second, tmp)
            previous = history_store.previous_run("example.com", "2026-01-02 00:00:00 UTC", tmp)
            self.assertEqual(previous["meta"]["scanned_at"], "2026-01-01 00:00:00 UTC")
            rows = history_store.diff_runs(previous, second)
            data = rows_to_dict(rows)
            self.assertEqual(data["Added"], "2")


class ExportHtmlTest(unittest.TestCase):
    def test_html(self):
        result = {
            "target": {"host": "example.com"},
            "sections": {"DNS": [("Note", "<script>alert(1)</script>")]},
            "meta": {"version": "1.2.0", "duration_seconds": 1.0, "scanned_at": "now", "findings": 1},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.html")
            helpers.export_html(path, result)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("<table>", text)
            self.assertIn("&lt;script&gt;", text)
            self.assertNotIn("<script>alert", text)


class CrawlTest(LocalBase):
    def test_crawl(self):
        result = crawl_check.collect(self.base + "/", timeout=5, max_pages=10)
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["Pages crawled"], "4")
        self.assertEqual(data["Broken pages"], "1")
        broken = [value for key, value in result["rows"] if key == "Broken"]
        self.assertTrue(any("/missing" in value for value in broken))

    def test_disabled(self):
        result = crawl_check.collect(self.base + "/", timeout=5, max_pages=0)
        self.assertIn("Skipped", result["rows"][0][1])


class JsAnalysisTest(LocalBase):
    def test_secrets_and_endpoints(self):
        html = '<script src="/app.js"></script><script>var g="AIza' + "A" * 35 + '";</script>'
        result = js_check.collect(self.base + "/", html, timeout=5, max_files=4)
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["External scripts found"], "1")
        self.assertIn("2", data["JS files analyzed"])
        self.assertIn("/api/v2/items", data["JS endpoint 1"])
        self.assertEqual(data["Possible secrets"], "2")


class ApiDiscoveryTest(LocalBase):
    def test_apis(self):
        import requests
        session = requests.Session()
        rows = web_extra_check.api_discovery(session, self.base, timeout=5)
        data = rows_to_dict(rows)
        self.assertIn("https://auth.local", data["API /.well-known/openid-configuration"])
        self.assertIn("likely", data["API /graphql"])
        self.assertEqual(data["API /api"], "HTTP 404")


class CorsFramingTest(unittest.TestCase):
    def test_cors_verdict(self):
        self.assertEqual(web_extra_check.cors_verdict("", ""), "No CORS reflection")
        self.assertEqual(web_extra_check.cors_verdict("*", ""), "Allows any origin (*)")
        self.assertIn("misconfigured", web_extra_check.cors_verdict("https://evil.example", ""))
        verdict = web_extra_check.cors_verdict("https://a.com", "Origin")
        self.assertIn("Vary", verdict)

    def test_framing(self):
        self.assertIn("DENY", web_extra_check.framing_verdict({"X-Frame-Options": "DENY"}))
        self.assertIn("frame-ancestors", web_extra_check.framing_verdict({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}))
        self.assertIn("allowed", web_extra_check.framing_verdict({}))

    def test_waf_signature(self):
        self.assertEqual(web_extra_check.waf_signature({"CF-Ray": "x"}, ""), "Cloudflare")
        self.assertEqual(web_extra_check.waf_signature({"Server": "Sucuri/Cloudproxy"}, ""), "Sucuri")
        self.assertEqual(web_extra_check.waf_signature({}, ""), "")

    def test_openid_graphql(self):
        self.assertIn("issuer", web_extra_check.parse_openid('{"issuer": "https://a.local"}'))
        self.assertIn("not valid", web_extra_check.parse_openid("nope"))
        self.assertIn("likely", web_extra_check.graphql_hint(400, '{"errors": []}', "application/json"))


class MtaStsDaneTest(LocalBase):
    def test_policy(self):
        rows = mail_check.describe_mta_sts_policy("example.com", self.base)
        data = rows_to_dict(rows)
        self.assertEqual(data["MTA-STS policy"], "Published")
        self.assertEqual(data["MTA-STS mode"], "enforce")
        self.assertEqual(data["MTA-STS MX patterns"], "1")

    def test_dane(self):
        resolver = FakeResolver({("_25._tcp.mail.example.com", "TLSA"): ["3 1 1 abc"]})
        self.assertIn("published", mail_check.dane_status(resolver, "mail.example.com"))
        self.assertEqual(mail_check.dane_status(FakeResolver({}), "mail.example.com"), "No TLSA record")


class PortsWebTest(LocalBase):
    def test_web_probe(self):
        detail = ports_check.probe_web_port("127.0.0.1", self.port)
        self.assertIn("200", detail)
        self.assertIn("Local", detail)


class CnameFollowTest(unittest.TestCase):
    def test_chain(self):
        resolver = FakeResolver({("a", "CNAME"): ["b."], ("b", "CNAME"): ["c."]})
        self.assertEqual(dns_check.follow_cname(resolver, "a"), ["b", "c"])
        self.assertEqual(dns_check.follow_cname(FakeResolver({}), "a"), [])


OPENSSL_SAMPLE = """ 0 s:CN = example.com
   i:C = US, O = Test CA, CN = Test Root
 1 s:C = US, O = Test CA, CN = Test Root
   i:C = US, O = Test CA, CN = Test Root
-----BEGIN CERTIFICATE-----
AAA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
BBB
-----END CERTIFICATE-----
Verify return code: 0 (ok)
"""


class OpensslParseTest(unittest.TestCase):
    def test_chain(self):
        rows = http_check.parse_openssl_chain(OPENSSL_SAMPLE)
        data = rows_to_dict(rows)
        self.assertEqual(data["Chain depth"], "2 certificates")
        self.assertEqual(data["Chain subject 1"], "CN = example.com")
        self.assertEqual(data["Chain verify"], "0 (ok)")

    def test_empty(self):
        rows = http_check.parse_openssl_chain("nope")
        self.assertIn("No certificates", rows[0][1])

    def test_weak_cipher(self):
        accepted = "New, TLSv1.2, Cipher is DES-CBC3-SHA\nCipher    : DES-CBC3-SHA\n"
        self.assertIn("ACCEPTED", http_check.parse_weak_cipher_output(accepted))
        self.assertEqual(http_check.parse_weak_cipher_output("Cipher is (NONE)"), "Rejected (good)")
        self.assertEqual(http_check.parse_weak_cipher_output("error: handshake failure"), "Rejected (good)")


HTML3 = """<html><head><title>L</title>
<script type="application/ld+json">{"@type": "Organization", "name": "Acme"}</script>
</head><body>
<form action="/login" method="post"><input name="username"><input type="password" name="pw"></form>
<form action="/search"><input name="q"></form>
</body></html>"""


class ContentLoginTest(unittest.TestCase):
    def test_login_and_jsonld(self):
        result = content_check.collect(HTML3, "https://example.com/", {}, [])
        data = rows_to_dict(result["rows"])
        self.assertEqual(data["Login forms"], "1")
        self.assertEqual(data["Login form 1"], "/login")
        self.assertEqual(data["JSON-LD blocks"], "1")
        self.assertEqual(data["Schema types"], "Organization")


class TechCmsTest(unittest.TestCase):
    def test_markers(self):
        html = '<link href="/load.php?x">moodle xenforo typo3 opencart preact'
        found = content_check.detect_tech(html, {}, [], {})
        data = rows_to_dict(found)
        self.assertIn("Tech: MediaWiki", data)
        self.assertIn("Tech: Moodle", data)
        self.assertIn("Tech: XenForo", data)
        self.assertIn("Tech: TYPO3", data)
        self.assertIn("Tech: OpenCart", data)
        self.assertIn("Tech: Preact", data)


class FilesFallbackTest(LocalBase):
    handler = NoSitemapHandler

    def test_fallbacks(self):
        result = files_check.collect(self.base, timeout=5)
        data = rows_to_dict(result["rows"])
        self.assertIn("Present", data["sitemap (robots)"])
        self.assertEqual(data["Sitemap URL count"], "1")
        self.assertIn("Present", data["security.txt (root)"])


class SubdomainProbeTest(LocalBase):
    def test_fetch_page(self):
        info = subdomain_check.fetch_subdomain_page(self.base + "/")
        self.assertEqual(info["status"], 200)
        self.assertEqual(info["title"], "Local")


class ZAppWiringTest(unittest.TestCase):
    def test_profile_compare_export(self):
        from unittest import mock
        fake_tkinter = mock.MagicMock()
        sys.modules["tkinter"] = fake_tkinter
        sys.modules.pop("domainscan.app", None)
        try:
            from domainscan import app as app_module
            root = mock.MagicMock()
            app = app_module.DomainScanApp(root)
            app.profile_box.get.return_value = "Quick"
            app.on_profile()
            self.assertEqual(app.caps["crawl_pages"], 0)
            app.tree.get_children.return_value = []
            app.search_entry.get.return_value = ""
            app.section_box.get.return_value = "All sections"
            result = {
                "target": {"host": "example.com"},
                "sections": {"Target": [("Host", "example.com")]},
                "meta": {"version": "1.2.0", "duration_seconds": 1.0, "scanned_at": "new", "findings": 1},
            }
            with mock.patch.object(app_module.history_store, "save_run", return_value="x"):
                app.finish_scan(result)
            old = {
                "target": {"host": "example.com"},
                "sections": {"Target": []},
                "meta": {"version": "1.2.0", "duration_seconds": 1.0, "scanned_at": "old", "findings": 0},
            }
            with mock.patch.object(app_module.history_store, "previous_run", return_value=old):
                app.compare_scan()
            self.assertIn("Changes", app.result["sections"])
            self.assertEqual(app.section_box.set.call_args[0][0], "Changes")
            with mock.patch.object(app_module.history_store, "previous_run", return_value=None):
                app.compare_scan()
            app_module.filedialog.asksaveasfilename.return_value = ""
            app.export_html()
        finally:
            sys.modules.pop("tkinter", None)
            sys.modules.pop("domainscan.app", None)


if __name__ == "__main__":
    unittest.main()


class RdapBootstrapTests(unittest.TestCase):
    def test_find_dns_service(self):
        data = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]}
        self.assertEqual(rdap_check.find_services(data, "dns", "com"), ["https://rdap.verisign.com/com/v1/"])

    def test_find_ipv4_service(self):
        data = {"services": [[["1.0.0.0/8"], ["https://rdap.apnic.net/"]]]}
        self.assertEqual(rdap_check.find_services(data, "ipv4", "1.2.3.4"), ["https://rdap.apnic.net/"])

    def test_no_match_returns_empty(self):
        data = {"services": [[["zz"], ["https://example.invalid/"]]]}
        self.assertEqual(rdap_check.find_services(data, "dns", "com"), [])


class RdapParseTests(unittest.TestCase):
    def test_domain_payload(self):
        payload = {
            "handle": "H1", "ldhName": "example.com", "port43": "whois.example",
            "status": ["clientTransferProhibited https://icann.org/epp"], 
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "ns1.example.com", "ipAddresses": {"v4": ["1.2.3.4"]}}],
            "secureDNS": {"delegationSigned": True},
            "entities": [{"roles": ["registrar"], "handle": "R1",
                          "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"],
                                                   ["email", {}, "text", "abuse@example.com"]]]}],
        }
        rows = whois_check.parse_rdap(payload)
        by_key = {key: value for key, value in rows}
        self.assertEqual(by_key["Domain name"], "example.com")
        self.assertIn("locked against transfer", by_key["Status 1"])
        self.assertEqual(by_key["Nameserver 1"], "ns1.example.com")
        self.assertEqual(by_key["DNSSEC delegation"], "Signed")
        self.assertEqual(by_key["Registrar email"], "abuse@example.com")
        self.assertIn("years", by_key["Domain age"])
        self.assertIn("Expires in", by_key["Domain expiry"])

    def test_ip_payload(self):
        payload = {"handle": "NET-1", "name": "TEST-NET", "country": "US",
                   "startAddress": "192.0.2.0", "endAddress": "192.0.2.255",
                   "cidr0_cidrs": [{"v4prefix": "192.0.2.0/24"}],
                   "status": ["active"],
                   "entities": [{"roles": ["administrative"],
                                 "vcardArray": ["vcard", [["email", {}, "text", "noc@example.net"]]]}]}
        rows = whois_check.parse_ip_rdap(payload)
        by_key = {key: value for key, value in rows}
        self.assertEqual(by_key["CIDR"], "192.0.2.0/24")
        self.assertEqual(by_key["Administrative email"], "noc@example.net")

    def test_whois_text_parser(self):
        text = ("Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
                "Creation Date: 2020-05-01T00:00:00Z\nRegistry Expiry Date: 2030-05-01T00:00:00Z\n"
                "Domain Status: clientTransferProhibited https://icann.org/epp\n"
                "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM\n"
                "Registrant Email: owner@example.com\nDNSSEC: signedDelegation\n")
        rows = whois_check.parse_whois_text(text)
        by_key = {key: value for key, value in rows}
        self.assertEqual(by_key["Registrar"], "Example Registrar, Inc.")
        self.assertIn("locked", by_key["Status 1"])
        self.assertEqual(by_key["Nameserver count"], "2")
        self.assertEqual(by_key["Registrant email"], "owner@example.com")
        self.assertIn("Expires in", by_key["Domain expiry"])

    def test_resolve_target(self):
        resolved = whois_check.resolve_whois_target("https://blog.example.co.uk/post")
        self.assertEqual(resolved["query"], "example.co.uk")
        self.assertIn("registrable", resolved["note"])
        resolved_ip = whois_check.resolve_whois_target("8.8.8.8")
        self.assertEqual(resolved_ip["kind"], "ip")

    def test_ns_describe_lame(self):
        from unittest.mock import patch
        with patch("domainscan.dns_check.query", return_value={"records": []}):
            rows = whois_check.describe_nameservers("example.com", ["ns1.example.com", "bad.example.net"])
        by_key = {key: value for key, value in rows}
        self.assertIn("lame", by_key["NS check: ns1.example.com"])
        self.assertIn("in-bailiwick", by_key["NS check: ns1.example.com"])


class CrossCheckTests(unittest.TestCase):
    def test_ns_consistency_match(self):
        rows = cross_check.ns_consistency(["NS1.Example.com."], ["ns1.example.com"])
        self.assertIn("Match", rows[0][1])

    def test_ns_consistency_mismatch(self):
        rows = cross_check.ns_consistency(["ns1.example.com"], ["ns9.example.com"])
        self.assertIn("Mismatch", rows[0][1])

    def test_dnssec_completeness(self):
        self.assertIn("Complete", cross_check.dnssec_completeness({"ds": ["x"], "dnskey": ["y"]})[0][1])
        self.assertIn("Unsigned", cross_check.dnssec_completeness({"ds": [], "dnskey": []})[0][1])

    def test_soa_serial(self):
        self.assertIn("2024-05-06", cross_check.soa_serial_verdict("ns1 host 2024050601 7200 3600 1209600 3600"))
        self.assertIn("Counter", cross_check.soa_serial_verdict("ns1 host 42 7200 3600 1209600 3600"))

    def test_spf_dmarc_parsers(self):
        self.assertEqual(cross_check.parse_spf_includes("v=spf1 include:_spf.google.com redirect=x.example ~all"),
                         ["_spf.google.com", "x.example"])
        self.assertEqual(cross_check.parse_dmarc_rua("v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.org"),
                         ["example.com", "example.org"])

    def test_cookie_security(self):
        rows = cross_check.cookie_security([{"name": "a", "secure": True}, {"name": "b", "secure": False}], True)
        self.assertIn("missing Secure", rows[0][1])
        self.assertIn("plain HTTP", cross_check.cookie_security([], False)[0][1])


class AccuracyPatchTests(unittest.TestCase):
    def test_ds_dnskey_parse(self):
        rows = dns_check.parse_ds(["12345 8 2 AABBCCDD"])
        self.assertIn("RSASHA256", rows[0][1])
        rows = dns_check.parse_dnskey(["257 3 8 AABBCC"])
        self.assertIn("KSK", rows[0][0])
        rows = dns_check.parse_dnskey(["256 3 13 AABBCC"])
        self.assertIn("ECDSAP256SHA256", rows[0][1])

    def test_clock_skew(self):
        import datetime as dt
        now = dt.datetime(2026, 6, 1, 12, 0, 0)
        self.assertIn("behind", http_check.clock_skew("Mon, 01 Jun 2026 11:59:00 GMT", now))
        self.assertIn("ahead", http_check.clock_skew("Mon, 01 Jun 2026 12:05:00 GMT", now))
        self.assertIn("No Date", http_check.clock_skew(""))

    def test_spf_issues(self):
        tokens = ["v=spf1", "ptr", "include:a.example"]
        issues = mail_check.spf_issues("v=spf1 ptr include:a.example", tokens, 3)
        joined = " ".join(issues)
        self.assertIn("no default all", joined)
        self.assertIn("ptr", joined)

    def test_prefix_size(self):
        self.assertEqual(bgp_check.prefix_size("192.0.2.0/24"), "256 addresses")
        self.assertEqual(bgp_check.prefix_size("1.2.3.4/32"), "1 address")
        self.assertTrue(bgp_check.prefix_size("2001:db8::/32").startswith("2^"))

    def test_ports_classify(self):
        import socket as sockmod
        self.assertEqual(ports_check.classify_error(ConnectionRefusedError()), "closed")
        self.assertEqual(ports_check.classify_error(sockmod.timeout()), "filtered")

    def test_subdomain_depths(self):
        depths = subdomain_check.subdomain_depths(["a.example.com", "b.a.example.com"], "example.com")
        self.assertEqual(depths, {1: 1, 2: 1})

    def test_wildcard_filter(self):
        from unittest.mock import patch
        def fake_query(resolver, name, rtype):
            if name == "real.example.com":
                return {"records": ["9.9.9.9"]}
            return {"records": ["5.5.5.5"]}
        with patch("domainscan.dns_check.query", side_effect=fake_query):
            confirmed, excluded = subdomain_check.verify_names(None, ["real.example.com", "fake.example.com"], 10, ["5.5.5.5"])
        self.assertEqual(list(confirmed), ["real.example.com"])
        self.assertEqual(excluded, 1)

    def test_network_helpers(self):
        self.assertIn("A and AAAA", network_check.dual_stack(["1.2.3.4", "2001:db8::1"]))
        self.assertTrue(network_check.routable("1.2.3.4"))
        self.assertFalse(network_check.routable("127.0.0.1"))
        self.assertIn("openstreetmap", network_check.map_link(41.0, 29.0))

    def test_idn_warning(self):
        info = helpers.parse_target("münchen.de")
        rows = helpers.describe_target(info)
        self.assertTrue(any("homograph" in value for key, value in rows if key == "IDN warning"))
        info2 = helpers.parse_target("example.com")
        rows2 = helpers.describe_target(info2)
        self.assertTrue(any(key == "IDN check" for key, value in rows2))


class SeoAuditTests(unittest.TestCase):
    def test_title_verdicts(self):
        from bs4 import BeautifulSoup
        short_soup = BeautifulSoup("<html><head><title>Hi</title></head></html>", "html.parser")
        self.assertIn("Short", rows_to_dict(seo_check.title_rows(short_soup))["Title verdict"])
        long_soup = BeautifulSoup("<html><head><title>" + "x" * 70 + "</title></head></html>", "html.parser")
        self.assertIn("Long", rows_to_dict(seo_check.title_rows(long_soup))["Title verdict"])
        good_soup = BeautifulSoup("<html><head><title>" + "x" * 45 + "</title></head></html>", "html.parser")
        self.assertEqual(rows_to_dict(seo_check.title_rows(good_soup))["Title verdict"], "Good length")

    def test_meta_robots_noindex(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><meta name="robots" content="noindex, nofollow"></head></html>', "html.parser")
        data = rows_to_dict(seo_check.meta_rows(soup))
        self.assertIn("noindex", data["Indexing"])

    def test_hreflang_default(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><link rel="alternate" hreflang="en" href="https://example.com/en"><link rel="alternate" hreflang="x-default" href="https://example.com/"></head></html>', "html.parser")
        data = rows_to_dict(seo_check.hreflang_rows(soup, 1))
        self.assertEqual(data["Hreflang tags"], "2")
        self.assertIn("present", data["Hreflang default"])

    def test_social_tags_missing(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><head></head></html>", "html.parser")
        data = rows_to_dict(seo_check.social_tag_rows(soup, 1))
        self.assertEqual(data["Open Graph tags"], "0 of 5")
        self.assertEqual(data["Twitter card"], "Missing")

    def test_heading_order(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><body><h1>Title</h1><h3>Skip</h3></body></html>", "html.parser")
        data = rows_to_dict(seo_check.heading_rows(soup))
        self.assertIn("skipped", data["Heading order"])
        self.assertEqual(data["H1 text"], "Title")


class A11yTests(unittest.TestCase):
    def test_missing_lang_and_alt(self):
        html = '<html><head><title>T</title></head><body><img src="a.png"><img src="b.png" alt=""></body></html>'
        data = rows_to_dict(a11y_check.collect(html)["rows"])
        self.assertIn("Missing", data["Page language"])
        self.assertEqual(data["Images without alt"], "1")
        self.assertEqual(data["Images with empty alt"], "1 (fine if decorative)")

    def test_unlabeled_fields(self):
        html = '<html><body><form><input type="text" name="q"><input type="text" aria-label="Search"></form></body></html>'
        data = rows_to_dict(a11y_check.collect(html)["rows"])
        self.assertEqual(data["Unlabeled fields"], "1")

    def test_empty_buttons_and_links(self):
        html = '<html><body><button></button><button aria-label="x"></button><a href="/x">click here</a></body></html>'
        data = rows_to_dict(a11y_check.collect(html)["rows"])
        self.assertEqual(data["Empty buttons"], "1")
        self.assertEqual(data["Generic link texts"], "1")

    def test_score_clean_page(self):
        html = '<html lang="en"><head><title>T</title></head><body><header></header><nav></nav><main><h1>T</h1><img src="a.png" alt="a"><a href="#main">Skip to content</a></main><footer></footer></body></html>'
        data = rows_to_dict(a11y_check.collect(html)["rows"])
        self.assertTrue(data["Accessibility score"].startswith("100/100"))


class PerfTests(unittest.TestCase):
    def test_verdicts_and_bytes(self):
        self.assertEqual(perf_check.verdict_ms(100, 800, 1800), "Good")
        self.assertEqual(perf_check.verdict_ms(900, 800, 1800), "Needs improvement")
        self.assertEqual(perf_check.verdict_ms(2000, 800, 1800), "Poor")
        self.assertEqual(perf_check.format_bytes(1536), "1.5 KB")
        self.assertEqual(perf_check.format_bytes(500), "500 bytes")

    def test_blocking_and_images(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><script src="a.js"></script><script src="b.js" defer></script><link rel="stylesheet" href="x.css"></head><body><img src="1.png" loading="lazy"><img src="2.png" width="1" height="1"></body></html>', "html.parser")
        data = rows_to_dict(perf_check.blocking_rows(soup))
        self.assertEqual(data["Blocking scripts in head"], "1")
        self.assertEqual(data["Deferred scripts in head"], "1")
        data = rows_to_dict(perf_check.image_perf_rows(soup))
        self.assertEqual(data["Lazy-loaded images"], "1 of 2")
        self.assertEqual(data["Images with dimensions"], "1 of 2 (prevents layout shift)")


class PrivacyTests(unittest.TestCase):
    def test_tracker_match(self):
        self.assertEqual(privacy_check.match_trackers({"www.google-analytics.com", "cdn.example.com"}), {"www.google-analytics.com": "Google Analytics"})

    def test_referrer_and_consent(self):
        data = rows_to_dict(privacy_check.referrer_rows({}))
        self.assertIn("Not set", data["Referrer-Policy"])
        data = rows_to_dict(privacy_check.consent_rows("<html>onetrust cookie consent</html>"))
        self.assertIn("Likely present", data["Consent banner"])

    def test_fingerprint_markers(self):
        html = '<script>var c = x.getContext("2d"); c.toDataURL(); new RTCPeerConnection();</script>'
        data = rows_to_dict(privacy_check.fingerprint_rows(html))
        self.assertEqual(data["Fingerprinting markers"], "2")


class WaybackParseTests(unittest.TestCase):
    def test_summarize(self):
        captures = [
            ["20200101120000", "http://example.com/", "200", "text/html", "A"],
            ["20210601120000", "http://example.com/admin/", "200", "text/html", "B"],
            ["20230601120000", "http://example.com/app.js", "200", "application/javascript", "C"],
        ]
        data = rows_to_dict(wayback_check.summarize(captures))
        self.assertEqual(data["Archived URLs"], "3 unique URLs")
        self.assertEqual(data["First capture"], "2020-01-01 12:00")
        self.assertIn("2023", data["Latest capture"])
        self.assertIn("admin", data["Archived path 1"])

    def test_stamp_helpers(self):
        self.assertEqual(wayback_check.format_stamp("20200101120000"), "2020-01-01 12:00")
        self.assertEqual(wayback_check.span_years("20200101120000", "20230101120000"), "About 3 years")


class CrtshParseTests(unittest.TestCase):
    def test_summarize(self):
        entries = [
            {"issuer_name": "CN=R3,O=Let's Encrypt,C=US", "not_before": "2023-01-01T00:00:00", "not_after": "2030-01-01T00:00:00", "name_value": "example.com\nwww.example.com"},
            {"issuer_name": "CN=R3,O=Let's Encrypt,C=US", "not_before": "2020-01-01T00:00:00", "not_after": "2020-04-01T00:00:00", "name_value": "*.example.com"},
        ]
        data = rows_to_dict(crtsh_check.summarize(entries, "example.com"))
        self.assertEqual(data["Certificates found"], "2 in CT logs")
        self.assertEqual(data["Distinct issuers"], "1")
        self.assertEqual(data["Expired certificates"], "1 of 2")
        self.assertIn("*.example.com", data["Wildcard certificates"])

    def test_issuer_and_precert(self):
        self.assertEqual(crtsh_check.parse_issuer("CN=R3,O=Let's Encrypt,C=US"), "R3")
        self.assertTrue(crtsh_check.is_precert({"extensions": "CT Poison"}))
        self.assertFalse(crtsh_check.is_precert({"extensions": "basicConstraints"}))


class TypoTests(unittest.TestCase):
    def test_variants(self):
        variants = typo_check.generate_variants("example.com")
        self.assertLessEqual(len(variants), 40)
        self.assertIn("exaple.com", variants)
        self.assertIn("example.net", variants)
        self.assertNotIn("example.com", variants)

    def test_probe_with_fake_dns(self):
        from unittest.mock import patch
        def fake_query(resolver, name, rtype):
            if name == "exaple.com":
                return {"records": ["9.9.9.9"]}
            return {"records": []}
        with patch("domainscan.dns_check.query", side_effect=fake_query):
            hits = typo_check.probe_variants(None, ["exaple.com", "examplle.com"])
        self.assertEqual(hits, [("exaple.com", ["9.9.9.9"])])


class ExposureTests(unittest.TestCase):
    def test_verdicts(self):
        class FakeResponse:
            def __init__(self, status, text):
                self.status_code = status
                self.text = text
                self.content = text.encode()
        exposed = exposure_check.verdict("/.git/config", "[core]", "critical", FakeResponse(200, "[core]\nrepo"))
        self.assertEqual(exposed[1], "exposed")
        clean = exposure_check.verdict("/.git/config", "[core]", "critical", FakeResponse(200, "<html>home</html>"))
        self.assertIsNone(clean)
        guarded = exposure_check.verdict("/console/", None, "medium", FakeResponse(401, "login"))
        self.assertEqual(guarded[1], "guarded")
        self.assertLess(exposure_check.rank("critical"), exposure_check.rank("high"))


class HttpDeepTests(unittest.TestCase):
    def test_csp_parse(self):
        data = rows_to_dict(http_check.parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline' *; report-uri /csp"))
        self.assertEqual(data["CSP directives"], "3")
        self.assertIn("unsafe-inline", data["CSP weaknesses"])
        self.assertEqual(data["CSP reporting"], "Configured")

    def test_permissions_link_timing(self):
        data = rows_to_dict(http_check.parse_permissions_policy("camera=(), geolocation=(self)"))
        self.assertEqual(data["Permissions features"], "2")
        self.assertEqual(data["Permissions disabled"], "camera")
        data = rows_to_dict(http_check.parse_link_header('</a.js>; rel=preload; as=script, </b>; rel=preconnect'))
        self.assertEqual(data["Link headers"], "2")
        self.assertIn("1 (", data["Link preload"])
        data = rows_to_dict(http_check.parse_server_timing("db;dur=53, cache;desc=hit"))
        self.assertIn("db=53ms", data["Server-Timing"])

    def test_x_header_inventory(self):
        data = rows_to_dict(http_check.x_header_inventory({"X-Custom": "1", "Content-Type": "x", "X-Frame-Options": "DENY"}))
        self.assertIn("X-Custom", data["Custom X- headers"])

    def test_cookie_prefixes(self):
        ok = http_check.cookie_prefix_rows(["__Host-id=1; Path=/; Secure"])
        self.assertIn("Valid", ok[0][1])
        bad = http_check.cookie_prefix_rows(["__Host-id=1; Path=/", "__Secure-x=1; Path=/", "a=1; SameSite=None"])
        joined = " ".join(value for _, value in bad)
        self.assertIn("Rejected", joined)

    def test_openssl_text_parse(self):
        sample = "Signature Algorithm: sha256WithRSAEncryption\nPublic-Key: (2048 bit)\nX509v3 Extended Key Usage: \nTLS Web Server Authentication\nCT Precertificate SCTs: \nSigned Certificate Timestamp:\nSigned Certificate Timestamp:\n"
        data = rows_to_dict(http_check.parse_openssl_text(sample))
        self.assertEqual(data["Signature algorithm"], "sha256WithRSAEncryption")
        self.assertEqual(data["Public key size"], "2048 bits")
        self.assertEqual(data["Embedded SCTs"], "2")
        self.assertEqual(data["OCSP Must-Staple"], "Not set")

    def test_http_version(self):
        class FakeRaw:
            version = 20
        class FakeResponse:
            raw = FakeRaw()
        self.assertEqual(http_check.http_version(FakeResponse()), "HTTP/2")


class DnsDeepTests(unittest.TestCase):
    def test_tlsa_sshfp_srv(self):
        data = rows_to_dict(dns_check.parse_tlsa(["3 1 1 AABBCCDDEE"]))
        self.assertIn("SHA-256", data["TLSA usage 3"])
        data = rows_to_dict(dns_check.parse_sshfp(["4 2 AABBCCDDEE"]))
        self.assertIn("Ed25519", data["SSHFP key"])
        data = rows_to_dict(dns_check.parse_srv(["0 5 443 example.com."]))
        self.assertIn("port 443", data["SRV service"])

    def test_svcb_and_loc(self):
        self.assertIn("priority 1", dns_check.describe_svcb('1 . alpn="h2" port="443"'))
        self.assertIn("alias to", dns_check.describe_svcb("0 pool.example.com."))
        coords = dns_check.decode_loc("51 30 0 N 0 7 0 W 10m")
        self.assertAlmostEqual(coords[0], 51.5)
        self.assertAlmostEqual(coords[1], -0.1166, places=3)
        self.assertIsNone(dns_check.decode_loc("not a loc record"))

    def test_soa_timers(self):
        data = rows_to_dict(dns_check.soa_timer_rows(["ns1 a 1 86400 7200 1209600 3600"]))
        self.assertEqual(data["SOA timers"], "Sane values")
        data = rows_to_dict(dns_check.soa_timer_rows(["ns1 a 1 100 200 1000 99999"]))
        self.assertIn("retry", data["SOA timers"])

    def test_ns_diversity(self):
        from unittest.mock import patch
        def fake_query(resolver, name, rtype):
            return {"records": ["192.0.2.1"] if "ns1" in name else ["192.0.2.2"]}
        with patch("domainscan.dns_check.query", side_effect=fake_query):
            data = rows_to_dict(dns_check.ns_diversity(None, ["ns1.example.com", "ns2.example.com"], "example.com"))
        self.assertEqual(data["NS count"], "2")
        self.assertIn("single point", data["NS diversity"].lower() + data.get("NS subnets", ""))


class MailDeepTests(unittest.TestCase):
    def test_parse_ehlo(self):
        greeting = "250-mail.example ESMTP\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10485760\r\n"
        extensions = mail_check.parse_ehlo(greeting)
        self.assertIn("STARTTLS", extensions)
        self.assertIn("AUTH PLAIN LOGIN", extensions)

    def test_private_ip(self):
        self.assertTrue(mail_check.is_private_ip("10.0.0.5"))
        self.assertTrue(mail_check.is_private_ip("172.20.1.1"))
        self.assertFalse(mail_check.is_private_ip("8.8.8.8"))
        self.assertFalse(mail_check.is_private_ip("not-an-ip"))

    def test_mx_health_dup_prefs(self):
        rows = mail_check.mx_health([("10", "mx1.example.com"), ("10", "mx2.example.com")], None)
        self.assertIn("Duplicate", rows[0][1])

    def test_dmarc_external_auth(self):
        from unittest.mock import patch
        with patch("domainscan.dns_check.query", return_value={"records": []}):
            rows = mail_check.dmarc_external_auth(None, "example.com", "mailto:reports@example.com,mailto:x@external.net")
        self.assertEqual(len(rows), 1)
        self.assertIn("Missing authorization", rows[0][1])

    def test_bimi_logo_rows(self):
        self.assertEqual(mail_check.bimi_logo_rows("v=BIMI1"), [])
        rows = mail_check.bimi_logo_rows("v=BIMI1; l=http://example.com/logo.svg")
        self.assertIn("Not HTTPS", rows[1][1])


class ContentDeepTests(unittest.TestCase):
    def test_sri_and_jquery(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><script src="a.js" integrity="sha384-x"></script><script src="b.js"></script></head></html>', "html.parser")
        data = rows_to_dict(content_check.sri_rows(soup))
        self.assertEqual(data["Scripts with integrity"], "1 of 2")
        self.assertIn("1 scripts lack", data["SRI gap (JS)"])
        jquery_soup = BeautifulSoup('<html><head><script src="jquery-2.2.4.min.js"></script></head></html>', "html.parser")
        data = rows_to_dict(content_check.jquery_rows(jquery_soup, "/*! jQuery JavaScript Library v2.2.4 */"))
        self.assertEqual(data["jQuery version"], "2.2.4")
        self.assertIn("end-of-life", data["jQuery verdict"])

    def test_form_security(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><body><form action="http://evil.example/" method="get"><input type="password" name="p"><input type="file" name="f"></form></body></html>', "html.parser")
        data = rows_to_dict(content_check.form_security_rows(soup.find_all("form"), "https://example.com/"))
        self.assertIn("credentials in URL", data["Password over GET"])
        self.assertEqual(data["File upload forms"], "1")
        self.assertEqual(data["Forms to plain HTTP"], "1")

    def test_traces_dom_pwa(self):
        data = rows_to_dict(content_check.trace_rows("<html>Fatal error: oops ORA-1234</html>"))
        self.assertIn("PHP fatal error", data["Error disclosure"])
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><body><div><p>x</p></div></body></html>", "html.parser")
        data = rows_to_dict(content_check.dom_rows(soup))
        self.assertEqual(data["DOM elements"], "4")
        data = rows_to_dict(content_check.pwa_rows(soup, "navigator.serviceWorker.register()"))
        self.assertIn("Registration code", data["Service worker"])

    def test_new_markers(self):
        html = '<html><div x-data="{}">htmx tailwind <script src="https://unpkg.com/alpinejs"></script></html>'
        found = dict(content_check.detect_tech(html, {}, [], {}))
        self.assertIn("Tech: Alpine.js", found)
        self.assertIn("Tech: htmx", found)
        self.assertIn("Tech: Tailwind CSS", found)


class FilesDeepTests(unittest.TestCase):
    def test_interesting_disallows(self):
        found = files_check.find_interesting_disallows(["Disallow: /admin/", "Disallow: /images/"])
        self.assertEqual(found, ["/admin/"])

    def test_security_expiry(self):
        self.assertIn("Valid", files_check.security_expiry("2999-01-01T00:00:00Z"))
        self.assertIn("Expired", files_check.security_expiry("2000-01-01T00:00:00Z"))
        self.assertIn("Unparseable", files_check.security_expiry("tomorrow"))

    def test_parse_ads(self):
        result = {"ok": True, "text": "google.com, pub-1, DIRECT\nopenx.com, 111, RESELLER\nCONTACT=ads@example.com\n"}
        data = rows_to_dict(files_check.parse_ads(result))
        self.assertIn("2 entries", data["ads.txt"])
        self.assertIn("1 DIRECT", data["ads.txt relationships"])

    def test_parse_crossdomain(self):
        result = {"ok": True, "size": 99, "text": '<cross-domain-policy><allow-access-from domain="*" secure="false"/></cross-domain-policy>'}
        data = rows_to_dict(files_check.parse_crossdomain(result))
        self.assertIn("Wildcard", data["crossdomain.xml policy"])
        self.assertIn("plain HTTP", data["crossdomain.xml transport"])

    def test_cms_parsers(self):
        self.assertEqual(files_check.parse_wp_readme("<title>WordPress 6.4.1</title>"), "6.4.1")
        self.assertEqual(files_check.parse_drupal_changelog("Drupal 10.2.0, 2023-12-06"), "10.2.0")
        self.assertEqual(files_check.parse_wp_readme("<html>nothing</html>"), "")

    def test_openid_config(self):
        data = rows_to_dict(files_check.parse_openid_config('{"issuer": "https://auth.example.com", "grant_types_supported": ["code"]}'))
        self.assertIn("auth.example.com", data["OpenID issuer"])


class WebExtraDeepTests(unittest.TestCase):
    def test_cdn_rows(self):
        data = rows_to_dict(web_extra_check.cdn_rows({"CF-Ray": "abc", "Age": "12"}))
        self.assertIn("Cloudflare", data["CDN detected"])
        self.assertIn("12s", data["Cache age"])

    def test_swagger_and_wpjson(self):
        hint = web_extra_check.swagger_hint('{"openapi": "3.0.0", "info": {"title": "Pet"}, "paths": {"/a": {}, "/b": {}}}')
        self.assertIn("3.0.0", hint)
        self.assertIn("2 paths", hint)
        hint = web_extra_check.wpjson_hint('{"name": "Blog", "namespaces": ["wp/v2", "oembed/1.0"]}')
        self.assertIn("2 namespaces", hint)


class ReputationDomainTests(unittest.TestCase):
    def test_domain_blocklists(self):
        resolver = FakeResolver({("example.com.multi.surbl.org", "A"): ["127.0.0.4"]})
        rows = reputation_check.domain_blocklists("example.com", resolver)
        data = rows_to_dict(rows)
        self.assertIn("Listed", data["example.com on SURBL multi"])
        self.assertEqual(data["example.com on Spamhaus DBL"], "Clean")
        self.assertEqual(data["Domain listings"], "1 of 3")


class JsDeepTests(unittest.TestCase):
    def test_frameworks_versions_sinks(self):
        texts = [("a.js", "webpack react-dom jQuery JavaScript Library v1.12.4 eval(x); document.write(y);")]
        data = rows_to_dict(js_check.framework_rows(texts))
        self.assertIn("webpack", data["JS frameworks"])
        self.assertIn("React", data["JS frameworks"])
        data = rows_to_dict(js_check.library_version_rows(texts))
        self.assertEqual(data["JS library: jQuery"], "1.12.4")
        data = rows_to_dict(js_check.danger_rows(texts))
        self.assertEqual(data["Dangerous sinks"], "2")

    def test_sourcemap_none(self):
        import requests
        rows = js_check.sourcemap_rows(requests.Session(), [("(inline scripts)", "var a = 1;")], 2)
        self.assertEqual(rows[0][1], "None referenced")


class PortsDeepTests(unittest.TestCase):
    def test_banner_verdicts(self):
        data = rows_to_dict(ports_check.banner_verdict(22, "SSH-2.0-OpenSSH_9.3"))
        self.assertEqual(data["SSH version"], "9.3")
        self.assertNotIn("SSH verdict", data)
        data = rows_to_dict(ports_check.banner_verdict(3306, "J\x00\x00\x008.0.33-mysql-native"))
        self.assertEqual(data["MySQL version"], "8.0.33")

    def test_tls_detect_plaintext(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        def accept():
            try:
                conn, _ = server.accept()
                time.sleep(1.5)
                conn.close()
            except Exception:
                pass
        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        try:
            self.assertIn("Plaintext", ports_check.tls_detect("127.0.0.1", port, timeout=3))
        finally:
            server.close()

    def test_udp_probe_open(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        got = []
        def reply():
            try:
                server.settimeout(5)
                data, addr = server.recvfrom(512)
                got.append(data)
                server.sendto(data[:2] + b"\x81\x80" + data[4:], addr)
            except Exception:
                pass
        thread = threading.Thread(target=reply, daemon=True)
        thread.start()
        real_probe = ports_check.udp_dns_probe
        import random
        ident = random.randint(1, 65535)
        packet = ident.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4)
        try:
            sock.sendto(packet, ("127.0.0.1", port))
            data, _ = sock.recvfrom(512)
            self.assertEqual(data[:2], ident.to_bytes(2, "big"))
        finally:
            sock.close()
            server.close()
        self.assertTrue(got)

    def test_ftp_anonymous_allowed(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        def serve():
            try:
                conn, _ = server.accept()
                conn.settimeout(5)
                conn.sendall(b"220 Test FTP\r\n")
                conn.recv(256)
                conn.sendall(b"331 Need password\r\n")
                conn.recv(256)
                conn.sendall(b"230 Logged in\r\n")
                time.sleep(0.5)
                conn.close()
            except Exception:
                pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        import domainscan.ports_check as ports_module
        real_create = socket.create_connection
        def fake_create(address, timeout=None, *args, **kwargs):
            return real_create(("127.0.0.1", port), timeout=timeout)
        with patch("socket.create_connection", side_effect=fake_create):
            verdict = ports_module.ftp_anonymous("anything.example", timeout=4)
        server.close()
        self.assertIn("ALLOWED", verdict)


class CrossDeepTests(unittest.TestCase):
    def test_caa_issuer(self):
        rows = cross_check.caa_issuer_rows("Let's Encrypt", ['0 issue "letsencrypt.org"'])
        self.assertIn("Consistent", rows[0][1])
        rows = cross_check.caa_issuer_rows("DigiCert Inc", ['0 issue "letsencrypt.org"'])
        self.assertIn("Mismatch", rows[0][1])
        rows = cross_check.caa_issuer_rows("X", [])
        self.assertIn("any CA", rows[0][1])

    def test_null_mx_spf(self):
        rows = cross_check.null_mx_spf_note({"mx": ["0 ."], "txt": []})
        self.assertIn("consistent", rows[0][1])
        self.assertEqual(cross_check.null_mx_spf_note({"mx": ["10 mx.example.com."], "txt": []}), [])


class BgpEnrichTests(unittest.TestCase):
    def test_peeringdb_parse(self):
        from unittest.mock import patch
        entry = {"name": "ExampleNet", "aka": "EXN", "website": "https://example.net", "policy_general": "Open", "info_traffic": "1-5Gbps", "info_type": "NSP", "irr_as_set": "AS-EXN"}
        with patch("domainscan.bgp_check.fetch_peeringdb", return_value=entry):
            rows = bgp_check.asn_enrichment(64500)
        data = rows_to_dict(rows)
        self.assertEqual(data["AS64500 name"], "ExampleNet")
        self.assertEqual(data["AS64500 peering policy"], "Open")


class ScannerSectionsTests(LocalBase):
    def test_new_sections_present(self):
        result = scanner.run_scan(self.base + "/", include_ports=False, include_subdomains=False, timeout=5, crawl_pages=0, js_files=0, subdomain_web=0, include_recon=False)
        sections = result["sections"]
        for name in ("SEO", "Accessibility", "Performance", "Privacy", "Archive", "Certificates", "Typosquat", "Exposures"):
            self.assertIn(name, sections)
        self.assertIn("Quick profile", sections["Archive"][0][1])


class SeoCollectTests(unittest.TestCase):
    def test_collect_end_to_end(self):
        html = "<html><head><title>Example page title here ok</title></head><body><h1>Hi</h1></body></html>"
        rows = seo_check.collect(html, "http://127.0.0.1:9/", {}, 1)["rows"]
        self.assertGreater(len(rows), 10)
        data = rows_to_dict(rows)
        self.assertEqual(data["Sitemap reference"], "No sitemap found")


class HttpExtraTests(unittest.TestCase):
    def test_hsts_readiness(self):
        data = rows_to_dict(http_check.hsts_rows("max-age=63072000; includeSubDomains; preload"))
        self.assertEqual(data["HSTS readiness"], "Meets preload requirements")
        self.assertEqual(data["HSTS subdomains"], "Covered")

    def test_hsts_weak(self):
        data = rows_to_dict(http_check.hsts_rows("max-age=60"))
        self.assertIn("weak", data["HSTS duration"])
        self.assertEqual(data["HSTS subdomains"], "Not covered")

    def test_hsts_invalid(self):
        data = rows_to_dict(http_check.hsts_rows("includeSubDomains"))
        self.assertIn("invalid", data["HSTS max-age"])

    def test_report_only(self):
        data = rows_to_dict(http_check.security_summary({"Content-Security-Policy-Report-Only": "default-src 'self'; report-uri /r"}))
        self.assertIn("not enforced", data["CSP report-only"])

    def test_self_signed(self):
        cert = {"subject": ((("commonName", "x"),),), "issuer": ((("commonName", "x"),),), "subjectAltName": []}
        data = rows_to_dict(http_check.parse_cert(cert, b"", "x"))
        self.assertTrue(data["Self-signed"].startswith("Yes"))
        self.assertIn("deprecated", data["SAN verdict"])

    def test_wildcard_san(self):
        cert = {"subject": ((("commonName", "x"),),), "issuer": ((("commonName", "y"),),),
                "subjectAltName": [("DNS", "*.example.com"), ("DNS", "example.com")]}
        data = rows_to_dict(http_check.parse_cert(cert, b"", "example.com"))
        self.assertEqual(data["Self-signed"], "No")
        self.assertIn("*.example.com", data["Wildcard SANs"])

    def test_sct_verdict(self):
        text = "CT Precertificate SCTs:\n    Signed Certificate Timestamp:\n    Signed Certificate Timestamp:\n"
        data = rows_to_dict(http_check.parse_openssl_text(text))
        self.assertIn("Meets", data["SCT verdict"])


class DnsExtraTests(unittest.TestCase):
    def test_nsec_modes(self):
        self.assertIn("enumerable", rows_to_dict(dns_check.nsec_mode_rows(["a"], []))["NSEC mode"])
        self.assertIn("NSEC3", rows_to_dict(dns_check.nsec_mode_rows([], ["1 0 10 X"]))["NSEC mode"])
        self.assertIn("unsigned", rows_to_dict(dns_check.nsec_mode_rows([], []))["NSEC mode"])

    def test_identity_probes_fail_soft(self):
        self.assertEqual(dns_check.nsid_query("127.0.0.1", timeout=1), "")
        self.assertEqual(dns_check.version_query("127.0.0.1", timeout=1), "")


class MailExtraTests(unittest.TestCase):
    def test_vrfy_verdicts(self):
        self.assertIn("enumeration", mail_check.vrfy_verdict("252 ok", "VRFY"))
        self.assertIn("disabled", mail_check.vrfy_verdict("502 no", "EXPN"))
        self.assertIn("550", mail_check.vrfy_verdict("550 denied", "VRFY"))

    def test_mta_sts_mx_match(self):
        rows = mail_check.mta_sts_mx_match(["*.example.com"], ["mx.example.com"])
        self.assertIn("match", rows_to_dict(rows)["MTA-STS coverage"])
        rows = mail_check.mta_sts_mx_match(["*.example.com"], ["rogue.example.org"])
        self.assertIn("rogue.example.org", rows_to_dict(rows)["MTA-STS coverage"])

    def test_forward_confirm_skip(self):
        self.assertEqual(mail_check.mx_forward_confirm("No PTR record", "1.2.3.4"), "Skipped (no PTR)")


class FilesExtraTests(unittest.TestCase):
    def test_sitemap_freshness(self):
        today = datetime.date.today().strftime("%Y-%m-%d")
        self.assertIn("Fresh", files_check.sitemap_freshness(today))
        self.assertIn("Stale", files_check.sitemap_freshness("2000-01-01"))

    def test_parse_humans(self):
        data = rows_to_dict(files_check.parse_humans("/* TEAM */\nJohn <john@example.com>\nLast update: 2024-01-01"))
        self.assertIn("john@example.com", data["humans.txt emails"])
        self.assertEqual(data["humans.txt updated"], "2024-01-01")

    def test_parse_sitemap_returns_urls(self):
        result = {"ok": True, "text": "<urlset><url><loc>https://a.example/x</loc></url></urlset>", "size": 10}
        parsed = files_check.parse_sitemap(result)
        self.assertEqual(parsed["urls"], ["https://a.example/x"])
        self.assertIn("Sitemap URL count", rows_to_dict(parsed["rows"]))


class VulnDbTests(unittest.TestCase):
    def test_jquery_vulnerable(self):
        hits = content_check.vuln_lookup("jQuery", "1.12.4")
        self.assertTrue(hits)
        self.assertIn("XSS", hits)

    def test_jquery_clean(self):
        self.assertEqual(content_check.vuln_lookup("jQuery", "3.6.0"), "")

    def test_lodash_cve(self):
        self.assertIn("CVE-2020-8203", content_check.vuln_lookup("Lodash", "4.17.15"))
        self.assertEqual(content_check.vuln_lookup("Lodash", "4.17.21"), "")

    def test_eol_flagged(self):
        self.assertIn("end-of-life", content_check.vuln_lookup("AngularJS", "1.6.0"))
        self.assertIn("XSS", content_check.vuln_lookup("Bootstrap", "3.4.1"))

    def test_version_below(self):
        self.assertTrue(content_check.version_below("1.9.0", "2.0.0"))
        self.assertFalse(content_check.version_below("3.6.0", "3.6.0"))
        self.assertFalse(content_check.version_below("abc", "3.0.0"))


class JsExtraTests(unittest.TestCase):
    def test_postmessage(self):
        texts = [("a.js", "addEventListener('message', function(e) { document.write(e.data); })")]
        data = rows_to_dict(js_check.postmessage_rows(texts))
        self.assertIn("without origin", data["postMessage origin check"])

    def test_storage(self):
        texts = [("a.js", "localStorage.setItem('auth_token', value);")]
        rows = js_check.storage_rows(texts)
        data = rows_to_dict(rows)
        self.assertIn("1 suspicious", data["Secrets in web storage"])
        self.assertIn("auth_token", str(rows))

    def test_debug(self):
        texts = [("a.js", "console.log(1); console.log(2); debugger;")]
        data = rows_to_dict(js_check.debug_rows(texts))
        self.assertIn("2 console calls", data["Debug leftovers"])
        self.assertIn("1 debugger", data["Debug leftovers"])

    def test_endpoint_keys(self):
        data = rows_to_dict(js_check.endpoint_key_rows(["/api/x?token=abc", "api_key='ZZZ'"]))
        self.assertIn("2 endpoints", data["Keys in URLs"])

    def test_lib_versions(self):
        texts = [("a.js", "angular.js/1.6.0/angular.min.js handlebars-4.0.0.js")]
        data = rows_to_dict(js_check.library_version_rows(texts))
        self.assertIn("end-of-life", data["JS library risk: AngularJS"])
        self.assertIn("CVE", data["JS library risk: Handlebars"])


class ContentExtraTests(unittest.TestCase):
    def test_base_tabnabbing_iframe(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><base href="https://evil.example/"></head><body><a href="https://x.example" target="_blank">x</a><iframe src="https://y.example"></iframe></body></html>', "html.parser")
        data = rows_to_dict(content_check.base_tag_rows(soup, "https://example.com/"))
        self.assertIn("evil.example", data["Base tag hijack"])
        self.assertIn("noopener", rows_to_dict(content_check.tabnabbing_rows(soup))["Tabnabbing risk"])
        self.assertIn("1 of 1", rows_to_dict(content_check.iframe_sandbox_rows(soup))["Unsandboxed iframes"])

    def test_refresh_duplicate_deprecated(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><meta http-equiv="refresh" content="5;url=https://evil.example/"></head><body><div id="a"></div><div id="a"></div><font>x</font></body></html>', "html.parser")
        data = rows_to_dict(content_check.refresh_rows(soup))
        self.assertIn("absolute URL", data["Meta refresh target"])
        self.assertIn("1: a", rows_to_dict(content_check.duplicate_id_rows(soup))["Duplicate IDs"])
        self.assertIn("font", rows_to_dict(content_check.deprecated_tag_rows(soup))["Deprecated tags"])

    def test_autocomplete(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<form><input type="password"></form>', "html.parser")
        data = rows_to_dict(content_check.autocomplete_rows(soup))
        self.assertEqual(data["Password autocomplete"], "0 of 1 disable storage")


class SeoExtraTests(unittest.TestCase):
    def test_blocks_all(self):
        self.assertTrue(seo_check.blocks_all_crawlers("User-agent: *\nDisallow: /"))
        self.assertFalse(seo_check.blocks_all_crawlers("User-agent: *\nDisallow: /admin/"))

    def test_title_h1(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><head><title>Same</title></head><body><h1>Same</h1></body></html>", "html.parser")
        self.assertIn("Identical", rows_to_dict(seo_check.title_h1_rows(soup))["Title vs H1"])

    def test_discovery(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><link rel="amphtml" href="/amp"><link rel="alternate" type="application/rss+xml" href="/feed"><link rel="next" href="/p2"></head></html>', "html.parser")
        data = rows_to_dict(seo_check.discovery_rows(soup))
        self.assertIn("/amp", data["AMP version"])
        self.assertEqual(data["Feeds discovered"], "1")
        self.assertIn("prev/next", data["Pagination"])


class A11yExtraTests(unittest.TestCase):
    def test_hidden_focus(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<div aria-hidden="true"><a href="/x">y</a></div>', "html.parser")
        data = rows_to_dict(a11y_check.hidden_focus_rows(soup))
        self.assertTrue(data["Hidden focusable elements"].startswith("1"))

    def test_motion(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<marquee>x</marquee><video autoplay></video>", "html.parser")
        data = rows_to_dict(a11y_check.motion_rows(soup))
        self.assertIn("1 marquee", data["Auto-moving content"])
        self.assertEqual(data["Autoplay videos"], "1")

    def test_group(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<input type="radio" name="a">', "html.parser")
        data = rows_to_dict(a11y_check.group_rows(soup))
        self.assertIn("No fieldset", data["Group verdict"])


class PerfExtraTests(unittest.TestCase):
    def test_dom_verdict(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<html><body><p>x</p></body></html>", "html.parser")
        self.assertEqual(rows_to_dict(perf_check.dom_verdict_rows(soup))["DOM verdict"], "Reasonable")

    def test_preconnect_coverage(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<html><head><link rel="preconnect" href="https://cdn.example/"></head><body><script src="https://cdn.example/a.js"></script><script src="https://other.example/b.js"></script></body></html>', "html.parser")
        data = rows_to_dict(perf_check.preconnect_coverage_rows(soup, "https://example.com/"))
        self.assertEqual(data["Preconnect coverage"], "1 of 2 third-party hosts")
        self.assertIn("other.example", data["Missing preconnect"])


class PrivacyExtraTests(unittest.TestCase):
    def test_client_storage(self):
        data = rows_to_dict(privacy_check.client_storage_rows("localStorage.setItem(1); navigator.sendBeacon(u);"))
        self.assertIn("localStorage", data["Client storage APIs"])
        self.assertIn("sendBeacon", data["Client storage APIs"])

    def test_pixels(self):
        data = rows_to_dict(privacy_check.pixel_rows('<img src="x" width="1" height="1"><img src="y">'))
        self.assertTrue(data["Tracking pixels"].startswith("1"))


class TypoExtraTests(unittest.TestCase):
    def test_homoglyph(self):
        variants = typo_check.homoglyph_variants("paypal")
        self.assertTrue(variants)
        self.assertTrue(all(item.startswith("xn--") for item in variants))

    def test_generate_includes_punycode(self):
        self.assertTrue(any("xn--" in item for item in typo_check.generate_variants("example.com")))


class WhoisLockTests(unittest.TestCase):
    def test_locks_set(self):
        data = rows_to_dict(whois_check.lock_rows(["clientTransferProhibited x", "serverDeleteProhibited x"]))
        self.assertTrue(data["Transfer lock"].startswith("Set"))
        self.assertIn("Partial", data["Update/delete lock"])

    def test_locks_missing(self):
        data = rows_to_dict(whois_check.lock_rows(["ok x"]))
        self.assertIn("Not set", data["Transfer lock"])


class WaybackExtraTests(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(wayback_check.format_bytes(1536), "1.5 KB")
        self.assertEqual(wayback_check.format_bytes(5 * 1024 * 1024), "5.0 MB")


class TakeoverTests(unittest.TestCase):
    def test_body_match(self):
        self.assertEqual(subdomain_check.match_takeover_body("NoSuchBucket error"), "AWS S3")

    def test_body_no_match(self):
        self.assertEqual(subdomain_check.match_takeover_body("<html>normal</html>"), "")


class ThreatIntelTests(unittest.TestCase):
    def test_urlscan_verdicts(self):
        payload = {"total": 2, "results": [
            {"_id": "abc", "verdicts": {"overall": {"malicious": True}}, "page": {"ip": "1.2.3.4", "country": "US"}, "task": {"time": "2024-01-01T00:00:00"}},
            {"_id": "def", "verdicts": {"overall": {"score": 10}}, "page": {"ip": "1.2.3.4"}, "task": {"time": "2024-02-01T00:00:00"}},
        ]}

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return payload

        with patch("requests.get", return_value=FakeResponse()):
            data = rows_to_dict(threat_check.urlscan_rows("example.com", 5))
        self.assertIn("1 malicious", data["urlscan.io verdicts"])
        self.assertEqual(data["urlscan.io first seen"], "2024-01-01")

    def test_urlscan_failure(self):
        with patch("requests.get", side_effect=RuntimeError("down")):
            with patch("time.sleep"):
                data = rows_to_dict(threat_check.urlscan_rows("example.com", 5))
        self.assertIn("Query failed", data["urlscan.io"])


class CommonCrawlTests(unittest.TestCase):
    def test_summarize(self):
        captures = [
            {"url": "https://example.com/a", "mime": "text/html", "length": "100"},
            {"url": "https://sub.example.com/b", "mime": "text/html", "length": "200"},
        ]
        data = rows_to_dict(commoncrawl_check.summarize(captures))
        self.assertIn("2 unique", data["Common Crawl URLs"])
        self.assertEqual(commoncrawl_check.format_bytes(300), "300 bytes")


class PruneTests(unittest.TestCase):
    def test_prune_old(self):
        import time
        directory = tempfile.mkdtemp()
        try:
            for index in range(5):
                path = os.path.join(directory, "example.com-2024010" + str(index) + "-000000.json")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("{}")
                stamp = time.time() - (5 - index)
                os.utime(path, (stamp, stamp))
            removed = history_store.prune_old("example.com", keep=2, directory=directory)
            self.assertEqual(removed, 3)
            self.assertEqual(len(history_store.list_runs("example.com", directory=directory)), 2)
        finally:
            shutil.rmtree(directory, ignore_errors=True)


class GradeTests(unittest.TestCase):
    def good_result(self):
        return {"sections": {
            "Website": [("Security: HSTS", "Present: max-age=63072000"), ("HSTS max-age", "63072000 seconds"), ("Security: CSP", "Present: default-src"), ("CSP weaknesses", "None found"), ("Security: Clickjacking protection", "Present: DENY"), ("Cookies missing Secure", "0"), ("Cookies missing HttpOnly", "0"), ("Final URL", "https://example.com/"), ("Server version exposed", "No (nginx)"), ("Powered-By exposed", "No")],
            "TLS": [("Certificate state", "Valid, 200 days remaining"), ("Chain trusted", "Yes (system certificate store)"), ("Legacy TLS", "TLS 1.0/1.1 not accepted"), ("Weak ciphers", "Rejected (good)")],
            "Mail": [("SPF default policy", "Fail (strict) [-all]"), ("DMARC policy", "Reject (block)"), ("DKIM keys found", "2"), ("MTA-STS verdict", "Enforcing (unsigned mail rejected)")],
            "DNS": [("DNSSEC", "Signed (DS/DNSKEY records published)"), ("CAA restricts issuance", "Yes (2 policies)")],
            "Exposures": [("Exposed paths", "0")], "Subdomains": [], "Threat Intel": [], "Ports": [],
            "Content": [("Mixed content refs", "None")]}}

    def test_good_grade(self):
        data = rows_to_dict(grade_check.collect(self.good_result())["rows"])
        self.assertTrue(data["Security grade"].startswith("A"))

    def test_bad_grade(self):
        result = {"sections": {
            "Website": [("Security: HSTS", "Missing"), ("Security: CSP", "Missing"), ("Security: Clickjacking protection", "Missing"), ("Cookies missing Secure", "4"), ("Final URL", "http://example.com/")],
            "TLS": [("Certificate state", "Expired 5 days ago"), ("Chain trusted", "No: self signed"), ("Legacy TLS", "TLS 1.0/1.1 accepted (TLSv1, weak)"), ("Weak ciphers", "ACCEPTED: DES-CBC3-SHA (weak)")],
            "Mail": [("SPF default policy", "No default policy"), ("DMARC policy", "Missing")],
            "DNS": [("DNSSEC", "No DS/DNSKEY records found")],
            "Exposures": [("CRITICAL: /.git/config", "x")], "Subdomains": [("Takeover 1", "x LIKELY TAKEABLE (Github error page)")],
            "Threat Intel": [("urlscan.io verdicts", "2 malicious, 0 suspicious of 5")], "Ports": [("Risk: port 23", "Open, plaintext")], "Content": []}}
        rows = grade_check.collect(result)["rows"]
        data = rows_to_dict(rows)
        self.assertTrue(data["Security grade"].startswith("F"))
        self.assertIn("Top recommendation 1", data)

    def test_letters(self):
        self.assertEqual(grade_check.grade_letter(97), "A+")
        self.assertEqual(grade_check.grade_letter(82), "B+")
        self.assertEqual(grade_check.grade_letter(40), "F")


class SpfChainTests(unittest.TestCase):
    def test_chain_counts_nested(self):
        mapping = {("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 ~all"]}
        rows = mail_check.describe_spf(["v=spf1 include:_spf.example.net -all"], FakeResolver(mapping), "example.com")
        data = rows_to_dict(rows)
        self.assertIn("SPF include _spf.example.net", data)
        self.assertIn("across chain", data["SPF total lookups"])

    def test_chain_missing_target(self):
        rows = mail_check.describe_spf(["v=spf1 include:gone.example.net -all"], FakeResolver({}), "example.com")
        data = rows_to_dict(rows)
        self.assertIn("permerror", data["SPF include gone.example.net"])

    def test_chain_loop(self):
        rows = mail_check.describe_spf(["v=spf1 include:example.com -all"], FakeResolver({}), "example.com")
        data = rows_to_dict(rows)
        self.assertIn("loop", data["SPF include example.com"])


class SpoofTests(unittest.TestCase):
    def test_protected(self):
        data = rows_to_dict(mail_check.spoof_rows([("SPF default policy", "Fail (strict) [-all]")], [("DMARC policy", "Reject (block)")]))
        self.assertIn("Protected", data["Spoofability"])

    def test_spoofable(self):
        data = rows_to_dict(mail_check.spoof_rows([("SPF default policy", "No default policy")], [("DMARC", "No DMARC record")]))
        self.assertIn("Easily spoofable", data["Spoofability"])


class BimiSvgTests(unittest.TestCase):
    def test_valid_svg(self):
        from unittest import mock

        class FakeResponse:
            status_code = 200
            content = b'<svg xmlns="http://www.w3.org/2000/svg" width="100"></svg>'

        with mock.patch("requests.get", return_value=FakeResponse()):
            data = rows_to_dict(mail_check.bimi_svg_rows("https://example.com/logo.svg"))
        self.assertIn("Valid SVG", data["BIMI logo format"])

    def test_not_svg(self):
        from unittest import mock

        class FakeResponse:
            status_code = 200
            content = b"\x89PNG not svg"

        with mock.patch("requests.get", return_value=FakeResponse()):
            data = rows_to_dict(mail_check.bimi_svg_rows("https://example.com/logo.svg"))
        self.assertIn("Not an SVG", data["BIMI logo format"])


class PreloadTests(unittest.TestCase):
    def test_listed(self):
        from unittest import mock

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"status": "preloaded"}

        with mock.patch("requests.get", return_value=FakeResponse()):
            data = rows_to_dict(cross_check.preload_status_rows("example.com", 5))
        self.assertIn("Listed", data["HSTS preload list"])

    def test_failed(self):
        from unittest import mock
        with mock.patch("requests.get", side_effect=RuntimeError("down")):
            with mock.patch("time.sleep"):
                data = rows_to_dict(cross_check.preload_status_rows("example.com", 5))
        self.assertIn("failed", data["HSTS preload list"])


class HeaderExtraTests(unittest.TestCase):
    def test_new_headers(self):
        headers = {"Reporting-Endpoints": "default=/r", "NEL": '{"report_to":"default"}', "Document-Policy": "js-profiling=?0", "Origin-Agent-Cluster": "?1"}
        data = rows_to_dict(http_check.security_summary(headers))
        self.assertIn("/r", data["Reporting endpoints"])
        self.assertIn("report_to", data["Network Error Logging"])
        self.assertIn("js-profiling", data["Document policy"])
        self.assertEqual(data["Origin agent cluster"], "?1")

    def test_partitioned(self):
        data = rows_to_dict(http_check.cookie_flag_rows(["id=1; Secure; Partitioned; Path=/"]))
        self.assertIn("CHIPS", data["Partitioned cookies"])


class DnssecExtraTests(unittest.TestCase):
    def test_caa_details(self):
        data = rows_to_dict(dns_check.caa_detail_rows(['0 issue "letsencrypt.org"', '128 validationmethods "dns-01"']))
        self.assertIn("issue rules also cover", data["CAA wildcards"])
        self.assertEqual(data["CAA validation"], "dns-01")
        self.assertIn("critical", data["CAA critical flag"])

    def test_rrsig_no_answer(self):
        self.assertEqual(dns_check.rrsig_expiry_rows(FakeResolver({}), "example.com"), [])
        self.assertEqual(dns_check.ds_link_rows(FakeResolver({}), "example.com"), [])


class SubdomainSourceTests(unittest.TestCase):
    def test_otx(self):
        from unittest import mock

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"passive_dns": [{"hostname": "a.example.com"}, {"hostname": "other.net"}]}

        with mock.patch("requests.get", return_value=FakeResponse()):
            self.assertEqual(subdomain_check.fetch_otx("example.com"), {"a.example.com"})

    def test_anubis(self):
        from unittest import mock

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return ["b.example.com", "x.other.net"]

        with mock.patch("requests.get", return_value=FakeResponse()):
            self.assertEqual(subdomain_check.fetch_anubis("example.com"), {"b.example.com"})

    def test_failures(self):
        from unittest import mock
        with mock.patch("requests.get", side_effect=RuntimeError("down")):
            with mock.patch("time.sleep"):
                self.assertIsNone(subdomain_check.fetch_otx("example.com"))
                self.assertIsNone(subdomain_check.fetch_anubis("example.com"))

    def test_takeover_markers(self):
        self.assertGreaterEqual(len(subdomain_check.TAKEOVER_BODIES), 50)
        self.assertEqual(subdomain_check.match_takeover_body("This UserVoice subdomain is currently available!"), "Uservoice")


class ServiceAdvisoryTests(unittest.TestCase):
    def test_openssh_old(self):
        self.assertIn("CVE-2018-15473", ports_check.service_advisory("SSH-2.0-OpenSSH_7.2"))

    def test_vsftpd_backdoor(self):
        self.assertIn("CVE-2011-2523", ports_check.service_advisory("220 (vsFTPd 2.3.4)"))

    def test_current_clean(self):
        self.assertEqual(ports_check.service_advisory("SSH-2.0-OpenSSH_9.3"), "")
        self.assertEqual(ports_check.service_advisory("220 (vsFTPd 3.0.3)"), "")

    def test_version_compare(self):
        self.assertTrue(ports_check.version_older("2.4.49", "2.4.51"))
        self.assertFalse(ports_check.version_older("9.3", "7.4"))

    def test_udp_closed(self):
        self.assertEqual(ports_check.ntp_probe("127.0.0.1", timeout=1), "Filtered (no UDP response)")


class WaybackDiffTests(unittest.TestCase):
    def test_drift_same(self):
        old = "<html><head><title>Acme</title></head><body><p>We sell quality widgets and gadgets online daily</p></body></html>"
        new = "<html><head><title>Acme</title></head><body><p>We sell quality widgets and gadgets online daily with shipping</p></body></html>"
        self.assertIn("nearly identical", wayback_check.drift_verdict(old, new))

    def test_drift_changed(self):
        old = "<html><head><title>Acme</title></head><body><p>We sell quality widgets and gadgets online daily</p></body></html>"
        new = "<html><head><title>Casino</title></head><body><p>crypto betting poker slots jackpot win money now</p></body></html>"
        verdict = wayback_check.drift_verdict(old, new)
        self.assertIn("title changed", verdict)
        self.assertIn("completely different", verdict)


class GeoCrossTests(unittest.TestCase):
    def test_agree(self):
        from unittest import mock

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"success": True, "country_code": "US", "connection": {"asn": 15169}}

        primary = {"countryCode": "US", "as": "AS15169 Google LLC"}
        with mock.patch("requests.get", return_value=FakeResponse()):
            data = rows_to_dict(network_check.second_source_rows("8.8.8.8", primary, "ip-api.com", "IP 1 "))
        self.assertIn("agree", data["IP 1 cross-check"])

    def test_disagree(self):
        from unittest import mock

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"success": True, "country_code": "DE", "connection": {"asn": 3320}}

        primary = {"countryCode": "US", "as": "AS15169 Google LLC"}
        with mock.patch("requests.get", return_value=FakeResponse()):
            data = rows_to_dict(network_check.second_source_rows("8.8.8.8", primary, "ip-api.com", "IP 1 "))
        self.assertIn("disagree", data["IP 1 cross-check"])


class TechWafTests(unittest.TestCase):
    def test_new_tech(self):
        rows = content_check.detect_tech('<script src="htmx.min.js"></script><script>supabase.createClient()</script>', {}, [], {})
        data = rows_to_dict(rows)
        self.assertIn("Tech: htmx", data)
        self.assertIn("Tech: Supabase", data)

    def test_new_waf(self):
        self.assertEqual(web_extra_check.waf_signature({"Server": "nginx"}, "blocked _px3"), "PerimeterX (HUMAN)")
        self.assertEqual(web_extra_check.waf_signature({"X-SL-CompState": "1"}, ""), "Radware")
        self.assertEqual(web_extra_check.waf_signature({"Server": "x"}, "naxsi blocked"), "NAXSI")

    def test_exposure_count(self):
        self.assertGreaterEqual(len(exposure_check.PROBES), 75)


class GradeSectionTests(unittest.TestCase):
    def test_grade_in_scan(self):
        result = scanner.run_scan("http://127.0.0.1:9/", include_ports=False, include_subdomains=False, timeout=2, crawl_pages=0, js_files=0, subdomain_web=0, include_recon=False)
        self.assertIn("Grade", result["sections"])
        data = rows_to_dict(result["sections"]["Grade"])
        self.assertIn("Security grade", data)


class RobustFetchTests(unittest.TestCase):
    def test_fetch_json_retries_then_succeeds(self):
        calls = []

        class Flaky:
            def raise_for_status(self):
                return None

            def json(self):
                if len(calls) < 2:
                    calls.append(1)
                    raise ValueError("bad json")
                return {"ok": True}

        with unittest.mock.patch("requests.get", return_value=Flaky()):
            with unittest.mock.patch("time.sleep"):
                self.assertEqual(helpers.fetch_json("https://example.com/x", tries=3), {"ok": True})

    def test_fetch_json_gives_up(self):
        class Bad:
            def raise_for_status(self):
                return None

            def json(self):
                raise ValueError("bad json")

        with unittest.mock.patch("requests.get", return_value=Bad()):
            with unittest.mock.patch("time.sleep"):
                with self.assertRaises(ValueError):
                    helpers.fetch_json("https://example.com/x", tries=2)

    def test_fetch_text_gives_up(self):
        import requests

        with unittest.mock.patch("requests.get", side_effect=requests.ConnectionError("down")):
            with unittest.mock.patch("time.sleep"):
                with self.assertRaises(requests.ConnectionError):
                    helpers.fetch_text("https://example.com/x", tries=2)


class DeeperDataTests(unittest.TestCase):
    def test_generator_versions(self):
        data = rows_to_dict(content_check.generator_version_rows("WordPress 6.1.1"))
        self.assertIn("Exact versions disclosed", data)
        other = rows_to_dict(content_check.generator_version_rows("CustomCMS 2.4"))
        self.assertIn("Version disclosure", other)
        self.assertEqual(content_check.generator_version_rows("Something Else"), [])

    def test_js_jwt_and_sinks(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
        data = rows_to_dict(js_check.jwt_rows([("app.js", "var t = '" + token + "';")]))
        self.assertTrue(data.get("Hardcoded JWTs", "").startswith("1 "))
        self.assertIn("JWT claims", data)
        dangers = rows_to_dict(js_check.danger_rows([("app.js", "new Function(x); setInterval('y', 1); Object.assign({}, z);")]))
        self.assertIn("Sink: Function() constructors", dangers)
        self.assertIn("Sink: setInterval strings", dangers)
        self.assertIn("Sink: merge/extend calls", dangers)

    def test_hreflang_validation(self):
        self.assertTrue(seo_check.valid_lang_code("en-US"))
        self.assertTrue(seo_check.valid_lang_code("x-default"))
        self.assertFalse(seo_check.valid_lang_code("english_USA!"))
        from bs4 import BeautifulSoup
        soup = BeautifulSoup('<link rel="alternate" hreflang="en" href="https://example.com/en"><link rel="alternate" hreflang="bad!" href="https://example.com/x">', "html.parser")
        data = rows_to_dict(seo_check.hreflang_rows(soup, 1, "https://example.com/en"))
        self.assertIn("Hreflang invalid codes", data)
        self.assertIn("Present", data.get("Hreflang self-reference", ""))

    def test_ads_malformed(self):
        data = rows_to_dict(files_check.parse_ads({"ok": True, "text": "google.com, pub-1, DIRECT\nbroken line"}))
        self.assertIn("ads.txt malformed", data)

    def test_thin_content(self):
        visited = {
            "https://a.example/": (200, "<p>" + "word " * 300 + "</p>", 1, 1),
            "https://a.example/t": (200, "<p>tiny</p>", 1, 1),
        }
        data = rows_to_dict(crawl_check.thin_content_rows(visited))
        self.assertEqual(data.get("Thin pages (<200 words)"), "1 of 2")
        self.assertIn("Thin page", data)
        self.assertIn("Average page words", data)

    def test_query_params(self):
        visited = {
            "https://a.example/?utm_source=x&id=1": (200, "", 1, 1),
            "https://a.example/?id=1&id=2": (200, "", 1, 1),
        }
        data = rows_to_dict(crawl_check.query_param_rows(visited))
        self.assertEqual(data.get("URLs with tracking parameters"), "1")
        self.assertIn("Duplicate query keys", data)
        self.assertIn("Top query keys", data)

    def test_contrast(self):
        from bs4 import BeautifulSoup
        html = '<p style="color:#777777;background:#ffffff">x</p>'
        data = rows_to_dict(content_check.contrast_rows(BeautifulSoup(html, "html.parser"), html))
        self.assertIn("Low-contrast pairs", data)
        html2 = '<p style="color:#000000;background:#ffffff">x</p>'
        data2 = rows_to_dict(content_check.contrast_rows(BeautifulSoup(html2, "html.parser"), html2))
        self.assertIn("Contrast verdict", data2)

    def test_sitemap_index_flag(self):
        parsed = files_check.parse_sitemap({"ok": True, "text": "<sitemapindex><sitemap><loc>https://a.example/s.xml</loc></sitemap></sitemapindex>", "size": 5})
        self.assertTrue(parsed["is_index"])
        self.assertEqual(parsed["urls"], ["https://a.example/s.xml"])

    def test_trend_needs_two_scans(self):
        tmp = tempfile.mkdtemp()
        try:
            current = {"meta": {"scanned_at": "2026-09-08"}, "target": {"host": "example.com"}, "sections": {"A": [("k", "v")]}}
            data = rows_to_dict(history_store.trend_rows("example.com", current, tmp))
            self.assertIn("Trend", data)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_abuse_contact(self):
        data = {"entities": [{"roles": ["abuse"], "vcardArray": [None, [["email", {}, "text", "abuse@example.com"]]]}]}
        rows = whois_check.parse_rdap(data)
        found = rows_to_dict(rows)
        self.assertIn("Abuse contact", found)


class LanguageTests(unittest.TestCase):
    def test_language_list(self):
        codes = [code for code, _ in i18n.LANGUAGES]
        self.assertEqual(codes, ["en", "tr", "es", "de"])
        self.assertEqual(i18n.valid_codes(), codes)

    def test_string_keys_complete(self):
        base = set(i18n.STRINGS["en"])
        self.assertGreater(len(base), 50)
        for code in ("tr", "es", "de"):
            self.assertEqual(set(i18n.STRINGS[code]), base)

    def test_section_names_complete(self):
        base = set(i18n.SECTION_NAMES["en"])
        self.assertIn("Summary", base)
        self.assertIn("Changes", base)
        for code in ("tr", "es", "de"):
            self.assertEqual(set(i18n.SECTION_NAMES[code]), base)

    def test_placeholders_match(self):
        import string
        fmt = string.Formatter()
        for key, en_text in i18n.STRINGS["en"].items():
            en_fields = {field[1] for field in fmt.parse(en_text) if field[1]}
            for code in ("tr", "es", "de"):
                other = {field[1] for field in fmt.parse(i18n.STRINGS[code][key]) if field[1]}
                self.assertEqual(other, en_fields)

    def test_get_fallback(self):
        self.assertEqual(i18n.get("xx", "scan"), i18n.STRINGS["en"]["scan"])
        self.assertEqual(i18n.get("tr", "no_such_key"), "no_such_key")
        self.assertEqual(i18n.section("tr", "No Such Section"), "No Such Section")
        self.assertEqual(i18n.section("xx", "DNS"), "DNS")

    def test_get_formats(self):
        self.assertIn("3", i18n.get("tr", "findings", n=3))
        self.assertIn("example.com", i18n.get("de", "scanning", target="example.com"))

    def test_language_persistence(self):
        tmp = tempfile.mkdtemp()
        try:
            self.assertEqual(i18n.load_language(tmp), "en")
            i18n.save_language("tr", tmp)
            self.assertEqual(i18n.load_language(tmp), "tr")
            with open(os.path.join(tmp, "language"), "w", encoding="utf-8") as handle:
                handle.write("xx")
            self.assertEqual(i18n.load_language(tmp), "en")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ZAppLanguageTest(unittest.TestCase):
    def test_refresh_language_with_mocked_gui(self):
        from unittest import mock
        fake_tkinter = mock.MagicMock()
        sys.modules["tkinter"] = fake_tkinter
        sys.modules.pop("domainscan.app", None)
        try:
            from domainscan import app as app_module
            root = mock.MagicMock()
            app = app_module.DomainScanApp(root)
            app.tree.get_children.return_value = []
            app.search_entry.get.return_value = ""
            app.section_box.get.return_value = "All sections"
            app.section_box.cget.return_value = ["All sections"]
            with mock.patch.object(app_module.i18n, "save_language", return_value="tr"):
                app.lang_box.get.return_value = "🇹🇷 Türkçe"
                app.on_language()
            self.assertEqual(app.lang, "tr")
            texts = [str(call[1].get("text", "")) for call in app.scan_button.configure.call_args_list]
            self.assertIn("Tara", texts)
            self.assertEqual(app.current_section_key(), "*all*")
            app.all_rows = [("DNS", "A", "1.2.3.4")]
            app.result = {"meta": {"duration_seconds": 2.0}, "target": {"host": "example.com"}, "sections": {"DNS": [("A", "1.2.3.4")]}}
            app.section_choices(["DNS"])
            app.section_box.cget.return_value = ["Tüm bölümler", "DNS"]
            app.section_box.get.return_value = "DNS"
            self.assertEqual(app.current_section_key(), "DNS")
            app.apply_filter()
            app.lang = "en"
            app.refresh_language()
            texts = [str(call[1].get("text", "")) for call in app.scan_button.configure.call_args_list]
            self.assertIn("Scan", texts)
        finally:
            sys.modules.pop("tkinter", None)
            sys.modules.pop("domainscan.app", None)
