import base64
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver

from domainscan import content_check, dns_check, files_check, helpers, http_check, mail_check, ports_check, whois_check


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
        self.assertEqual(data["ads.txt"], "Present (1 entries)")
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

    def do_GET(self):
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/":
            self.send_body("<html><head><title>Local</title></head><body><p>Hello</p></body></html>", extra={
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


if __name__ == "__main__":
    unittest.main()
