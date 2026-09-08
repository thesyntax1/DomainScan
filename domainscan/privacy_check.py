import re
import urllib.parse

from domainscan.helpers import short


TRACKERS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "googlesyndication.com": "Google Ads",
    "doubleclick.net": "DoubleClick",
    "facebook.net": "Facebook",
    "connect.facebook.net": "Facebook",
    "facebook.com": "Facebook",
    "hotjar.com": "Hotjar",
    "fullstory.com": "FullStory",
    "mouseflow.com": "Mouseflow",
    "crazyegg.com": "Crazy Egg",
    "mixpanel.com": "Mixpanel",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "amplitude.com": "Amplitude",
    "matomo": "Matomo",
    "piwik": "Piwik",
    "newrelic.com": "New Relic",
    "optimizely.com": "Optimizely",
    "criteo.com": "Criteo",
    "taboola.com": "Taboola",
    "outbrain.com": "Outbrain",
    "ads-twitter.com": "Twitter Ads",
    "ads.linkedin.com": "LinkedIn Ads",
    "snapchat.com": "Snapchat",
    "tiktok.com": "TikTok",
    "pinterest.com": "Pinterest",
    "scorecardresearch.com": "Scorecard",
    "quantserve.com": "Quantcast",
    "alexametrics.com": "Alexa",
    "hubspot.com": "HubSpot",
    "marketo.net": "Marketo",
    "pardot.com": "Pardot",
    "intercom.io": "Intercom",
    "drift.com": "Drift",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "tawk.to": "Tawk.to",
    "crisp.chat": "Crisp",
    "livechatinc.com": "LiveChat",
    "clarity.ms": "Clarity",
    "cloudflareinsights.com": "Cloudflare Insights",
    "vercel-insights.com": "Vercel Insights",
    "sentry.io": "Sentry",
    "bugsnag.com": "Bugsnag",
    "stripe.com": "Stripe",
    "paypal.com": "PayPal",
}

FINGERPRINT_PATTERNS = [
    ("Canvas fingerprinting", r"getContext\s*\(\s*['\"]2d['\"]\s*\).{0,400}toDataURL"),
    ("WebGL fingerprinting", r"getContext\s*\(\s*['\"]webgl"),
    ("Audio fingerprinting", r"(OfflineAudioContext|createOscillator|createDynamicsCompressor)"),
    ("Font enumeration", r"(measureText|offsetWidth).{0,200}(font|Font)"),
    ("Battery API", r"getBattery\s*\("),
    ("WebRTC leak surface", r"RTCPeerConnection"),
]


def collect(html, page_url, headers=None, cookies=None):
    rows = []
    if not html:
        rows.append(("Privacy audit", "No page content to analyze"))
        return {"rows": rows}
    third = third_party_hosts(html, page_url)
    rows.append(("Third-party hosts", str(len(third))))
    trackers = match_trackers(third)
    if trackers:
        rows.append(("Trackers detected", str(len(trackers))))
        for host, vendor in sorted(trackers.items()):
            rows.append(("Tracker: " + short(vendor, 50), host))
    else:
        rows.append(("Trackers detected", "None from the built-in list"))
    rows.extend(referrer_rows(headers or {}))
    rows.extend(fingerprint_rows(html))
    rows.extend(cookie_rows(cookies or []))
    rows.extend(consent_rows(html))
    return {"rows": rows}


def third_party_hosts(html, page_url):
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return set()
    host = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    found = set()
    for tag in soup.find_all(["script", "link", "img", "iframe", "video", "audio", "source", "embed"]):
        src = tag.get("src", "") or tag.get("href", "")
        if src.lower().startswith("http"):
            other = (urllib.parse.urlsplit(src).hostname or "").lower()
            if other and other != host and not other.endswith("." + host):
                found.add(other)
    for match in re.findall(r"https?://([A-Za-z0-9.-]+)", html or ""):
        other = match.lower()
        if other != host and not other.endswith("." + host):
            found.add(other)
    return found


def match_trackers(hosts):
    found = {}
    for host in hosts:
        for domain, vendor in TRACKERS.items():
            if host == domain or host.endswith("." + domain) or domain in host:
                found[host] = vendor
                break
    return found


def referrer_rows(headers):
    rows = []
    low = {str(name).lower(): value for name, value in headers.items()}
    policy = low.get("referrer-policy", "")
    if policy:
        rows.append(("Referrer-Policy", policy))
    else:
        rows.append(("Referrer-Policy", "Not set (full URLs leak to third parties)"))
    return rows


def fingerprint_rows(html):
    rows = []
    hits = []
    for label, pattern in FINGERPRINT_PATTERNS:
        try:
            if re.search(pattern, html or "", re.IGNORECASE | re.DOTALL):
                hits.append(label)
        except Exception:
            continue
    if hits:
        rows.append(("Fingerprinting markers", str(len(hits))))
        for label in hits:
            rows.append(("Marker: " + label, "Pattern present in page or inline JS"))
    else:
        rows.append(("Fingerprinting markers", "None found"))
    return rows


def cookie_rows(cookies):
    rows = []
    rows.append(("First-party cookies", str(len(cookies))))
    persistent = [cookie for cookie in cookies if cookie.get("expires") or cookie.get("max_age")]
    rows.append(("Persistent cookies", str(len(persistent))))
    return rows


def consent_rows(html):
    rows = []
    low = (html or "").lower()
    banners = ("cookiebot", "onetrust", "trustarc", "quantcast choice", "cookieyes", "osiano", "gdpr", "cookie consent", "cookie-consent", "cookiefirst")
    found = [name for name in banners if name in low]
    if found:
        rows.append(("Consent banner", "Likely present (" + ", ".join(found[:3]) + ")"))
    else:
        rows.append(("Consent banner", "None detected"))
    return rows
