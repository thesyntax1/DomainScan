import re
import urllib.parse
from collections import Counter

from domainscan.helpers import EMAIL_RE, PHONE_RE, short


try:
    from bs4 import BeautifulSoup, Comment
    HAS_BS4 = True
except Exception:
    HAS_BS4 = False


SOCIAL = {
    "facebook.com": "Facebook",
    "twitter.com": "Twitter",
    "x.com": "X",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "github.com": "GitHub",
    "pinterest.com": "Pinterest",
    "reddit.com": "Reddit",
}

STOPWORDS = set("""
the and for with are this that from have has not you your all any can had her was one our out day get him his how its may new now old see two way who did own about into over after there their what which when make like time just look more find than first been call page home menu click here will shall each other many some such only also back under while where your web site online best top shop buy sale price free today
""".split())


def collect(html, page_url, headers, cookies):
    rows = []
    tech_rows = []
    if not html:
        rows.append(("Page content", "Empty response body"))
        tech_rows.append(("Technologies detected", "Skipped (no page content)"))
        return {"rows": rows, "tech": tech_rows}
    rows.append(("HTML size", str(len(html)) + " characters"))
    if HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        rows.extend(analyze_soup(soup, page_url, html))
        metas = meta_dict(soup)
    else:
        rows.append(("HTML parser", "beautifulsoup4 not installed, regex fallback used"))
        rows.extend(analyze_regex(html, page_url))
        metas = {}
    found = detect_tech(html, headers or {}, cookies or [], metas)
    if found:
        tech_rows.append(("Technologies detected", str(len(found))))
        tech_rows.extend(found)
    else:
        tech_rows.append(("Technologies detected", "None identified"))
    return {"rows": rows, "tech": tech_rows}


def meta_dict(soup):
    metas = {}
    for tag in soup.find_all("meta"):
        name = tag.get("name", "") or tag.get("property", "") or tag.get("http-equiv", "")
        content = tag.get("content", "")
        if name and content and name.lower() not in metas:
            metas[name.lower()] = content.strip()
    return metas


def analyze_soup(soup, page_url, html):
    rows = []
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    if title:
        rows.append(("Page title", short(title, 200)))
    else:
        rows.append(("Page title", "Missing"))
    lang = ""
    if soup.html:
        lang = soup.html.get("lang", "")
    if lang:
        rows.append(("Page language", lang))
    else:
        rows.append(("Page language", "Not declared"))
    charset = ""
    charset_tag = soup.find("meta", charset=True)
    if charset_tag:
        charset = charset_tag.get("charset", "")
    if not charset:
        for tag in soup.find_all("meta"):
            if tag.get("http-equiv", "").lower() == "content-type":
                charset = tag.get("content", "")
    if charset:
        rows.append(("Charset", short(charset, 80)))
    else:
        rows.append(("Charset", "Not declared"))
    metas = meta_dict(soup)
    rows.append(("Meta tag count", str(len(soup.find_all("meta")))))
    wanted = [
        ("description", "Meta description"),
        ("keywords", "Meta keywords"),
        ("author", "Meta author"),
        ("generator", "Meta generator"),
        ("viewport", "Meta viewport"),
        ("robots", "Meta robots"),
        ("theme-color", "Meta theme color"),
        ("referrer", "Meta referrer"),
        ("og:title", "OG title"),
        ("og:type", "OG type"),
        ("og:url", "OG URL"),
        ("og:image", "OG image"),
        ("og:site_name", "OG site name"),
        ("og:description", "OG description"),
        ("twitter:card", "Twitter card"),
        ("twitter:site", "Twitter site"),
        ("twitter:title", "Twitter title"),
        ("twitter:image", "Twitter image"),
    ]
    for key, label in wanted:
        if metas.get(key):
            rows.append((label, short(metas[key], 220)))
    for level in ("h1", "h2", "h3", "h4", "h5", "h6"):
        rows.append((level.upper() + " count", str(len(soup.find_all(level)))))
    first_h1 = soup.find("h1")
    if first_h1:
        rows.append(("First H1", short(first_h1.get_text(" ", strip=True), 200)))
    hrefs = [tag.get("href", "") for tag in soup.find_all("a", href=True)]
    rows.append(("Link count", str(len(hrefs))))
    stats, external_hosts = classify_links(hrefs, page_url)
    rows.append(("Internal links", str(stats["internal"])))
    rows.append(("External links", str(stats["external"])))
    rows.append(("Mailto links", str(stats["mailto"])))
    rows.append(("Tel links", str(stats["tel"])))
    rows.append(("JavaScript links", str(stats["javascript"])))
    rows.append(("Fragment links", str(stats["fragment"])))
    rows.append(("Unique external domains", str(len(external_hosts))))
    ranked = sorted(external_hosts, key=lambda h: external_hosts[h], reverse=True)[:10]
    for index, host in enumerate(ranked, 1):
        rows.append(("External domain " + str(index), host + " (" + str(external_hosts[host]) + " links)"))
    images = soup.find_all("img")
    rows.append(("Image count", str(len(images))))
    if images:
        without_alt = [img for img in images if not (img.get("alt") or "").strip()]
        rows.append(("Images without alt", str(len(without_alt))))
    scripts = soup.find_all("script")
    inline = [tag for tag in scripts if not tag.get("src")]
    external = [tag.get("src", "") for tag in scripts if tag.get("src")]
    rows.append(("Script count", str(len(scripts))))
    rows.append(("Inline scripts", str(len(inline))))
    rows.append(("External scripts", str(len(external))))
    for index, src in enumerate(external[:10], 1):
        rows.append(("Script " + str(index), short(src, 200)))
    styles = []
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]
        if "stylesheet" in [item.lower() for item in rel]:
            styles.append(tag.get("href", ""))
    rows.append(("Stylesheet count", str(len(styles))))
    for index, href in enumerate(styles[:5], 1):
        rows.append(("Stylesheet " + str(index), short(href, 200)))
    forms = soup.find_all("form")
    rows.append(("Form count", str(len(forms))))
    for index, form in enumerate(forms[:5], 1):
        action = form.get("action", "") or "(same page)"
        method = (form.get("method", "get") or "get").upper()
        rows.append(("Form " + str(index), method + " " + short(action, 160)))
    rows.append(("Input count", str(len(soup.find_all("input")))))
    rows.append(("Password fields", str(len(soup.find_all("input", {"type": "password"})))))
    rows.append(("Button count", str(len(soup.find_all("button")))))
    rows.append(("Iframe count", str(len(soup.find_all("iframe")))))
    for index, frame in enumerate(soup.find_all("iframe", src=True)[:5], 1):
        rows.append(("Iframe " + str(index), short(frame.get("src", ""), 200)))
    rows.append(("Table count", str(len(soup.find_all("table")))))
    rows.append(("Video count", str(len(soup.find_all("video")))))
    rows.append(("Audio count", str(len(soup.find_all("audio")))))
    rows.extend(form_target_rows(forms, page_url))
    if page_url.startswith("https://"):
        mixed = count_mixed(soup)
        if mixed:
            rows.append(("Mixed content refs", str(mixed)))
        else:
            rows.append(("Mixed content refs", "None"))
    rows.extend(comment_rows(soup))
    inline_js = "\n".join(tag.string or "" for tag in soup.find_all("script") if not tag.get("src"))
    paths = extract_js_paths(inline_js)
    rows.append(("JS paths (inline)", str(len(paths))))
    for index, path in enumerate(paths[:12], 1):
        rows.append(("JS path " + str(index), short(path, 160)))
    maps = html.lower().count("sourcemappingurl")
    if maps:
        rows.append(("Source maps referenced", str(maps)))
    else:
        rows.append(("Source maps referenced", "None"))
    handlers = len(re.findall(r"\son[a-z]+\s*=", html, re.IGNORECASE))
    rows.append(("Inline event handlers", str(handlers)))
    rows.extend(seo_rows(soup, metas))
    text = soup.get_text(" ", strip=True)
    words = text.split()
    rows.append(("Visible words", str(len(words))))
    rows.append(("Visible text size", str(len(text)) + " characters"))
    for index, (word, count) in enumerate(top_words(text), 1):
        rows.append(("Top word " + str(index), word + " (" + str(count) + " times)"))
    rows.extend(find_contacts(html, hrefs))
    return rows


def form_target_rows(forms, page_url):
    rows = []
    page_host = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    external_forms = []
    for form in forms:
        action = form.get("action", "")
        if action.lower().startswith("http"):
            target_host = (urllib.parse.urlsplit(action).hostname or "").lower()
            if target_host and target_host != page_host:
                external_forms.append(action)
    rows.append(("External form targets", str(len(external_forms))))
    for index, action in enumerate(external_forms[:3], 1):
        rows.append(("External form " + str(index), short(action, 200)))
    return rows


def count_mixed(soup):
    count = 0
    for tag in soup.find_all(["img", "script", "link", "iframe", "video", "audio", "source", "embed"]):
        for attr in ("src", "href"):
            value = tag.get(attr, "")
            if value.lower().startswith("http://"):
                count += 1
    return count


def comment_rows(soup):
    rows = []
    comments = soup.find_all(string=lambda item: isinstance(item, Comment))
    rows.append(("HTML comments", str(len(comments))))
    for index, comment in enumerate(comments[:5], 1):
        rows.append(("HTML comment " + str(index), short(str(comment), 160)))
    blob = " ".join(str(item).lower() for item in comments)
    keywords = [word for word in ("password", "secret", "api key", "apikey", "todo", "fixme", "hack") if word in blob]
    if keywords:
        rows.append(("Comment keywords", "Found: " + ", ".join(keywords)))
    return rows


def extract_js_paths(js):
    found = []
    for match in re.findall(r"[\"'](/[A-Za-z0-9_\-./?=&%]{2,120})[\"']", js or ""):
        if match.startswith("//"):
            continue
        if len(match) > 2 and match not in found:
            found.append(match)
    return found[:40]


def seo_rows(soup, metas):
    rows = []
    canonical = ""
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]
        if "canonical" in [item.lower() for item in rel]:
            canonical = tag.get("href", "")
    if canonical:
        rows.append(("Canonical URL", short(canonical, 200)))
    else:
        rows.append(("Canonical URL", "Missing"))
    langs = []
    for tag in soup.find_all("link", href=True):
        if tag.get("hreflang"):
            langs.append(tag.get("hreflang"))
    rows.append(("Hreflang count", str(len(langs))))
    if langs:
        rows.append(("Hreflang langs", ", ".join(sorted(set(langs))[:10])))
    done = sum(1 for key in ("og:title", "og:type", "og:url", "og:image") if metas.get(key))
    rows.append(("OG completeness", str(done) + " of 4"))
    description = metas.get("description", "")
    if description:
        rows.append(("Description length", str(len(description)) + " characters"))
    return rows


def analyze_regex(html, page_url):
    rows = []
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        title = re.sub(r"\s+", " ", match.group(1).strip())
        rows.append(("Page title", short(title, 200)))
    else:
        rows.append(("Page title", "Missing"))
    rows.append(("Meta tag count", str(len(re.findall(r"<meta\b", html, re.IGNORECASE)))))
    hrefs = re.findall(r"href=[\"']([^\"']+)[\"']", html)
    rows.append(("Link count", str(len(hrefs))))
    stats, external_hosts = classify_links(hrefs, page_url)
    rows.append(("Internal links", str(stats["internal"])))
    rows.append(("External links", str(stats["external"])))
    rows.append(("Image count", str(len(re.findall(r"<img\b", html, re.IGNORECASE)))))
    rows.append(("Script count", str(len(re.findall(r"<script\b", html, re.IGNORECASE)))))
    rows.extend(find_contacts(html, hrefs))
    return rows


def classify_links(hrefs, page_url):
    base_host = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    stats = {"internal": 0, "external": 0, "mailto": 0, "tel": 0, "javascript": 0, "fragment": 0, "other": 0}
    external_hosts = {}
    for href in hrefs:
        item = (href or "").strip()
        if not item:
            stats["other"] += 1
            continue
        low = item.lower()
        if low.startswith("mailto:"):
            stats["mailto"] += 1
            continue
        if low.startswith("tel:"):
            stats["tel"] += 1
            continue
        if low.startswith("javascript:"):
            stats["javascript"] += 1
            continue
        if item.startswith("#"):
            stats["fragment"] += 1
            continue
        absolute = urllib.parse.urljoin(page_url, item)
        host = (urllib.parse.urlsplit(absolute).hostname or "").lower()
        if not host or host == base_host:
            stats["internal"] += 1
        else:
            stats["external"] += 1
            external_hosts[host] = external_hosts.get(host, 0) + 1
    return stats, external_hosts


def find_contacts(html, hrefs):
    rows = []
    emails = []
    for match in EMAIL_RE.findall(html):
        if match not in emails:
            emails.append(match)
    rows.append(("Email addresses found", str(len(emails))))
    for index, email in enumerate(emails[:10], 1):
        rows.append(("Email " + str(index), email))
    phones = []
    for match in PHONE_RE.findall(html):
        cleaned = re.sub(r"\s+", " ", match.strip())
        if cleaned not in phones:
            phones.append(cleaned)
    rows.append(("Possible phones found", str(len(phones))))
    for index, phone in enumerate(phones[:10], 1):
        rows.append(("Possible phone " + str(index), phone))
    social = {}
    for href in hrefs:
        low = (href or "").lower()
        for domain, network in SOCIAL.items():
            if domain in low and network not in social:
                social[network] = href
    if social:
        rows.append(("Social profiles", str(len(social))))
    else:
        rows.append(("Social profiles", "None found"))
    for network, href in sorted(social.items()):
        rows.append(("Social: " + network, short(href, 200)))
    return rows


def top_words(text, limit=8):
    words = re.findall(r"[a-zA-Z]{5,}", text.lower())
    counts = Counter(word for word in words if word not in STOPWORDS)
    return counts.most_common(limit)


def extract_version(text, pattern):
    match = re.search(pattern, text or "", re.IGNORECASE)
    if match:
        return match.group(1)
    return ""


def detect_tech(html, headers, cookies, metas):
    found = []
    seen = set()

    def add(name, evidence):
        if name not in seen:
            seen.add(name)
            found.append(("Tech: " + name, evidence))

    low = html.lower()
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    generator = metas.get("generator", "")
    via = headers.get("Via", "")
    server_low = server.lower()
    if "cloudflare" in server_low or headers.get("CF-Ray", ""):
        add("Cloudflare", "CDN and protection, seen in response headers")
    if "nginx" in server_low:
        add("nginx", "Web server, advertised in Server header")
    if "apache" in server_low:
        add("Apache", "Web server, advertised in Server header")
    if "litespeed" in server_low:
        add("LiteSpeed", "Web server, advertised in Server header")
    if "microsoft-iis" in server_low:
        add("IIS", "Web server, advertised in Server header")
    if "openresty" in server_low:
        add("OpenResty", "Web server, advertised in Server header")
    if "caddy" in server_low:
        add("Caddy", "Web server, advertised in Server header")
    if "traefik" in server_low:
        add("Traefik", "Proxy, advertised in Server header")
    if "envoy" in server_low:
        add("Envoy", "Proxy, advertised in Server header")
    if "gunicorn" in server_low:
        add("Gunicorn", "App server, advertised in Server header")
    if "uvicorn" in server_low:
        add("Uvicorn", "App server, advertised in Server header")
    if "werkzeug" in server_low:
        add("Werkzeug", "App server, advertised in Server header")
    if "kestrel" in server_low:
        add("Kestrel", "App server, advertised in Server header")
    if "jetty" in server_low:
        add("Jetty", "App server, advertised in Server header")
    if "coyote" in server_low or "tomcat" in server_low:
        add("Tomcat", "App server, advertised in Server header")
    if server_low in ("gws", "sffe", "gse") or server_low.startswith("gws "):
        add("Google frontend", "Edge server, advertised in Server header")
    if "amazons3" in server_low or "awselb" in server_low or headers.get("X-Amz-Request-Id", ""):
        add("AWS", "Cloud marker seen in response headers")
    if "microsoft-httpapi" in server_low or headers.get("X-Azure-Ref", ""):
        add("Azure", "Cloud marker seen in response headers")
    if "netlify" in server_low or headers.get("X-Nf-Request-Id", ""):
        add("Netlify", "Hosting marker seen in response headers")
    if "vercel" in server_low or headers.get("X-Vercel-Id", ""):
        add("Vercel", "Hosting marker seen in response headers")
    if "heroku" in via.lower() or "heroku" in server_low:
        add("Heroku", "Hosting marker seen in response headers")
    if "fly.io" in via.lower() or "flyio" in server_low:
        add("Fly.io", "Hosting marker seen in response headers")
    if "bunnycdn" in server_low:
        add("BunnyCDN", "CDN, advertised in Server header")
    if "keycdn" in server_low:
        add("KeyCDN", "CDN, advertised in Server header")
    if "varnish" in via.lower() or "varnish" in server_low or headers.get("X-Varnish", ""):
        add("Varnish", "Cache layer, seen in response headers")
    if "cloudfront" in via.lower() or "cloudfront" in server_low:
        add("CloudFront", "CDN, seen in response headers")
    if "fastly" in via.lower() or "fastly" in server_low:
        add("Fastly", "CDN, seen in response headers")
    if "sucuri" in server_low:
        add("Sucuri", "Protection layer, advertised in Server header")
    if "incapsula" in server_low or "imperva" in server_low:
        add("Imperva", "Protection layer, advertised in Server header")
    if headers.get("X-AspNet-Version", ""):
        add("ASP.NET " + headers["X-AspNet-Version"], "Framework, advertised in headers")
    if headers.get("X-AspNetMvc-Version", ""):
        add("ASP.NET MVC " + headers["X-AspNetMvc-Version"], "Framework, advertised in headers")
    if headers.get("X-Runtime", ""):
        add("Ruby on Rails", "Framework, X-Runtime header observed")
    if headers.get("X-Generator", ""):
        add(headers["X-Generator"].split("/")[0].strip() + " (header)", "Declared in X-Generator header")
    if powered:
        name = powered.split("/")[0].strip()
        if name:
            add(name, "Backend, advertised in X-Powered-By header")
    jq_version = extract_version(html, r"jquery[/-](\d+\.\d+(?:\.\d+)?)")
    if "jquery" in low:
        if jq_version:
            add("jQuery " + jq_version, "JavaScript library referenced in page")
        else:
            add("jQuery", "JavaScript library referenced in page")
    if "__next_data__" in low or "_next/static" in low:
        add("Next.js", "Framework marker found in page")
    if "react-dom" in low or "react.production" in low or "react.development" in low:
        add("React", "Library marker found in page")
    if "vue.js" in low or "vue.min.js" in low or "__vue__" in low:
        add("Vue.js", "Framework marker found in page")
    if "ng-version" in low or "angular.min.js" in low:
        add("Angular", "Framework marker found in page")
    if "nuxt" in low:
        add("Nuxt", "Framework marker found in page")
    if "svelte" in low:
        add("Svelte", "Framework marker found in page")
    if "ember.js" in low:
        add("Ember.js", "Framework marker found in page")
    if "htmx" in low:
        add("htmx", "Library marker found in page")
    if "alpinejs" in low or "alpine.js" in low:
        add("Alpine.js", "Library marker found in page")
    if "@vite/client" in low:
        add("Vite", "Build tool marker found in page")
    if "webpackchunk" in low:
        add("webpack", "Bundler marker found in page")
    if "backbone" in low:
        add("Backbone.js", "Library marker found in page")
    if "lodash" in low:
        add("Lodash", "Library marker found in page")
    if "moment.js" in low or "moment.min.js" in low:
        add("Moment.js", "Library marker found in page")
    if "axios" in low:
        add("Axios", "Library marker found in page")
    bs_version = extract_version(html, r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)")
    if "bootstrap" in low:
        if bs_version:
            add("Bootstrap " + bs_version, "CSS framework referenced in page")
        else:
            add("Bootstrap", "CSS framework referenced in page")
    if "tailwind" in low:
        add("Tailwind CSS", "CSS framework marker found in page")
    if "gsap" in low:
        add("GSAP", "Animation library referenced in page")
    if "three.min.js" in low or "three.module.js" in low:
        add("Three.js", "3D library referenced in page")
    if "chart.js" in low or "chart.min.js" in low:
        add("Chart.js", "Chart library referenced in page")
    if "d3.min.js" in low or "d3.v" in low:
        add("D3.js", "Chart library referenced in page")
    if "firebase" in low:
        add("Firebase", "Backend marker found in page")
    if "supabase" in low:
        add("Supabase", "Backend marker found in page")
    if "contentful" in low:
        add("Contentful", "CMS marker found in page")
    if "strapi" in low:
        add("Strapi", "CMS marker found in page")
    if "sanity.io" in low:
        add("Sanity", "CMS marker found in page")
    if "googletagmanager.com" in low:
        add("Google Tag Manager", "Analytics tag found in page")
    if "google-analytics.com" in low or "gtag(" in low:
        add("Google Analytics", "Analytics tag found in page")
    if "connect.facebook.net" in low:
        add("Meta Pixel", "Tracking tag found in page")
    if "hotjar" in low:
        add("Hotjar", "Tracking tag found in page")
    if "matomo" in low:
        add("Matomo", "Analytics tag found in page")
    if "plausible" in low:
        add("Plausible", "Analytics tag found in page")
    if "clarity.ms" in low:
        add("Microsoft Clarity", "Tracking tag found in page")
    if "mc.yandex" in low or "yandex-metrica" in low:
        add("Yandex Metrica", "Analytics tag found in page")
    if "segment.com" in low or "segment.io" in low:
        add("Segment", "Tracking tag found in page")
    if "amplitude" in low:
        add("Amplitude", "Analytics tag found in page")
    if "optimizely" in low:
        add("Optimizely", "Testing tag found in page")
    if "crazyegg" in low:
        add("Crazy Egg", "Tracking tag found in page")
    if "quantcast" in low:
        add("Quantcast", "Tracking tag found in page")
    if "adsbygoogle" in low:
        add("AdSense", "Ad tag found in page")
    if "doubleclick" in low:
        add("DoubleClick", "Ad tag found in page")
    if "criteo" in low:
        add("Criteo", "Ad tag found in page")
    if "taboola" in low:
        add("Taboola", "Ad tag found in page")
    if "outbrain" in low:
        add("Outbrain", "Ad tag found in page")
    if "newrelic" in low:
        add("New Relic", "Monitoring tag found in page")
    if "datadog" in low:
        add("Datadog", "Monitoring tag found in page")
    if "sentry" in low:
        add("Sentry", "Monitoring tag found in page")
    if "intercom" in low:
        add("Intercom", "Chat widget found in page")
    if "zendesk" in low or "zdassets" in low:
        add("Zendesk", "Support widget found in page")
    if "drift.com" in low:
        add("Drift", "Chat widget found in page")
    if "hubspot" in low or "hs-scripts" in low:
        add("HubSpot", "Marketing tag found in page")
    if "mailchimp" in low:
        add("Mailchimp", "Marketing tag found in page")
    if "klaviyo" in low:
        add("Klaviyo", "Marketing tag found in page")
    if "tawk.to" in low:
        add("Tawk.to", "Chat widget found in page")
    if "crisp.chat" in low:
        add("Crisp", "Chat widget found in page")
    if "livechatinc" in low:
        add("LiveChat", "Chat widget found in page")
    if "freshchat" in low:
        add("Freshchat", "Chat widget found in page")
    if "cookiebot" in low:
        add("Cookiebot", "Consent widget found in page")
    if "onetrust" in low:
        add("OneTrust", "Consent widget found in page")
    if "trustpilot" in low:
        add("Trustpilot", "Review widget found in page")
    if "disqus" in low:
        add("Disqus", "Comment widget found in page")
    if generator:
        add(generator.split()[0] + " (generator)", "Declared in meta generator tag")
    if "wp-content" in low or "wp-includes" in low:
        wp_version = extract_version(generator, r"WordPress\s+(\d+\.\d+(?:\.\d+)?)")
        if wp_version:
            add("WordPress " + wp_version, "CMS marker found in page")
        else:
            add("WordPress", "CMS marker found in page")
    if "joomla" in low:
        add("Joomla", "CMS marker found in page")
    if "drupal" in low or headers.get("X-Drupal-Cache", ""):
        add("Drupal", "CMS marker found in page or headers")
    if "prestashop" in low:
        add("PrestaShop", "Store platform marker found")
    if "magento" in low or "/mage/" in low:
        add("Magento", "Store platform marker found")
    if "bigcommerce" in low:
        add("BigCommerce", "Store platform marker found")
    if "cdn.shopify.com" in low or headers.get("X-Shopify-Stage", ""):
        add("Shopify", "Store platform marker found")
    if "static.wixstatic.com" in low or "wix.com" in low:
        add("Wix", "Site builder marker found")
    if "squarespace" in low:
        add("Squarespace", "Site builder marker found")
    if "webflow" in low:
        add("Webflow", "Site builder marker found")
    if "weebly" in low:
        add("Weebly", "Site builder marker found")
    if "ghost.min.js" in low:
        add("Ghost", "CMS marker found in page")
    if "__viewstate" in low:
        add("ASP.NET WebForms", "Page state field found in HTML")
    if "recaptcha" in low:
        add("reCAPTCHA", "Captcha widget found in page")
    if "hcaptcha" in low:
        add("hCaptcha", "Captcha widget found in page")
    if "challenges.cloudflare.com" in low:
        add("Cloudflare Turnstile", "Captcha widget found in page")
    if "js.stripe.com" in low:
        add("Stripe", "Payment script found in page")
    if "paypal" in low:
        add("PayPal", "Payment marker found in page")
    if "font-awesome" in low:
        add("Font Awesome", "Icon font referenced in page")
    if "fonts.googleapis.com" in low or "fonts.gstatic.com" in low:
        add("Google Fonts", "Web font referenced in page")
    if "cdnjs.cloudflare.com" in low:
        add("cdnjs", "Script CDN referenced in page")
    if "cdn.jsdelivr.net" in low:
        add("jsDelivr", "Script CDN referenced in page")
    if "unpkg.com" in low:
        add("UNPKG", "Script CDN referenced in page")
    cookie_names = " ".join(cookie.get("name", "") for cookie in cookies)
    if "PHPSESSID" in cookie_names:
        add("PHP", "Session cookie observed")
    if "csrftoken" in cookie_names or "sessionid" in cookie_names:
        add("Django", "Session cookie observed")
    if "laravel_session" in cookie_names:
        add("Laravel", "Session cookie observed")
    if "JSESSIONID" in cookie_names:
        add("Java backend", "Session cookie observed")
    if "ARRAffinity" in cookie_names:
        add("Azure hosting", "Affinity cookie observed")
    if "wordpress_" in cookie_names or "wp-settings" in cookie_names:
        add("WordPress", "Session cookie observed")
    if "__RequestVerificationToken" in cookie_names:
        add("ASP.NET", "Verification cookie observed")
    return found
