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
        rows.append(("External images", str(count_external_refs(images, "src", page_url))))
    scripts = soup.find_all("script")
    inline = [tag for tag in scripts if not tag.get("src")]
    external = [tag.get("src", "") for tag in scripts if tag.get("src")]
    rows.append(("Script count", str(len(scripts))))
    rows.append(("Inline scripts", str(len(inline))))
    rows.append(("External scripts", str(len(external))))
    for index, src in enumerate(external[:10], 1):
        rows.append(("Script " + str(index), short(src, 200)))
    rows.extend(sri_rows(soup))
    rows.extend(jquery_rows(soup, html))
    styles = []
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]
        if "stylesheet" in [item.lower() for item in rel]:
            styles.append(tag.get("href", ""))
    rows.append(("Stylesheet count", str(len(styles))))
    rows.append(("External stylesheets", str(count_external_refs([tag for tag in soup.find_all("link", href=True)], "href", page_url))))
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
    rows.extend(login_form_rows(forms))
    rows.extend(form_security_rows(forms, page_url))
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
    rows.extend(trace_rows(html))
    rows.extend(dom_rows(soup))
    rows.extend(pwa_rows(soup, html))
    rows.extend(resource_host_rows(soup, page_url))
    rows.extend(base_tag_rows(soup, page_url))
    rows.extend(tabnabbing_rows(soup))
    rows.extend(iframe_sandbox_rows(soup))
    rows.extend(refresh_rows(soup))
    rows.extend(duplicate_id_rows(soup))
    rows.extend(deprecated_tag_rows(soup))
    rows.extend(autocomplete_rows(soup))
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
    rows.extend(jsonld_rows(soup))
    text = soup.get_text(" ", strip=True)
    words = text.split()
    rows.append(("Visible words", str(len(words))))
    rows.append(("Visible text size", str(len(text)) + " characters"))
    for index, (word, count) in enumerate(top_words(text), 1):
        rows.append(("Top word " + str(index), word + " (" + str(count) + " times)"))
    rows.extend(find_contacts(html, hrefs))
    return rows


def base_tag_rows(soup, page_url):
    rows = []
    tags = soup.find_all("base", href=True)
    if not tags:
        return rows
    rows.append(("Base tags", str(len(tags))))
    page_host = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    for tag in tags[:3]:
        href = tag.get("href", "")
        if href.lower().startswith("http"):
            host = (urllib.parse.urlsplit(href).hostname or "").lower()
            if host and host != page_host:
                rows.append(("Base tag hijack", "External base " + short(href, 140) + " (all relative URLs resolve there)"))
            else:
                rows.append(("Base tag", short(href, 140)))
        else:
            rows.append(("Base tag", short(href, 140)))
    return rows


def tabnabbing_rows(soup):
    rows = []
    targets = [tag for tag in soup.find_all("a", href=True) if str(tag.get("target", "")).lower() == "_blank"]
    if not targets:
        return rows
    rows.append(("New-tab links", str(len(targets))))
    exposed = 0
    for tag in targets:
        rel = str(tag.get("rel", "")).lower()
        if "noopener" not in rel and "noreferrer" not in rel:
            exposed += 1
    if exposed:
        rows.append(("Tabnabbing risk", str(exposed) + " target=_blank links lack rel=noopener"))
    else:
        rows.append(("Tabnabbing risk", "All new-tab links use rel=noopener"))
    return rows


def iframe_sandbox_rows(soup):
    rows = []
    frames = soup.find_all("iframe")
    if not frames:
        return rows
    unsandboxed = [frame for frame in frames if not frame.has_attr("sandbox")]
    rows.append(("Unsandboxed iframes", str(len(unsandboxed)) + " of " + str(len(frames))))
    for frame in unsandboxed[:5]:
        rows.append(("Unsandboxed iframe", short(frame.get("src", "") or "(no src)", 160)))
    return rows


def refresh_rows(soup):
    rows = []
    for tag in soup.find_all("meta"):
        if str(tag.get("http-equiv", "")).lower() != "refresh":
            continue
        content = tag.get("content", "")
        rows.append(("Meta refresh", short(content, 160)))
        low = content.lower()
        if "url=http" in low.replace(" ", ""):
            rows.append(("Meta refresh target", "Redirects to absolute URL (review)"))
    return rows


def duplicate_id_rows(soup):
    rows = []
    seen = {}
    dupes = set()
    for tag in soup.find_all(id=True):
        value = tag.get("id", "")
        if value in seen:
            dupes.add(value)
        else:
            seen[value] = True
    if dupes:
        rows.append(("Duplicate IDs", str(len(dupes)) + ": " + short(", ".join(sorted(dupes)[:8]), 180)))
    return rows


def deprecated_tag_rows(soup):
    rows = []
    hits = {}
    for name in ("font", "center", "marquee", "blink", "applet", "frame", "frameset", "big", "strike"):
        count = len(soup.find_all(name))
        if count:
            hits[name] = count
    if hits:
        rows.append(("Deprecated tags", ", ".join(name + "x" + str(hits[name]) for name in sorted(hits))))
    return rows


def autocomplete_rows(soup):
    rows = []
    passwords = soup.find_all("input", {"type": "password"})
    if not passwords:
        return rows
    off = sum(1 for tag in passwords if str(tag.get("autocomplete", "")).lower() in ("off", "new-password"))
    rows.append(("Password autocomplete", str(off) + " of " + str(len(passwords)) + " disable storage"))
    ccs = [tag for tag in soup.find_all("input") if "card" in str(tag.get("name", "")).lower() or "card" in str(tag.get("id", "")).lower() or "cc-" in str(tag.get("autocomplete", "")).lower()]
    if ccs:
        rows.append(("Card fields", str(len(ccs)) + " possible payment inputs"))
    return rows


def sri_rows(soup):
    rows = []
    scripts = soup.find_all("script", src=True)
    if scripts:
        protected = sum(1 for tag in scripts if tag.get("integrity"))
        rows.append(("Scripts with integrity", str(protected) + " of " + str(len(scripts))))
        if protected < len(scripts):
            rows.append(("SRI gap (JS)", str(len(scripts) - protected) + " scripts lack Subresource Integrity"))
    styles = [tag for tag in soup.find_all("link", href=True) if "stylesheet" in str(tag.get("rel", "")).lower()]
    if styles:
        protected = sum(1 for tag in styles if tag.get("integrity"))
        rows.append(("Stylesheets with integrity", str(protected) + " of " + str(len(styles))))
    return rows


def jquery_rows(soup, html):
    rows = []
    version = ""
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "") or ""
        match = re.search(r"jquery[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", src, re.IGNORECASE)
        if match:
            version = match.group(1)
            break
    if not version:
        version = extract_version(html, r"jQuery(?: JavaScript Library)? v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
    if not version:
        return rows
    rows.append(("jQuery version", version))
    try:
        major = int(version.split(".")[0])
    except Exception:
        major = 3
    if major < 3:
        rows.append(("jQuery verdict", "Version 1.x/2.x is end-of-life (known XSS issues)"))
    elif version.startswith("3."):
        rows.append(("jQuery verdict", "Version 3.x (maintained branch)"))
    vuln = vuln_lookup("jQuery", version)
    if vuln:
        rows.append(("jQuery vulnerability", vuln))
    return rows


def form_security_rows(forms, page_url):
    rows = []
    if not forms:
        return rows
    csrf_names = ("csrf", "xsrf", "authenticity_token", "__requestverificationtoken", "_token", "nonce", "form_token")
    without_token = 0
    uploads = 0
    get_with_password = 0
    external_http = 0
    for form in forms:
        inputs = form.find_all("input")
        names = " ".join((tag.get("name", "") or "") + " " + (tag.get("id", "") or "") for tag in inputs).lower()
        if not any(token in names for token in csrf_names):
            without_token += 1
        if any((tag.get("type", "") or "").lower() == "file" for tag in inputs):
            uploads += 1
        method = (form.get("method", "get") or "get").lower()
        if method == "get" and any((tag.get("type", "") or "").lower() == "password" for tag in inputs):
            get_with_password += 1
        action = form.get("action", "") or ""
        if action.lower().startswith("http://"):
            external_http += 1
    rows.append(("Forms without CSRF token", str(without_token) + " of " + str(len(forms))))
    if uploads:
        rows.append(("File upload forms", str(uploads)))
    if get_with_password:
        rows.append(("Password over GET", str(get_with_password) + " forms (credentials in URL)"))
    if external_http:
        rows.append(("Forms to plain HTTP", str(external_http)))
    novalidate = sum(1 for form in forms if form.has_attr("novalidate"))
    if novalidate:
        rows.append(("Forms with novalidate", str(novalidate)))
    return rows


def trace_rows(html):
    rows = []
    patterns = {
        "Python traceback": "Traceback (most recent call last)",
        "PHP fatal error": "Fatal error:",
        "PHP warning": "Warning: mysql",
        "ASP.NET error": "Server Error in '/' Application",
        ".NET exception": "NullReferenceException",
        "Java stack trace": "at java.base/java",
        "SQL error": "SQL syntax",
        "Oracle error": "ORA-",
        "Django error": "DisallowedHost",
        "Node error": "at async ",
    }
    low = (html or "")
    hits = [label for label, marker in patterns.items() if marker in low]
    if hits:
        rows.append(("Error disclosure", str(len(hits)) + " stack-trace markers: " + ", ".join(hits)))
    else:
        rows.append(("Error disclosure", "No stack-trace markers"))
    return rows


def dom_rows(soup):
    rows = []
    tags = soup.find_all(True)
    rows.append(("DOM elements", str(len(tags))))
    kinds = set(tag.name for tag in tags)
    rows.append(("DOM tag kinds", str(len(kinds))))
    if tags and len(tags) <= 20000:
        depth = 0
        for tag in tags:
            level = 0
            parent = tag.parent
            while parent is not None and getattr(parent, "name", "") != "[document]":
                level += 1
                parent = parent.parent
                if level > 60:
                    break
            if level > depth:
                depth = level
        rows.append(("DOM max depth", str(depth)))
    return rows


def pwa_rows(soup, html):
    rows = []
    manifest = soup.find("link", attrs={"rel": "manifest"})
    if manifest:
        rows.append(("Web manifest", "Linked (" + short(manifest.get("href", ""), 120) + ")"))
    else:
        rows.append(("Web manifest", "Not linked"))
    if "serviceWorker" in (html or "") and "register" in (html or ""):
        rows.append(("Service worker", "Registration code found"))
    else:
        rows.append(("Service worker", "No registration code"))
    return rows


def resource_host_rows(soup, page_url):
    rows = []
    base_host = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    hosts = {}
    for tag in soup.find_all(["script", "link", "img"]):
        src = tag.get("src", "") or tag.get("href", "")
        if src.lower().startswith("http"):
            host = (urllib.parse.urlsplit(src).hostname or "").lower()
            if host and host != base_host:
                hosts[host] = hosts.get(host, 0) + 1
    if not hosts:
        rows.append(("Resource hosts", "All resources are same-host"))
        return rows
    rows.append(("Resource hosts", str(len(hosts)) + " external hosts"))
    for index, host in enumerate(sorted(hosts, key=lambda h: -hosts[h])[:10], 1):
        rows.append(("Resource host " + str(index), host + " (" + str(hosts[host]) + " refs)"))
    return rows


def login_form_rows(forms):
    rows = []
    logins = []
    for form in forms:
        inputs = form.find_all("input")
        types = [(tag.get("type", "text") or "text").lower() for tag in inputs]
        names = " ".join((tag.get("name", "") or "") for tag in inputs).lower()
        if "password" in types and ("text" in types or "email" in types or "user" in names or "login" in names):
            logins.append(form.get("action", "") or "(same page)")
    rows.append(("Login forms", str(len(logins))))
    for index, action in enumerate(logins[:3], 1):
        rows.append(("Login form " + str(index), short(action, 160)))
    return rows


def jsonld_rows(soup):
    import json
    rows = []
    blocks = soup.find_all("script", {"type": "application/ld+json"})
    rows.append(("JSON-LD blocks", str(len(blocks))))
    types = []
    invalid = 0
    for block in blocks:
        try:
            data = json.loads(block.string or "")
        except Exception:
            invalid += 1
            continue
        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("@graph", [data]) if isinstance(data.get("@graph"), list) else [data]
        for item in items:
            if isinstance(item, dict) and item.get("@type") and item["@type"] not in types:
                types.append(str(item["@type"]))
    if types:
        rows.append(("Schema types", ", ".join(types[:10])))
    if invalid:
        rows.append(("JSON-LD invalid", str(invalid) + " blocks fail to parse"))
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


def count_external_refs(tags, attr, page_url):
    base_host = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    count = 0
    for tag in tags:
        value = (tag.get(attr, "") or "").strip()
        if value.lower().startswith("http"):
            host = (urllib.parse.urlsplit(value).hostname or "").lower()
            if host and host != base_host:
                count += 1
    return count


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


VULN_DB = [
    ("jQuery", "3.5.0", "below 3.5.0 is affected by published XSS CVEs"),
    ("Lodash", "4.17.21", "below 4.17.21 is affected by prototype pollution CVE-2020-8203"),
    ("Bootstrap", "4.3.1", "below 4.3.1 is affected by published XSS CVEs"),
    ("Moment", "2.29.4", "below 2.29.4 is affected by ReDoS CVE-2022-24785"),
    ("Handlebars", "4.7.7", "below 4.7.7 is affected by template code execution CVEs"),
]

EOL_LIBS = {
    "jQuery 1": "jQuery 1.x is end-of-life",
    "jQuery 2": "jQuery 2.x is end-of-life",
    "Bootstrap 3": "Bootstrap 3.x is end-of-life",
    "Bootstrap 2": "Bootstrap 2.x is end-of-life",
    "AngularJS 1": "AngularJS 1.x is end-of-life since January 2022",
    "Vue 1": "Vue 1.x is end-of-life",
    "CKEditor 4": "CKEditor 4.x reached end-of-life in June 2023",
    "Prototype": "Prototype.js is end-of-life",
    "MooTools": "MooTools is end-of-life",
}


def version_tuple(version):
    parts = []
    for bit in str(version or "").split("."):
        digits = "".join(char for char in bit if char.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def version_below(found, minimum):
    have = version_tuple(found)
    want = version_tuple(minimum)
    if not have or not want:
        return False
    length = max(len(have), len(want))
    have = have + (0,) * (length - len(have))
    want = want + (0,) * (length - len(want))
    return have < want


def vuln_lookup(name, version):
    low = (name or "").lower()
    for lib, minimum, label in VULN_DB:
        if lib.lower() == low and version_below(version, minimum):
            return lib + " " + str(version) + " " + label
    major = str(version or "").split(".")[0]
    key = (name or "") + " " + major
    if key in EOL_LIBS:
        return EOL_LIBS[key] + " (" + str(version) + ")"
    if low in ("prototype", "mootools"):
        return EOL_LIBS.get(name, "")
    return ""


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
    if "solid-js" in low or "solidjs" in low:
        add("SolidJS", "Library marker found in page")
    if "preact" in low:
        add("Preact", "Library marker found in page")
    if "lit-element" in low or "lit-html" in low:
        add("Lit", "Library marker found in page")
    if "@remix-run" in low:
        add("Remix", "Framework marker found in page")
    if "astro-" in low:
        add("Astro", "Framework marker found in page")
    if "gatsby-" in low:
        add("Gatsby", "Framework marker found in page")
    if "/load.php" in low or "mediawiki" in low:
        add("MediaWiki", "Wiki marker found in page")
    if "phpbb" in low:
        add("phpBB", "Forum marker found in page")
    if "vbulletin" in low:
        add("vBulletin", "Forum marker found in page")
    if "discourse" in low:
        add("Discourse", "Forum marker found in page")
    if "nodebb" in low:
        add("NodeBB", "Forum marker found in page")
    if "flarum" in low:
        add("Flarum", "Forum marker found in page")
    if "xenforo" in low:
        add("XenForo", "Forum marker found in page")
    if "mybb" in low:
        add("MyBB", "Forum marker found in page")
    if "data-craft" in low or "craft cms" in low:
        add("Craft CMS", "CMS marker found in page")
    if "expressionengine" in low:
        add("ExpressionEngine", "CMS marker found in page")
    if "silverstripe" in low:
        add("SilverStripe", "CMS marker found in page")
    if "umbraco" in low:
        add("Umbraco", "CMS marker found in page")
    if "kentico" in low:
        add("Kentico", "CMS marker found in page")
    if "sitecore" in low:
        add("Sitecore", "CMS marker found in page")
    if "/etc.clientlibs" in low:
        add("Adobe AEM", "CMS marker found in page")
    if "liferay" in low:
        add("Liferay", "CMS marker found in page")
    if "typo3" in low:
        add("TYPO3", "CMS marker found in page")
    if "concrete5" in low or "concretecms" in low:
        add("Concrete CMS", "CMS marker found in page")
    if "getgrav" in low:
        add("Grav", "CMS marker found in page")
    if "kirby" in low:
        add("Kirby", "CMS marker found in page")
    if "statamic" in low:
        add("Statamic", "CMS marker found in page")
    if "octobercms" in low:
        add("OctoberCMS", "CMS marker found in page")
    if "processwire" in low:
        add("ProcessWire", "CMS marker found in page")
    if "opencart" in low:
        add("OpenCart", "Store platform marker found")
    if "shopware" in low:
        add("Shopware", "Store platform marker found")
    if "saleor" in low:
        add("Saleor", "Store platform marker found")
    if "nopcommerce" in low:
        add("nopCommerce", "Store platform marker found")
    if "moodle" in low:
        add("Moodle", "LMS marker found in page")
    if "docusaurus" in low:
        add("Docusaurus", "Docs generator marker found")
    if "mkdocs" in low:
        add("MkDocs", "Docs generator marker found")
    if "sphinxdoc" in low:
        add("Sphinx", "Docs generator marker found")
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
    if "django" in generator.lower() or "csrftoken" in low:
        add("Django", "Marker found in page or generator")
    if "rails" in generator.lower() or "phusion passenger" in server_low:
        add("Ruby on Rails", "Marker found in page or headers")
    if "laravel" in low or "laravel_session" in low:
        add("Laravel", "Marker found in page")
    if "symfony" in low or "symfony" in powered.lower():
        add("Symfony", "Marker found in page or headers")
    if "codeigniter" in low:
        add("CodeIgniter", "Marker found in page")
    if "cakephp" in low:
        add("CakePHP", "Marker found in page")
    if "yii.js" in low:
        add("Yii", "Marker found in page")
    if "flask" in low and ("flask" in powered.lower() or "werkzeug" in low):
        add("Flask", "Marker found in page or headers")
    if "fastapi" in low or "fastapi" in powered.lower():
        add("FastAPI", "Marker found in page or headers")
    if "express" in powered.lower() or "express" in server_low:
        add("Express.js", "Marker found in headers")
    if "next.js" in low or "__next" in low or "next/router" in low:
        add("Next.js", "Marker found in page")
    if "nuxt" in low or "__nuxt" in low:
        add("Nuxt.js", "Marker found in page")
    if "gatsby" in low or "gatsby-" in low:
        add("Gatsby", "Marker found in page")
    if "remix" in low and ("remix.run" in low or "__remix" in low):
        add("Remix", "Marker found in page")
    if "astro" in generator.lower() or "astro-" in low:
        add("Astro", "Marker found in page or generator")
    if "svelte" in low and ("svelte-" in low or "sveltekit" in low):
        add("Svelte", "Marker found in page")
    if "alpine.js" in low or "x-data" in low:
        add("Alpine.js", "Marker found in page")
    if "htmx" in low:
        add("htmx", "Marker found in page")
    if "tailwind" in low:
        add("Tailwind CSS", "Marker found in page")
    if "bootstrap" in low:
        version = extract_version(low, r"bootstrap[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
        if version:
            add("Bootstrap " + version, "Stylesheet or script observed")
        else:
            add("Bootstrap", "Marker found in page")
    if "bulma" in low:
        add("Bulma", "Marker found in page")
    if "foundation" in low and "foundation.min" in low:
        add("Foundation", "Marker found in page")
    if "materialize" in low:
        add("Materialize", "Marker found in page")
    if "antd" in low or "ant-design" in low:
        add("Ant Design", "Marker found in page")
    if "mui" in low and ("mui-" in low or "@mui" in low):
        add("Material UI", "Marker found in page")
    if "chakra" in low and "chakra-" in low:
        add("Chakra UI", "Marker found in page")
    if "storybook" in low:
        add("Storybook", "Marker found in page")
    if "graphql" in low:
        add("GraphQL", "Marker found in page")
    if "apollo" in low and ("apollo-client" in low or "__apollo" in low):
        add("Apollo", "Marker found in page")
    if "firebase" in low:
        add("Firebase", "Marker found in page")
    if "supabase" in low:
        add("Supabase", "Marker found in page")
    if "amplify" in low and "aws-amplify" in low:
        add("AWS Amplify", "Marker found in page")
    if "contentful" in low:
        add("Contentful", "Marker found in page")
    if "sanity.io" in low:
        add("Sanity", "Marker found in page")
    if "strapi" in low:
        add("Strapi", "Marker found in page")
    if "hugo" in generator.lower():
        add("Hugo", "Declared in meta generator")
    if "jekyll" in generator.lower():
        add("Jekyll", "Declared in meta generator")
    if "typo3" in generator.lower():
        add("TYPO3", "Declared in meta generator")
    if "webflow" in generator.lower() or "webflow" in low:
        add("Webflow", "Marker found in page or generator")
    if "wix.com" in low or "wixstatic" in low:
        add("Wix", "Marker found in page")
    if "squarespace" in low:
        add("Squarespace", "Marker found in page")
    if "weebly" in low:
        add("Weebly", "Marker found in page")
    if "shopify" in low:
        add("Shopify", "Marker found in page")
    if "magento" in low or "mage/" in low:
        add("Magento", "Marker found in page")
    if "woocommerce" in low:
        add("WooCommerce", "Marker found in page")
    if "prestashop" in low:
        add("PrestaShop", "Marker found in page")
    if "opencart" in low:
        add("OpenCart", "Marker found in page")
    if "bigcommerce" in low:
        add("BigCommerce", "Marker found in page")
    if "salesforce" in low and ("commercecloud" in low or "demandware" in low):
        add("Salesforce Commerce", "Marker found in page")
    if "discourse" in low:
        add("Discourse", "Marker found in page")
    if "phpbb" in low:
        add("phpBB", "Marker found in page")
    if "vbulletin" in low:
        add("vBulletin", "Marker found in page")
    if "xenforo" in low:
        add("XenForo", "Marker found in page")
    if "mediawiki" in generator.lower():
        add("MediaWiki", "Declared in meta generator")
    if "dokuwiki" in low:
        add("DokuWiki", "Marker found in page")
    if "confluence" in low:
        add("Confluence", "Marker found in page")
    if "sharepoint" in low:
        add("SharePoint", "Marker found in page")
    if "_debug_toolbar" in low:
        add("Django Debug Toolbar", "Debug toolbar exposed in page")
    if "webpack" in low:
        add("webpack", "Bundler marker found in page")
    if "vite" in low and ("/@vite/" in low or "vite.svg" in low):
        add("Vite", "Bundler marker found in page")
    if "parcel" in low and "parcel-require" in low:
        add("Parcel", "Bundler marker found in page")
    if "rollup" in low and "rollup-" in low:
        add("Rollup", "Bundler marker found in page")
    if "ember" in low and ("ember-" in low or "vendor/ember" in low):
        add("Ember.js", "Marker found in page")
    if "backbone" in low and "backbone-min" in low:
        add("Backbone.js", "Marker found in page")
    if "knockout" in low:
        add("Knockout.js", "Marker found in page")
    if "lodash" in low:
        version = extract_version(low, r"lodash[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
        if version:
            add("Lodash " + version, "Library observed")
        else:
            add("Lodash", "Marker found in page")
    if "moment.js" in low or "moment.min.js" in low:
        add("Moment.js", "Library observed")
    if "d3.js" in low or "d3.min.js" in low:
        add("D3.js", "Library observed")
    if "chart.js" in low or "chart.min.js" in low:
        add("Chart.js", "Library observed")
    if "three.js" in low or "three.min.js" in low:
        add("Three.js", "Library observed")
    if "leaflet" in low:
        add("Leaflet", "Map library observed")
    if "mapbox" in low:
        add("Mapbox", "Map library observed")
    if "openlayers" in low:
        add("OpenLayers", "Map library observed")
    if "ckeditor" in low:
        add("CKEditor", "Editor observed")
    if "tinymce" in low:
        add("TinyMCE", "Editor observed")
    if "monaco" in low and "monaco-editor" in low:
        add("Monaco Editor", "Editor observed")
    if "recaptcha" in low:
        add("reCAPTCHA", "Captcha observed")
    if "hcaptcha" in low:
        add("hCaptcha", "Captcha observed")
    if "cloudflare" in low and ("turnstile" in low or "cf_chl" in low):
        add("Cloudflare challenge", "Challenge marker found in page")
    if "datadome" in low:
        add("DataDome", "Bot protection marker found")
    if "perimeterx" in low or "px-captcha" in low:
        add("PerimeterX", "Bot protection marker found")
    if "akamai" in low and ("sensor" in low or "_abck" in low):
        add("Akamai Bot Manager", "Bot protection marker found")
    if "cookielaw" in low or "onetrust" in low:
        add("OneTrust", "Consent manager observed")
    if "cookiebot" in low:
        add("Cookiebot", "Consent manager observed")
    if "trustarc" in low:
        add("TrustArc", "Consent manager observed")
    if "newrelic" in low:
        add("New Relic", "Monitoring marker found")
    if "sentry" in low and ("sentry.io" in low or "@sentry" in low):
        add("Sentry", "Error tracking observed")
    if "bugsnag" in low:
        add("Bugsnag", "Error tracking observed")
    if "hotjar" in low:
        add("Hotjar", "Analytics marker found")
    if "fullstory" in low:
        add("FullStory", "Analytics marker found")
    if "mixpanel" in low:
        add("Mixpanel", "Analytics marker found")
    if "amplitude" in low:
        add("Amplitude", "Analytics marker found")
    if "segment.io" in low or "segment.com" in low:
        add("Segment", "Analytics marker found")
    if "optimizely" in low:
        add("Optimizely", "Experimentation marker found")
    if "crazyegg" in low:
        add("Crazy Egg", "Analytics marker found")
    if "criteo" in low:
        add("Criteo", "Ad marker found")
    if "taboola" in low:
        add("Taboola", "Ad marker found")
    if "outbrain" in low:
        add("Outbrain", "Ad marker found")
    if "doubleclick" in low or "googlesyndication" in low:
        add("Google Ads", "Ad marker found")
    return found
