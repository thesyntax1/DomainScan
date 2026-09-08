import re
import urllib.parse

from domainscan.helpers import BROWSER_UA, short


def collect(html, page_url, headers=None, timeout=8):
    rows = []
    if not html:
        rows.append(("SEO audit", "No page content to analyze"))
        return {"rows": rows}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        rows.append(("SEO audit", "HTML parsing unavailable"))
        return {"rows": rows}
    rows.extend(title_rows(soup))
    rows.extend(meta_rows(soup))
    rows.extend(canonical_rows(soup, page_url, timeout))
    rows.extend(hreflang_rows(soup, timeout))
    rows.extend(social_tag_rows(soup, timeout))
    rows.extend(heading_rows(soup))
    rows.extend(technical_rows(soup, page_url, headers or {}, html))
    return {"rows": rows}


def page_title(soup):
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return ""


def title_rows(soup):
    rows = []
    titles = soup.find_all("title")
    rows.append(("Title tags", str(len(titles))))
    if len(titles) > 1:
        rows.append(("Title issue", "Multiple title tags"))
    title = page_title(soup)
    if not title:
        rows.append(("Title", "Missing"))
        return rows
    rows.append(("Title length", str(len(title)) + " characters"))
    if len(title) < 30:
        rows.append(("Title verdict", "Short (under 30 characters)"))
    elif len(title) > 60:
        rows.append(("Title verdict", "Long (over 60 characters, may truncate)"))
    else:
        rows.append(("Title verdict", "Good length"))
    return rows


def meta_content(soup, key):
    tag = soup.find("meta", attrs={"name": key})
    if tag and tag.get("content"):
        return tag["content"].strip()
    tag = soup.find("meta", attrs={"property": key})
    if tag and tag.get("content"):
        return tag["content"].strip()
    return ""


def meta_rows(soup):
    rows = []
    description = meta_content(soup, "description")
    if not description:
        rows.append(("Meta description", "Missing"))
    else:
        rows.append(("Meta description length", str(len(description)) + " characters"))
        if len(description) < 70:
            rows.append(("Meta description verdict", "Short (under 70 characters)"))
        elif len(description) > 160:
            rows.append(("Meta description verdict", "Long (over 160 characters, may truncate)"))
        else:
            rows.append(("Meta description verdict", "Good length"))
    robots = meta_content(soup, "robots")
    if robots:
        rows.append(("Meta robots", robots))
        low = robots.lower()
        if "noindex" in low:
            rows.append(("Indexing", "Blocked by noindex"))
        if "nofollow" in low:
            rows.append(("Link following", "Blocked by nofollow"))
    else:
        rows.append(("Meta robots", "Not set (page is indexable)"))
    keywords = meta_content(soup, "keywords")
    if keywords:
        rows.append(("Meta keywords", "Present (ignored by Google)"))
    generator = meta_content(soup, "generator")
    if generator:
        rows.append(("Meta generator", short(generator, 120)))
    return rows


def head_status(url, timeout):
    import requests
    try:
        response = requests.head(url, timeout=timeout, headers={"User-Agent": BROWSER_UA}, allow_redirects=True)
        if response.status_code == 405:
            response = requests.get(url, timeout=timeout, headers={"User-Agent": BROWSER_UA}, stream=True)
            response.close()
        return response.status_code
    except Exception:
        return 0


def canonical_rows(soup, page_url, timeout):
    rows = []
    links = soup.find_all("link", attrs={"rel": "canonical"})
    if not links:
        rows.append(("Canonical URL", "Missing"))
        return rows
    if len(links) > 1:
        rows.append(("Canonical issue", "Multiple canonical tags"))
    href = (links[0].get("href", "") or "").strip()
    rows.append(("Canonical URL", short(href, 200)))
    absolute = urllib.parse.urljoin(page_url, href)
    if absolute.rstrip("/") == page_url.rstrip("/"):
        rows.append(("Canonical verdict", "Self-referencing"))
    else:
        rows.append(("Canonical verdict", "Points to another URL"))
    status = head_status(absolute, timeout)
    if status == 200:
        rows.append(("Canonical reachable", "Yes (HTTP 200)"))
    elif status:
        rows.append(("Canonical reachable", "No (HTTP " + str(status) + ")"))
    else:
        rows.append(("Canonical reachable", "Check failed"))
    return rows


def hreflang_rows(soup, timeout):
    rows = []
    links = soup.find_all("link", attrs={"hreflang": True})
    rows.append(("Hreflang tags", str(len(links))))
    if not links:
        return rows
    langs = []
    for link in links:
        code = (link.get("hreflang", "") or "").strip()
        if code and code not in langs:
            langs.append(code)
    rows.append(("Hreflang languages", ", ".join(langs[:12])))
    if "x-default" in [code.lower() for code in langs]:
        rows.append(("Hreflang default", "x-default present"))
    else:
        rows.append(("Hreflang default", "x-default missing"))
    checked = 0
    broken = 0
    for link in links[:5]:
        href = (link.get("href", "") or "").strip()
        if not href:
            continue
        checked += 1
        if head_status(href, timeout) != 200:
            broken += 1
    if checked:
        rows.append(("Hreflang reachable", str(checked - broken) + " of " + str(checked) + " sampled OK"))
    return rows


def social_tag_rows(soup, timeout):
    rows = []
    og_names = ["og:title", "og:description", "og:image", "og:url", "og:type"]
    present = [name for name in og_names if meta_content(soup, name)]
    rows.append(("Open Graph tags", str(len(present)) + " of " + str(len(og_names))))
    missing = [name for name in og_names if name not in present]
    if missing:
        rows.append(("Open Graph missing", ", ".join(missing)))
    og_image = meta_content(soup, "og:image")
    if og_image:
        status = head_status(og_image, timeout)
        if status == 200:
            rows.append(("OG image reachable", "Yes (HTTP 200)"))
        elif status:
            rows.append(("OG image reachable", "No (HTTP " + str(status) + ")"))
        else:
            rows.append(("OG image reachable", "Check failed"))
    twitter = meta_content(soup, "twitter:card")
    if twitter:
        rows.append(("Twitter card", twitter))
    else:
        rows.append(("Twitter card", "Missing"))
    return rows


def heading_rows(soup):
    rows = []
    counts = {}
    for level in range(1, 7):
        counts[level] = len(soup.find_all("h" + str(level)))
    rows.append(("Headings", "h1:" + str(counts[1]) + " h2:" + str(counts[2]) + " h3:" + str(counts[3])))
    if counts[1] == 0:
        rows.append(("H1 verdict", "Missing H1"))
    elif counts[1] > 1:
        rows.append(("H1 verdict", str(counts[1]) + " H1 tags (one is ideal)"))
    else:
        rows.append(("H1 verdict", "Single H1"))
    if counts[1] == 1:
        text = soup.find("h1").get_text(" ", strip=True)
        rows.append(("H1 text", short(text, 120)))
    order = []
    for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        order.append(int(tag.name[1]))
    skips = 0
    for first, second in zip(order, order[1:]):
        if second > first + 1:
            skips += 1
    if skips:
        rows.append(("Heading order", str(skips) + " skipped levels"))
    else:
        rows.append(("Heading order", "No skipped levels"))
    return rows


def technical_rows(soup, page_url, headers, html):
    rows = []
    html_tag = soup.find("html")
    lang = ""
    if html_tag:
        lang = (html_tag.get("lang", "") or "").strip()
    if lang:
        rows.append(("HTML language", lang))
    else:
        rows.append(("HTML language", "Missing (hurts SEO and screen readers)"))
    if soup.find("meta", attrs={"name": "viewport"}):
        rows.append(("Viewport meta", "Present"))
    else:
        rows.append(("Viewport meta", "Missing (not mobile-friendly)"))
    text = soup.get_text(" ", strip=True)
    words = [word for word in re.split(r"\s+", text) if word]
    rows.append(("Word count", str(len(words))))
    if len(words) < 300:
        rows.append(("Content depth", "Thin content (under 300 words)"))
    links = [tag.get("href", "") for tag in soup.find_all("a", href=True)]
    nofollow = 0
    for tag in soup.find_all("a", href=True):
        if "nofollow" in str(tag.get("rel", "")).lower():
            nofollow += 1
    rows.append(("Nofollow links", str(nofollow) + " of " + str(len(links))))
    base = urllib.parse.urlsplit(page_url)
    prefix = base.scheme + "://" + base.netloc
    rows.append(("Sitemap reference", sitemap_reference(prefix)))
    icons = soup.find_all("link", attrs={"rel": "apple-touch-icon"})
    if icons:
        rows.append(("Apple touch icon", "Declared"))
    else:
        rows.append(("Apple touch icon", "Not declared"))
    return rows


def sitemap_reference(prefix):
    import requests
    for candidate in (prefix + "/robots.txt", prefix + "/sitemap.xml"):
        try:
            response = requests.get(candidate, timeout=6, headers={"User-Agent": BROWSER_UA})
            if response.status_code != 200:
                continue
            if "robots.txt" in candidate and "sitemap:" in (response.text or "").lower():
                return "Declared in robots.txt"
            if "sitemap.xml" in candidate:
                return "sitemap.xml exists"
        except Exception:
            continue
    return "No sitemap found"
