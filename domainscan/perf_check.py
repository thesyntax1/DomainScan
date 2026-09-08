import urllib.parse

from domainscan.helpers import short


def collect(web, html, page_url):
    rows = []
    rows.extend(timing_rows(web))
    if not html:
        rows.append(("Page weight", "No page content"))
        return {"rows": rows}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        rows.append(("Page weight", "HTML parsing unavailable"))
        return {"rows": rows}
    rows.extend(weight_rows(soup, html, page_url))
    rows.extend(blocking_rows(soup))
    rows.extend(image_perf_rows(soup))
    rows.append(("Performance score", score(web, soup, html)))
    return {"rows": rows}


def timing_rows(web):
    rows = []
    total = web.get("total_ms", 0)
    ttfb = web.get("ttfb_ms", 0)
    if total:
        rows.append(("Total load time", str(total) + " ms"))
        rows.append(("TTFB verdict", verdict_ms(total, 800, 1800)))
    else:
        rows.append(("Total load time", "Not measured"))
    if ttfb:
        rows.append(("Time to first byte", str(ttfb) + " ms"))
        rows.append(("TTFB verdict detail", verdict_ms(ttfb, 200, 600)))
    version = web.get("http_version", "")
    if version:
        rows.append(("HTTP version", version))
    raw = web.get("raw_bytes", 0)
    decoded = web.get("decoded_bytes", 0)
    if raw and decoded:
        saved = 100 - int(raw * 100 / decoded)
        rows.append(("Transfer size", format_bytes(raw) + " (" + format_bytes(decoded) + " uncompressed)"))
        rows.append(("Compression saving", str(saved) + "%"))
    elif decoded:
        rows.append(("Transfer size", format_bytes(decoded) + " (no compression)"))
    return rows


def verdict_ms(value, good, poor):
    if value <= good:
        return "Good"
    if value <= poor:
        return "Needs improvement"
    return "Poor"


def format_bytes(count):
    if count >= 1048576:
        return str(round(count / 1048576, 2)) + " MB"
    if count >= 1024:
        return str(round(count / 1024, 1)) + " KB"
    return str(count) + " bytes"


def page_host(page_url):
    return (urllib.parse.urlsplit(page_url).hostname or "").lower()


def weight_rows(soup, html, page_url):
    rows = []
    rows.append(("HTML size", format_bytes(len(html.encode("utf-8", "ignore")))))
    scripts = soup.find_all("script", src=True)
    inline = [tag for tag in soup.find_all("script") if not tag.get("src")]
    inline_bytes = sum(len((tag.string or "").encode("utf-8", "ignore")) for tag in inline)
    styles = soup.find_all("link", rel="stylesheet")
    rows.append(("External scripts", str(len(scripts))))
    rows.append(("Inline scripts", str(len(inline)) + " (" + format_bytes(inline_bytes) + ")"))
    rows.append(("Stylesheets", str(len(styles))))
    fonts = [tag for tag in soup.find_all("link", href=True) if "font" in str(tag.get("href")).lower() or str(tag.get("rel", "")).lower() == "preload" and str(tag.get("as", "")).lower() == "font"]
    rows.append(("Font files", str(len(fonts))))
    iframes = soup.find_all("iframe")
    rows.append(("Iframes", str(len(iframes))))
    host = page_host(page_url)
    third = set()
    for tag in soup.find_all(["script", "link", "img"]):
        src = tag.get("src", "") or tag.get("href", "")
        if src.lower().startswith("http"):
            other = (urllib.parse.urlsplit(src).hostname or "").lower()
            if other and other != host:
                third.add(other)
    rows.append(("Third-party hosts", str(len(third))))
    if third:
        rows.append(("Third-party sample", short(", ".join(sorted(third)[:8]), 200)))
    requests = len(scripts) + len(styles) + len(soup.find_all("img")) + len(iframes) + 1
    rows.append(("Estimated requests", "About " + str(requests)))
    return rows


def blocking_rows(soup):
    rows = []
    head = soup.find("head")
    if not head:
        rows.append(("Render blocking", "No head element"))
        return rows
    blocking_js = 0
    deferred = 0
    for tag in head.find_all("script", src=True):
        if tag.has_attr("async") or tag.has_attr("defer"):
            deferred += 1
        else:
            blocking_js += 1
    rows.append(("Blocking scripts in head", str(blocking_js)))
    rows.append(("Deferred scripts in head", str(deferred)))
    blocking_css = 0
    for tag in head.find_all("link", rel="stylesheet"):
        media = str(tag.get("media", "")).lower()
        if not media or media in ("all", "screen"):
            blocking_css += 1
    rows.append(("Blocking stylesheets", str(blocking_css)))
    preload = soup.find_all("link", attrs={"rel": "preload"})
    preconnect = soup.find_all("link", attrs={"rel": "preconnect"})
    rows.append(("Preload hints", str(len(preload))))
    rows.append(("Preconnect hints", str(len(preconnect))))
    return rows


def image_perf_rows(soup):
    rows = []
    images = soup.find_all("img")
    if not images:
        rows.append(("Images", "None"))
        return rows
    lazy = [img for img in images if str(img.get("loading", "")).lower() == "lazy"]
    rows.append(("Lazy-loaded images", str(len(lazy)) + " of " + str(len(images))))
    sized = [img for img in images if img.get("width") and img.get("height")]
    rows.append(("Images with dimensions", str(len(sized)) + " of " + str(len(images)) + " (prevents layout shift)"))
    modern = [img for img in images if str(img.get("src", "")).lower().endswith((".webp", ".avif"))]
    rows.append(("Modern formats", str(len(modern)) + " webp/avif"))
    pictures = soup.find_all("picture")
    rows.append(("Picture elements", str(len(pictures))))
    return rows


def score(web, soup, html):
    problems = 0
    total = web.get("total_ms", 0)
    if total > 1800:
        problems += 3
    elif total > 800:
        problems += 1
    raw = web.get("raw_bytes", 0)
    decoded = web.get("decoded_bytes", 0)
    if decoded and (not raw or raw >= decoded):
        problems += 1
    head = soup.find("head")
    if head:
        blocking = sum(1 for tag in head.find_all("script", src=True) if not tag.has_attr("async") and not tag.has_attr("defer"))
        if blocking > 3:
            problems += 2
        elif blocking > 0:
            problems += 1
    size = len(html.encode("utf-8", "ignore"))
    if size > 500000:
        problems += 2
    elif size > 200000:
        problems += 1
    problems = min(problems, 10)
    return str((10 - problems) * 10) + "/100 (" + str(problems) + " issue points)"
