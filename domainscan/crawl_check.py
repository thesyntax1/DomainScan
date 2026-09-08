import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from domainscan.helpers import BROWSER_UA, short


SKIP_EXTENSIONS = (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".js", ".zip", ".mp4", ".woff", ".woff2", ".ico", ".mp3")


def collect(start_url, timeout=8, max_pages=15):
    import requests
    rows = []
    if max_pages <= 0:
        rows.append(("Crawl", "Skipped (disabled in profile)"))
        return {"rows": rows}
    base_host = (urllib.parse.urlsplit(start_url).hostname or "").lower()
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_UA})
    visited = {}
    queue = [start_url]
    while queue and len(visited) < max_pages:
        batch = []
        for url in queue[:8]:
            if url not in visited and url not in batch:
                batch.append(url)
        queue = queue[8:]
        if not batch:
            break

        def fetch(url):
            try:
                response = session.get(url, timeout=timeout)
                return (url, response.status_code, response.text or "", len(response.content or b""))
            except Exception:
                return (url, 0, "", 0)

        with ThreadPoolExecutor(max_workers=6) as pool:
            for url, status, text, size in pool.map(fetch, batch):
                if len(visited) >= max_pages:
                    break
                visited[url] = (status, text, size)
                if status == 200:
                    for link in extract_links(text, url):
                        if len(queue) > 200:
                            break
                        if link not in visited and link not in queue and same_host(link, base_host) and not skipped(link):
                            queue.append(link)
    rows.append(("Pages crawled", str(len(visited))))
    broken = []
    index = 0
    for url, (status, text, size) in visited.items():
        index += 1
        path = urllib.parse.urlsplit(url).path or "/"
        if status == 0:
            rows.append(("Page " + str(index), short(path, 120) + " fetch failed"))
        else:
            title = extract_title(text)
            detail = str(status) + " " + short(path, 100) + " (" + str(size) + " bytes)"
            if title:
                detail = detail + " " + title
            rows.append(("Page " + str(index), detail))
        if status == 404 or status >= 500 or status == 0:
            broken.append((url, status))
    rows.append(("Broken pages", str(len(broken))))
    for url, status in broken[:10]:
        rows.append(("Broken", str(status) + " " + short(url, 160)))
    return {"rows": rows}


def extract_links(html, page_url):
    links = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        hrefs = [tag.get("href", "") for tag in soup.find_all("a", href=True)]
    except Exception:
        hrefs = re.findall(r"href=[\"']([^\"']+)[\"']", html or "")
    for href in hrefs:
        item = (href or "").strip()
        if not item or item.startswith("#") or item.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue
        absolute = urllib.parse.urljoin(page_url, item)
        absolute, _ = urllib.parse.urldefrag(absolute)
        if absolute not in links:
            links.append(absolute)
    return links


def same_host(url, base_host):
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except Exception:
        return False
    scheme = urllib.parse.urlsplit(url).scheme
    return host == base_host and scheme in ("http", "https")


def skipped(url):
    path = urllib.parse.urlsplit(url).path.lower()
    return path.endswith(SKIP_EXTENSIONS)


def extract_title(html):
    match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    if match:
        return short(re.sub(r"\s+", " ", match.group(1).strip()), 100)
    return ""
