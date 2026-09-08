import re
import urllib.parse

from domainscan.content_check import extract_js_paths
from domainscan.helpers import BROWSER_UA, short


SECRET_PATTERNS = [
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("AWS secret", r"(?i)aws_secret[^A-Za-z0-9]{0,5}[0-9A-Za-z/+]{40}"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z\-]+"),
    ("GitHub token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("Private key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Generic secret", r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*[\"'][^\"']{4,80}[\"']"),
]

MAX_FILE_BYTES = 600000


def collect(page_url, html, timeout=8, max_files=6):
    import requests
    rows = []
    if max_files <= 0:
        rows.append(("JS analysis", "Skipped (disabled in profile)"))
        return {"rows": rows}
    texts = []
    inline = extract_inline_js(html)
    if inline.strip():
        texts.append(("(inline scripts)", inline))
    srcs = extract_script_srcs(html, page_url)
    rows.append(("External scripts found", str(len(srcs))))
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_UA})
    fetched = 0
    for src in srcs[:max_files]:
        body = fetch_limited(session, src, timeout)
        if body is None:
            rows.append(("JS fetch failed", short(src, 160)))
            continue
        fetched += 1
        texts.append((src, body))
    rows.append(("JS files analyzed", str(len(texts)) + " (" + str(fetched) + " fetched)"))
    endpoints = []
    for label, body in texts:
        for path in extract_js_paths(body):
            if path not in endpoints:
                endpoints.append(path)
    rows.append(("JS endpoints", str(len(endpoints))))
    for index, path in enumerate(endpoints[:15], 1):
        rows.append(("JS endpoint " + str(index), short(path, 160)))
    secrets = []
    for label, body in texts:
        for kind, pattern in SECRET_PATTERNS:
            for match in re.findall(pattern, body or ""):
                if isinstance(match, tuple):
                    match = match[0]
                preview = str(match)[:8] + "****"
                secrets.append((kind, short(label, 100), preview))
    secrets = secrets[:20]
    if secrets:
        rows.append(("Possible secrets", str(len(secrets))))
        for index, (kind, label, preview) in enumerate(secrets, 1):
            rows.append(("Secret " + str(index), kind + " in " + label + " (" + preview + ")"))
    else:
        rows.append(("Possible secrets", "None spotted"))
    return {"rows": rows}


def extract_inline_js(html):
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html or "", "html.parser")
        return "\n".join(tag.string or "" for tag in soup.find_all("script") if not tag.get("src"))
    except Exception:
        return " ".join(re.findall(r"<script[^>]*>(.*?)</script>", html or "", re.IGNORECASE | re.DOTALL))


def extract_script_srcs(html, page_url):
    srcs = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html or "", "html.parser")
        raw = [tag.get("src", "") for tag in soup.find_all("script") if tag.get("src")]
    except Exception:
        raw = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html or "", re.IGNORECASE)
    for item in raw:
        absolute = urllib.parse.urljoin(page_url, item.strip())
        if absolute.lower().startswith(("http://", "https://")) and absolute not in srcs:
            srcs.append(absolute)
    return srcs


def fetch_limited(session, url, timeout):
    try:
        response = session.get(url, timeout=timeout, stream=True)
        if response.status_code != 200:
            return None
        chunks = []
        size = 0
        for chunk in response.iter_content(65536):
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        try:
            return data.decode(response.encoding or "utf-8", "ignore")
        except Exception:
            return data.decode("utf-8", "ignore")
    except Exception:
        return None
