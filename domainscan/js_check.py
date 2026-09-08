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
    rows.extend(framework_rows(texts))
    rows.extend(library_version_rows(texts))
    rows.extend(danger_rows(texts))
    rows.extend(postmessage_rows(texts))
    rows.extend(storage_rows(texts))
    rows.extend(debug_rows(texts))
    rows.extend(endpoint_key_rows(endpoints))
    rows.extend(sourcemap_rows(session, texts, timeout))
    return {"rows": rows}


FRAMEWORKS = [
    ("webpack", "webpack"),
    ("React", "react-dom"),
    ("React", "_reactroot"),
    ("Vue", "__vue__"),
    ("Vue", "vue-router"),
    ("Angular", "ng-version"),
    ("Angular", "@angular/core"),
    ("Ember", "ember-"),
    ("Backbone", "backbone-min"),
    ("Svelte", "svelte-"),
    ("Next.js", "__next"),
    ("Nuxt", "__nuxt"),
    ("Alpine.js", "alpinejs"),
    ("htmx", "htmx.org"),
    ("Meteor", "__meteor"),
]


def framework_rows(texts):
    rows = []
    blob = " ".join(body or "" for _, body in texts).lower()
    found = []
    for name, marker in FRAMEWORKS:
        if marker in blob and name not in found:
            found.append(name)
    if found:
        rows.append(("JS frameworks", ", ".join(found)))
    else:
        rows.append(("JS frameworks", "None identified"))
    return rows


LIB_VERSIONS = [
    ("jQuery", r"jquery[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("React", r"react[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Vue", r"vue[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Angular", r"@angular/core[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("AngularJS", r"angular\.js[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Handlebars", r"handlebars[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("CKEditor", r"ckeditor[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Prototype", r"prototype[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("MooTools", r"mootools[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Lodash", r"lodash[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Moment", r"moment[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("D3", r"d3[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Bootstrap", r"bootstrap[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
]


def library_version_rows(texts):
    rows = []
    blob = " ".join(body or "" for _, body in texts)
    hits = []
    for name, pattern in LIB_VERSIONS:
        match = re.search(pattern, blob, re.IGNORECASE)
        if match and name not in [item[0] for item in hits]:
            hits.append((name, match.group(1)))
    if not hits:
        return rows
    for name, version in hits[:8]:
        rows.append(("JS library: " + name, version))
    for name, version in hits:
        if name == "jQuery" and version.split(".")[0] in ("1", "2"):
            rows.append(("jQuery in JS", "End-of-life " + version + " (known XSS issues)"))
    from domainscan.content_check import vuln_lookup
    for name, version in hits:
        label = vuln_lookup(name, version)
        if label:
            rows.append(("JS library risk: " + name, label))
    return rows


def postmessage_rows(texts):
    rows = []
    blob = " ".join(body or "" for _, body in texts)
    listeners = len(re.findall(r"addEventListener\s*\(\s*[\"']message[\"']", blob))
    posts = blob.count("postMessage")
    if not listeners and not posts:
        rows.append(("postMessage use", "None found"))
        return rows
    rows.append(("postMessage use", str(listeners) + " listeners, " + str(posts) + " posts"))
    unchecked = 0
    for match in re.finditer(r"addEventListener\s*\(\s*[\"']message[\"']", blob):
        window = blob[match.start():match.start() + 800]
        if ".origin" not in window and "origin ===" not in window:
            unchecked += 1
    if unchecked:
        rows.append(("postMessage origin check", str(unchecked) + " listeners without origin validation"))
    else:
        rows.append(("postMessage origin check", "Listeners validate origin"))
    return rows


def storage_rows(texts):
    rows = []
    blob = " ".join(body or "" for _, body in texts)
    hits = []
    for match in re.finditer(r"(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*[\"']([^\"']+)[\"']", blob):
        key = match.group(2).lower()
        if any(word in key for word in ("pass", "token", "secret", "key", "auth", "credential", "ssn")):
            hits.append(match.group(2))
    if hits:
        rows.append(("Secrets in web storage", str(len(hits)) + " suspicious keys"))
        for key in hits[:5]:
            rows.append(("Storage key", short(key, 100) + " (readable by any page script)"))
    else:
        rows.append(("Secrets in web storage", "None spotted"))
    return rows


def debug_rows(texts):
    rows = []
    blob = " ".join(body or "" for _, body in texts)
    logs = blob.count("console.log") + blob.count("console.debug") + blob.count("console.info")
    debuggers = len(re.findall(r"\bdebugger\b", blob))
    todos = blob.count("TODO") + blob.count("FIXME")
    rows.append(("Debug leftovers", str(logs) + " console calls, " + str(debuggers) + " debugger statements"))
    if todos:
        rows.append(("TODO/FIXME in JS", str(todos)))
    if "sourceMappingURL=data:" in blob.replace(" ", ""):
        rows.append(("Inline source map", "Embedded (exposes original sources)"))
    return rows


def endpoint_key_rows(endpoints):
    rows = []
    hits = []
    for path in endpoints or []:
        low = path.lower()
        if any(token in low for token in ("apikey=", "api_key=", "api-key=", "token=", "secret=", "password=", "passwd=", "access_token=", "client_secret=")):
            hits.append(path)
    if hits:
        rows.append(("Keys in URLs", str(len(hits)) + " endpoints carry credentials"))
        for path in hits[:5]:
            rows.append(("Keyed endpoint", short(path, 160)))
    else:
        rows.append(("Keys in URLs", "None spotted"))
    return rows


def danger_rows(texts):
    rows = []
    blob = " ".join(body or "" for _, body in texts)
    counts = {
        "eval() calls": blob.count("eval("),
        "document.write": blob.count("document.write"),
        "innerHTML writes": blob.count(".innerHTML=") + blob.count(".innerHTML ="),
        "outerHTML writes": blob.count(".outerHTML=") + blob.count(".outerHTML ="),
        "setTimeout strings": blob.count("setTimeout(" + chr(34)) + blob.count("setTimeout(" + chr(39)),
    }
    total = sum(counts.values())
    rows.append(("Dangerous sinks", str(total)))
    for label, count in counts.items():
        if count:
            rows.append(("Sink: " + label, str(count)))
    return rows


def sourcemap_rows(session, texts, timeout):
    rows = []
    maps = []
    for label, body in texts:
        for match in re.findall(r"sourceMappingURL=([^\s\*'\"]+)", body or ""):
            candidate = match.strip()
            if label.startswith("http"):
                full = urllib.parse.urljoin(label, candidate)
            else:
                full = candidate
            if full.startswith("http") and full not in [item[1] for item in maps]:
                maps.append((label, full))
    if not maps:
        rows.append(("Source maps", "None referenced"))
        return rows
    rows.append(("Source maps", str(len(maps)) + " referenced"))
    for label, url in maps[:3]:
        try:
            response = session.get(url, timeout=timeout)
        except Exception:
            rows.append(("Source map", short(url, 160) + " (fetch failed)"))
            continue
        if response.status_code != 200:
            rows.append(("Source map", short(url, 160) + " (HTTP " + str(response.status_code) + ")"))
            continue
        try:
            data = response.json()
            sources = data.get("sources", []) or []
        except Exception:
            rows.append(("Source map", short(url, 160) + " (not valid JSON)"))
            continue
        rows.append(("Source map", short(url, 160) + " exposes " + str(len(sources)) + " source paths"))
        for source in sources[:5]:
            rows.append(("Map source", short(str(source), 160)))
    return rows


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
