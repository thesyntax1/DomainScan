from domainscan.helpers import short


def collect(html):
    rows = []
    if not html:
        rows.append(("Accessibility", "No page content to analyze"))
        return {"rows": rows}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        rows.append(("Accessibility", "HTML parsing unavailable"))
        return {"rows": rows}
    rows.extend(document_rows(soup))
    rows.extend(image_rows(soup))
    rows.extend(form_rows(soup))
    rows.extend(button_rows(soup))
    rows.extend(structure_rows(soup))
    rows.append(("Accessibility score", score(rows)))
    return {"rows": rows}


def document_rows(soup):
    rows = []
    html_tag = soup.find("html")
    lang = ""
    if html_tag:
        lang = (html_tag.get("lang", "") or "").strip()
    if lang:
        rows.append(("Page language", "Set (" + lang + ")"))
    else:
        rows.append(("Page language", "Missing (screen readers guess)"))
    if soup.title and (soup.title.string or "").strip():
        rows.append(("Page title", "Present"))
    else:
        rows.append(("Page title", "Missing or empty"))
    return rows


def image_rows(soup):
    rows = []
    images = soup.find_all("img")
    rows.append(("Images checked", str(len(images))))
    if not images:
        return rows
    without_alt = [img for img in images if img.get("alt") is None]
    empty_alt = [img for img in images if img.get("alt") is not None and not img.get("alt").strip()]
    rows.append(("Images without alt", str(len(without_alt))))
    rows.append(("Images with empty alt", str(len(empty_alt)) + " (fine if decorative)"))
    if without_alt:
        sample = (without_alt[0].get("src", "") or "")[:100]
        rows.append(("Alt sample", short(sample, 120)))
    return rows


def form_rows(soup):
    rows = []
    fields = soup.find_all(["input", "select", "textarea"])
    fields = [field for field in fields if str(field.get("type", "")).lower() not in ("hidden", "submit", "button", "image")]
    rows.append(("Form fields checked", str(len(fields))))
    if not fields:
        return rows
    unlabeled = 0
    for field in fields:
        label = field.get("aria-label", "") or field.get("aria-labelledby", "") or field.get("title", "")
        if label:
            continue
        field_id = field.get("id", "")
        if field_id and soup.find("label", attrs={"for": field_id}):
            continue
        if field.find_parent("label"):
            continue
        unlabeled += 1
    rows.append(("Unlabeled fields", str(unlabeled)))
    placeholders = [field for field in fields if field.get("placeholder") and not field.get("aria-label", "")]
    if placeholders:
        rows.append(("Placeholder-only fields", str(len(placeholders)) + " (placeholders are not labels)"))
    return rows


def button_rows(soup):
    rows = []
    buttons = soup.find_all("button")
    empty = [button for button in buttons if not button.get_text(strip=True) and not button.get("aria-label", "")]
    rows.append(("Buttons checked", str(len(buttons))))
    rows.append(("Empty buttons", str(len(empty))))
    links = soup.find_all("a", href=True)
    empty_links = [link for link in links if not link.get_text(strip=True) and not link.find("img")]
    rows.append(("Links checked", str(len(links))))
    rows.append(("Empty links", str(len(empty_links))))
    generic = 0
    for link in links:
        text = link.get_text(" ", strip=True).lower()
        if text in ("click here", "here", "read more", "more", "link"):
            generic += 1
    rows.append(("Generic link texts", str(generic)))
    return rows


def structure_rows(soup):
    rows = []
    landmarks = 0
    for tag in ("header", "nav", "main", "footer"):
        if soup.find(tag):
            landmarks += 1
    rows.append(("Landmarks", str(landmarks) + " of 4 (header/nav/main/footer)"))
    skip = False
    for link in soup.find_all("a", href=True):
        text = link.get_text(" ", strip=True).lower()
        if "skip" in text and ("content" in text or "main" in text or "navigation" in text):
            skip = True
            break
    if skip:
        rows.append(("Skip link", "Present"))
    else:
        rows.append(("Skip link", "Missing"))
    tabindex = [tag for tag in soup.find_all(attrs={"tabindex": True}) if str(tag.get("tabindex")).lstrip("-").isdigit() and int(tag.get("tabindex")) > 0]
    rows.append(("Positive tabindex", str(len(tabindex)) + " (should be 0)"))
    tables = soup.find_all("table")
    if tables:
        with_headers = sum(1 for table in tables if table.find("th"))
        rows.append(("Data tables", str(with_headers) + " of " + str(len(tables)) + " use th headers"))
    videos = soup.find_all("video")
    if videos:
        captioned = sum(1 for video in videos if video.find("track"))
        rows.append(("Videos with captions", str(captioned) + " of " + str(len(videos))))
    contrast = soup.find_all(attrs={"style": True})
    inline_styles = sum(1 for tag in contrast if "color" in str(tag.get("style")).lower())
    rows.append(("Inline color styles", str(inline_styles) + " (contrast not verified)"))
    return rows


def score(rows):
    problems = 0
    for key, value in rows:
        if key in ("Page language", "Page title") and ("Missing" in value or "empty" in value):
            problems += 2
        if key == "Images without alt" and value != "0":
            problems += 2
        if key == "Unlabeled fields" and value != "0":
            problems += 2
        if key == "Empty buttons" and value != "0":
            problems += 1
        if key == "Empty links" and value != "0":
            problems += 1
        if key == "Generic link texts" and value != "0":
            problems += 1
        if key == "Skip link" and value == "Missing":
            problems += 1
        if key == "Positive tabindex" and not value.startswith("0"):
            problems += 1
    problems = min(problems, 10)
    return str((10 - problems) * 10) + "/100 (" + str(problems) + " issue points)"
