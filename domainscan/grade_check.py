def collect(result):
    rows = []
    sections = (result or {}).get("sections", {}) or {}
    score = 100
    good = []
    bad = []

    def value(section, *needles):
        for key, text in sections.get(section, []) or []:
            low = str(key).lower()
            if all(needle.lower() in low for needle in needles):
                return str(text)
        return ""

    def values(section, *needles):
        found = []
        for key, text in sections.get(section, []) or []:
            low = str(key).lower()
            if all(needle.lower() in low for needle in needles):
                found.append((str(key), str(text)))
        return found

    def add(points, label, detail):
        if points >= 0:
            good.append((label, "+" + str(points) + " " + detail))
        else:
            bad.append((label, str(points) + " " + detail))
        return points

    hsts = value("Website", "security: hsts")
    if "present" in hsts.lower():
        top = value("Website", "hsts max-age")
        if "missing" in top.lower() or "weak" in value("Website", "hsts duration").lower():
            score += add(-6, "HSTS", "header present but max-age too short")
        else:
            score += add(3, "HSTS", "strict transport security enabled")
    elif hsts:
        score += add(-8, "HSTS", "header missing, first visits can be downgraded")
    csp = value("Website", "security: csp")
    if "present" in csp.lower():
        weak = value("Website", "csp weaknesses")
        if weak and weak.lower() != "none found":
            score += add(-3, "CSP", "policy present but has weaknesses")
        else:
            score += add(3, "CSP", "content security policy enforced")
    elif csp:
        score += add(-6, "CSP", "no content security policy")
    framing = value("Website", "security: clickjacking")
    if "present" in framing.lower():
        score += add(2, "Framing", "clickjacking protection present")
    elif framing:
        score += add(-3, "Framing", "page can be embedded by other sites")
    state = value("TLS", "certificate state")
    if "expired" in state.lower():
        score += add(-15, "Certificate", "certificate has expired")
    elif "valid" in state.lower():
        import re
        match = re.search(r"(\d+)\s+days", state)
        days = int(match.group(1)) if match else 90
        if days < 14:
            score += add(-6, "Certificate", "expires within two weeks")
        else:
            score += add(4, "Certificate", "valid certificate")
    trust = value("TLS", "chain trusted")
    if trust.lower().startswith("no"):
        score += add(-12, "Trust", "chain is not trusted: " + trust[4:80])
    legacy = value("TLS", "legacy tls")
    if "not accepted" not in legacy.lower() and "accepted" in legacy.lower():
        score += add(-10, "Legacy TLS", legacy[:90])
    weak = value("TLS", "weak ciphers")
    if "rejected" not in weak.lower() and "accepted" in weak.lower():
        score += add(-10, "Weak ciphers", weak[:90])
    spf = value("Mail", "spf default policy")
    if "fail (strict)" in spf.lower():
        score += add(3, "SPF", "strict fail policy")
    elif "softfail" in spf.lower():
        score += add(1, "SPF", "softfail policy")
    elif "permissive" in spf.lower() or "+all" in spf.lower():
        score += add(-8, "SPF", "overly permissive sending policy")
    elif "no default" in spf.lower():
        score += add(-6, "SPF", "no SPF record published")
    dmarc = value("Mail", "dmarc policy")
    if "reject" in dmarc.lower():
        score += add(4, "DMARC", "reject policy enforced")
    elif "quarantine" in dmarc.lower():
        score += add(2, "DMARC", "quarantine policy")
    elif "monitor only" in dmarc.lower():
        score += add(-2, "DMARC", "monitor-only policy")
    elif dmarc:
        score += add(-5, "DMARC", "no DMARC record")
    if value("Mail", "dkim keys found"):
        score += add(2, "DKIM", "signing keys published")
    mtasts = value("Mail", "mta-sts verdict")
    if "enforcing" in mtasts.lower():
        score += add(2, "MTA-STS", "enforced mail transport security")
    dnssec = value("DNS", "dnssec")
    if dnssec.lower().startswith("signed"):
        score += add(3, "DNSSEC", "zone is signed")
    caa = value("DNS", "caa restricts")
    if caa.lower().startswith("yes"):
        score += add(2, "CAA", "issuance restricted to listed CAs")
    for key, text in values("DNS", "recursion"):
        if "open resolver" in text.lower():
            score += add(-8, "DNS", key + " is an " + text[:60])
    for key, text in values("DNS", "axfr"):
        if "allowed" in text.lower():
            score += add(-10, "DNS", "zone transfer allowed by " + key)
    insecure = value("Website", "cookies missing secure")
    try:
        missing_secure = int(insecure.split()[0])
    except Exception:
        missing_secure = 0
    if missing_secure:
        score += add(-min(missing_secure * 2, 6), "Cookies", str(missing_secure) + " cookies without Secure flag")
    readable = value("Website", "cookies missing httponly")
    try:
        missing_only = int(readable.split()[0])
    except Exception:
        missing_only = 0
    if missing_only:
        score += add(-min(missing_only, 4), "Cookies", str(missing_only) + " cookies readable by scripts")
    exposed = values("Exposures", "critical:")
    if exposed:
        score += add(-min(len(exposed) * 8, 24), "Exposures", str(len(exposed)) + " critical files disclosed")
    highs = values("Exposures", "high:")
    if highs:
        score += add(-min(len(highs) * 4, 12), "Exposures", str(len(highs)) + " high-severity files disclosed")
    takeovers = [row for row in values("Subdomains", "takeover") if "takeable" in row[1].lower()]
    if takeovers:
        score += add(-min(len(takeovers) * 8, 16), "Takeover", str(len(takeovers)) + " subdomains look takeable")
    verdicts = value("Threat Intel", "urlscan.io verdicts")
    if "malicious" in verdicts.lower():
        try:
            malicious = int(verdicts.split("malicious")[0].split()[-1])
        except Exception:
            malicious = 0
        if malicious:
            score += add(-10, "Threat intel", str(malicious) + " malicious urlscan verdicts")
    if value("Threat Intel", "threatfox samples"):
        score += add(-10, "Threat intel", "malware samples reference this domain")
    if value("Threat Intel", "urlhaus urls"):
        score += add(-10, "Threat intel", "malicious URLs hosted on this domain")
    risky = values("Ports", "risk: port")
    if risky:
        score += add(-min(len(risky) * 4, 16), "Ports", str(len(risky)) + " risky open ports")
    server = value("Website", "server version exposed")
    if server.lower().startswith("yes"):
        score += add(-2, "Disclosure", "server version advertised")
    powered = value("Website", "powered-by exposed")
    if powered and powered.lower() != "no":
        score += add(-2, "Disclosure", "X-Powered-By advertises " + powered[:60])
    mixed = value("Content", "mixed content refs")
    if mixed and mixed.lower() != "none":
        score += add(-3, "Mixed content", mixed[:80])
    sri = value("Content", "sri gap")
    if sri and not sri.startswith("0"):
        score += add(-2, "SRI", sri[:80])
    jquery = value("Content", "jquery vulnerability")
    if jquery:
        score += add(-4, "Libraries", jquery[:90])
    for key, text in values("JS Analysis", "js library risk"):
        score += add(-3, "Libraries", key.rsplit(":", 1)[-1].strip() + ": " + text[:70])
        break
    final = value("Website", "final url")
    if final.lower().startswith("https://"):
        score += add(2, "HTTPS", "site served over TLS")
    score = max(0, min(100, score))
    rows.append(("Security grade", grade_letter(score) + " (" + str(score) + "/100)"))
    for label, detail in bad[:25]:
        rows.append(("- " + label, detail))
    for label, detail in good[:25]:
        rows.append(("+ " + label, detail))
    worst = sorted(bad, key=lambda item: int(item[1].split()[0]))[:3]
    for index, (label, detail) in enumerate(worst, 1):
        rows.append(("Top recommendation " + str(index), label + ": " + detail.split(" ", 1)[1]))
    if not bad:
        rows.append(("Top recommendation 1", "No weaknesses found, keep patching and monitoring"))
    return {"rows": rows}


def grade_letter(score):
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 85:
        return "A-"
    if score >= 80:
        return "B+"
    if score >= 75:
        return "B"
    if score >= 70:
        return "B-"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"
