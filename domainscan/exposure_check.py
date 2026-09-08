from concurrent.futures import ThreadPoolExecutor

from domainscan.helpers import BROWSER_UA, short


PROBES = [
    ("/.git/config", "[core]", "critical"),
    ("/.git/logs/HEAD", None, "high"),
    ("/.svn/entries", None, "high"),
    ("/.hg/requires", None, "high"),
    ("/.bzr/README", None, "medium"),
    ("/WEB-INF/web.xml", "<web-app", "high"),
    ("/.env.local", "APP_", "critical"),
    ("/.env.production", "APP_", "critical"),
    ("/config.php~", "<?", "high"),
    ("/wp-config.php.bak", "DB_", "critical"),
    ("/wp-config.php~", "DB_", "high"),
    ("/configuration.php~", "<?", "medium"),
    ("/settings.php.bak", "$", "medium"),
    ("/backup.sql", "CREATE TABLE", "critical"),
    ("/dump.sql", "CREATE TABLE", "critical"),
    ("/database.sql", "CREATE TABLE", "critical"),
    ("/db.sql.gz", None, "high"),
    ("/backup.zip", None, "high"),
    ("/site.zip", None, "high"),
    ("/package.json", "\"name\"", "medium"),
    ("/composer.json", "\"require\"", "medium"),
    ("/Gemfile", "source ", "low"),
    ("/requirements.txt", "==", "low"),
    ("/server-info", "Apache Server Information", "high"),
    ("/server-status?auto", "Total Accesses", "high"),
    ("/phpmyadmin/", "phpMyAdmin", "high"),
    ("/adminer.php", "Adminer", "high"),
    ("/xmlrpc.php", "XML-RPC", "medium"),
    ("/wp-login.php", "WordPress", "medium"),
    ("/administrator/", "Joomla", "medium"),
    ("/user/login", "Drupal", "low"),
    ("/actuator/env", "systemProperties", "critical"),
    ("/actuator/heapdump", None, "critical"),
    ("/actuator/health", "status", "low"),
    ("/actuator/metrics", "measurements", "medium"),
    ("/debug/vars", "memstats", "medium"),
    ("/trace.axd", "Trace", "medium"),
    ("/elmah.axd", "Error Log", "high"),
    ("/.well-known/change-password", None, "info"),
    ("/console/", None, "medium"),
    ("/manager/html", "Tomcat", "high"),
    ("/jmx-console/", "JBoss", "high"),
    ("/hudson/", "Hudson", "medium"),
    ("/jenkins/login", "Jenkins", "medium"),
    ("/gitlab/users/sign_in", "GitLab", "medium"),
    ("/.s3cfg", "access_key", "critical"),
    ("/aws.yml", "secret", "high"),
    ("/credentials.xml", "credentials", "high"),
    ("/id_rsa", "PRIVATE KEY", "critical"),
    ("/server.key", "PRIVATE KEY", "critical"),
    ("/.env", "APP_", "critical"),
    ("/.env.development", "APP_", "high"),
    ("/Dockerfile", "FROM ", "medium"),
    ("/docker-compose.yml", "services:", "medium"),
    ("/phpinfo.php", "phpinfo()", "high"),
    ("/info.php", "phpinfo()", "high"),
    ("/swagger.json", "openapi", "medium"),
    ("/openapi.json", "openapi", "medium"),
    ("/api-docs", "swagger", "medium"),
    ("/wp-json/wp/v2/users", "\"slug\"", "medium"),
    ("/.DS_Store", None, "low"),
    ("/metrics", "# HELP", "medium"),
    ("/healthz", None, "low"),
    ("/v2/_catalog", "repositories", "medium"),
    ("/graphql", "query", "medium"),
]


def collect(base_url, timeout=8, enabled=True):
    rows = []
    if not enabled:
        rows.append(("Exposure scan", "Skipped (disabled in options)"))
        return {"rows": rows}
    import requests
    session = requests.Session()
    session.headers.update({"User-Agent": BROWSER_UA})
    findings = probe_all(session, base_url, timeout)
    exposed = [item for item in findings if item[1] == "exposed"]
    guarded = [item for item in findings if item[1] == "guarded"]
    rows.append(("Paths tested", str(len(PROBES))))
    rows.append(("Exposed paths", str(len(exposed))))
    for path, _, severity, detail in sorted(exposed, key=lambda item: (rank(item[2]), item[0])):
        rows.append((severity.upper() + ": " + path, detail))
    if guarded:
        rows.append(("Login pages found", str(len(guarded)) + " (verify brute-force protection)"))
        for path, _, _, detail in guarded[:8]:
            rows.append(("Login: " + path, detail))
    if not exposed and not guarded:
        rows.append(("Exposure verdict", "No sensitive files disclosed"))
    return {"rows": rows}


def rank(severity):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)


def probe_all(session, base_url, timeout):
    results = []

    def check(entry):
        path, marker, severity = entry
        try:
            response = session.get(base_url + path, timeout=timeout, allow_redirects=False)
        except Exception:
            return None
        return verdict(path, marker, severity, response)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for item in pool.map(check, PROBES):
            if item:
                results.append(item)
    return results


def verdict(path, marker, severity, response):
    status = response.status_code
    body = (response.text or "")[:4000]
    if status in (401, 403):
        if status == 401 or "login" in body.lower() or "password" in body.lower():
            return (path, "guarded", severity, "HTTP " + str(status) + " (login required)")
        return None
    if status == 200 and not marker:
        return (path, "exposed", severity, "HTTP 200, " + str(len(response.content or b"")) + " bytes (review manually)")
    if status == 200 and marker and marker.lower() in body.lower():
        return (path, "exposed", severity, "HTTP 200 with signature " + short(marker, 60))
    if status == 200 and marker:
        return None
    return None
