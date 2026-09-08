PROFILES = {
    "Quick": {
        "include_ports": False,
        "include_subdomains": False,
        "crawl_pages": 0,
        "js_files": 0,
        "subdomain_web": 0,
        "include_recon": False,
        "timeout": 8,
    },
    "Standard": {
        "include_ports": True,
        "include_subdomains": True,
        "crawl_pages": 15,
        "js_files": 6,
        "subdomain_web": 20,
        "include_recon": True,
        "timeout": 12,
    },
    "Deep": {
        "include_ports": True,
        "include_subdomains": True,
        "crawl_pages": 40,
        "js_files": 12,
        "subdomain_web": 40,
        "include_recon": True,
        "timeout": 15,
    },
}


def profile_names():
    return list(PROFILES)


def get_profile(name):
    if name in PROFILES:
        return dict(PROFILES[name])
    return dict(PROFILES["Standard"])
