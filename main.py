import sys


def run_gui():
    from domainscan.app import main
    main()


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(prog="DomainScan", description="Legal website and domain intelligence.")
    parser.add_argument("target", nargs="?", help="Domain or URL to scan (omit to open the desktop app)")
    parser.add_argument("--profile", default="Standard", choices=["Quick", "Standard", "Deep"], help="Scan profile")
    parser.add_argument("--no-ports", action="store_true", help="Skip the port check")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain discovery")
    parser.add_argument("--timeout", type=int, default=0, help="Request timeout in seconds (0 uses the profile default)")
    parser.add_argument("--export", default="", help="Write the report to this file")
    parser.add_argument("--format", default="", choices=["", "json", "csv", "txt", "html"], help="Report format (defaults to the export extension)")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary")
    return parser


def infer_format(path):
    low = (path or "").lower()
    if low.endswith(".json"):
        return "json"
    if low.endswith(".csv"):
        return "csv"
    if low.endswith(".html") or low.endswith(".htm"):
        return "html"
    return "txt"


def main_cli(argv):
    from domainscan import helpers, history_store, profiles, scanner
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.target:
        parser.print_help()
        return 1
    caps = profiles.get_profile(args.profile)
    if args.timeout > 0:
        request_timeout = args.timeout
    else:
        request_timeout = caps["timeout"]

    def progress(percent, message):
        print(str(percent) + "% " + message)

    if args.quiet:
        callback = None
    else:
        callback = progress
    result = scanner.run_scan(
        args.target,
        on_progress=callback,
        include_ports=caps["include_ports"] and not args.no_ports,
        include_subdomains=caps["include_subdomains"] and not args.no_subdomains,
        timeout=request_timeout,
        crawl_pages=caps["crawl_pages"],
        js_files=caps["js_files"],
        subdomain_web=caps["subdomain_web"],
        include_recon=caps["include_recon"],
    )
    meta = result["meta"]
    print("Target: " + result["target"]["host"])
    print("Findings: " + str(meta["findings"]) + " in " + str(meta["duration_seconds"]) + " seconds")
    for section, items in result["sections"].items():
        print("  " + section + ": " + str(len(items)))
    if args.export:
        fmt = args.format or infer_format(args.export)
        if fmt == "json":
            helpers.export_json(args.export, result)
        elif fmt == "csv":
            helpers.export_csv(args.export, result)
        elif fmt == "html":
            helpers.export_html(args.export, result)
        else:
            helpers.export_txt(args.export, result)
        print("Report saved to " + args.export)
    try:
        history_store.save_run(result)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main_cli(sys.argv[1:]))
    else:
        run_gui()
