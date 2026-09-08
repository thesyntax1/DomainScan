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
    parser.add_argument("--history", default="", help="List saved scans for this host and exit")
    parser.add_argument("--compare", default="", help="Compare the last two saved scans for this host and exit")
    parser.add_argument("--watch", default="", help="Rescan this target periodically and report changes")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between watch rounds (default 300)")
    parser.add_argument("--rounds", type=int, default=0, help="Watch rounds to run (0 means forever)")
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
    if args.history:
        return show_history(args.history)
    if args.compare:
        return show_compare(args.compare)
    if args.watch:
        return watch_target(args)
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


def show_history(host):
    from domainscan import history_store
    paths = history_store.list_runs(host)
    if not paths:
        print("No saved scans for " + host + ".")
        return 0
    print("Saved scans for " + host + " (" + str(len(paths)) + "):")
    for path in paths[:20]:
        try:
            data = history_store.load_run(path)
            stamp = data["meta"].get("scanned_at", "?")
            findings = data["meta"].get("findings", "?")
        except Exception:
            stamp = "unreadable"
            findings = "?"
        print("  " + stamp + "  findings=" + str(findings) + "  " + path)
    return 0


def show_compare(host):
    from domainscan import history_store
    paths = history_store.list_runs(host)
    if len(paths) < 2:
        print("Need at least two saved scans for " + host + " to compare.")
        return 1
    try:
        new = history_store.load_run(paths[0])
        old = history_store.load_run(paths[1])
    except Exception as exc:
        print("Could not load saved scans (" + exc.__class__.__name__ + ").")
        return 1
    rows = history_store.diff_runs(old, new)
    print("Comparing " + str(old["meta"].get("scanned_at", "?")) + " -> " + str(new["meta"].get("scanned_at", "?")))
    for key, value in rows:
        print("  " + key + ": " + value)
    return 0


def watch_target(args):
    import time
    from domainscan import history_store, profiles, scanner
    caps = profiles.get_profile("Quick")
    request_timeout = args.timeout if args.timeout > 0 else caps["timeout"]
    round_no = 0
    try:
        while True:
            round_no += 1
            print("Round " + str(round_no) + ": scanning " + args.watch + "...")
            try:
                result = scanner.run_scan(
                    args.watch,
                    include_ports=False,
                    include_subdomains=caps["include_subdomains"],
                    timeout=request_timeout,
                    crawl_pages=0,
                    js_files=0,
                    subdomain_web=0,
                    include_recon=False,
                )
            except ValueError as exc:
                print("Invalid target: " + str(exc))
                return 1
            except Exception as exc:
                print("Scan failed (" + exc.__class__.__name__ + ": " + str(exc) + "), retrying next round.")
                result = None
            if result is not None:
                try:
                    history_store.save_run(result)
                    history_store.prune_old(result["target"]["host"])
                except Exception:
                    pass
                try:
                    previous = history_store.previous_run(result["target"]["host"], result["meta"]["scanned_at"])
                except Exception:
                    previous = None
                if not previous:
                    print("Round " + str(round_no) + ": baseline saved (" + str(result["meta"]["findings"]) + " findings).")
                else:
                    rows = history_store.diff_runs(previous, result)
                    summary = {key: value for key, value in rows if key in ("Added", "Removed", "Changed")}
                    total = sum(int(summary.get(key, "0")) for key in ("Added", "Removed", "Changed"))
                    print("Round " + str(round_no) + ": +" + summary.get("Added", "0") + "/-" + summary.get("Removed", "0") + "/~" + summary.get("Changed", "0"))
                    if total:
                        for key, value in rows:
                            if key in ("Added finding", "Removed finding", "Changed finding"):
                                print("  " + key + ": " + value)
                    else:
                        print("  No differences.")
            if args.rounds > 0 and round_no >= args.rounds:
                return 0
            time.sleep(max(args.interval, 5))
    except KeyboardInterrupt:
        print("Watch stopped.")
        return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main_cli(sys.argv[1:]))
    else:
        run_gui()
