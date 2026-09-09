"""DomainScan command-line interface.

Usage:
    domainscan example.com                     Scan a domain (interactive output)
    domainscan example.com --profile deep      Use the Deep profile
    domainscan example.com --json              Print JSON result to stdout
    domainscan example.com -o report.json      Save JSON report to file
    domainscan example.com -o report.html      Save HTML report to file
    domainscan example.com -o report.csv       Save CSV report to file
    domainscan example.com -o report.txt       Save text report to file
    domainscan example.com -o report.pdf       Save PDF report to file
    domainscan --gui                           Launch the desktop GUI
    domainscan --version                       Print version
    domainscan --help                          Show help
"""

import argparse
import json
import os
import sys
import threading
import time

from domainscan import __version__, helpers, profiles, scanner


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_BLUE = "\033[44m"


def color_supported():
    """Check if the terminal likely supports ANSI colors."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


USE_COLOR = color_supported()


def styled(text, *codes):
    if not USE_COLOR:
        return str(text)
    return "".join(codes) + str(text) + RESET


def header(text):
    return styled(text, BOLD, CYAN)


def muted(text):
    return styled(text, DIM)


def success(text):
    return styled(text, GREEN)


def warning(text):
    return styled(text, YELLOW)


def danger(text):
    return styled(text, RED)


def info(text):
    return styled(text, BLUE)


def print_banner():
    """Print the DomainScan CLI banner."""
    banner = r"""
     ____                                   ____
    |  _ \  _____      ___ __   ___  ___   / ___|  ___ __ _ _ __  _ __   ___ _ __
    | | | |/ _ \ \ /\ / / '_ \ / _ \/ _ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    | |_| | (_) \ V  V /| | | |  __/  __/   ___) | (_| (_| | | | | | | |  __/ |
    |____/ \___/ \_/\_/ |_| |_|\___|\___|  |____/ \___\__,_|_| |_|_| |_|\___|_|
"""
    print(styled(banner, BOLD, CYAN))
    print("  " + styled("Legal website and domain intelligence", DIM) + "  " + styled("v" + __version__, BOLD))
    print("  " + muted("Collects only publicly available data. Only scan domains you own or are allowed to test."))
    print()


def build_parser():
    """Build the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="domainscan",
        description="DomainScan - Legal website and domain intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  domainscan example.com                  Quick scan with default profile\n"
            "  domainscan example.com --profile deep   Deep scan with all checks\n"
            "  domainscan example.com --no-ports       Skip port scanning\n"
            "  domainscan example.com --json           Print JSON to stdout\n"
            "  domainscan example.com -o report.html   Export HTML report\n"
            "  domainscan --gui                        Launch desktop GUI\n"
            "\n"
            "Profiles: quick, standard, deep\n"
            "Export formats: json, html, csv, txt, pdf\n"
        ),
    )
    parser.add_argument("target", nargs="?", default=None, help="Domain name or URL to scan (e.g. example.com)")
    parser.add_argument("--version", action="version", version="DomainScan " + __version__)
    parser.add_argument("--gui", action="store_true", help="Launch the desktop GUI")
    parser.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard", help="Scan profile (default: standard)")
    parser.add_argument("--no-ports", action="store_true", help="Disable port scanning")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain discovery")
    parser.add_argument("--timeout", type=int, default=None, help="HTTP request timeout in seconds")
    parser.add_argument("--proxy", type=str, default=None, help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output (only show results)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Print JSON result to stdout")
    parser.add_argument("--output", "-o", type=str, default=None, help="Export result to file (format from extension: json, html, csv, txt, pdf)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    return parser


def export_result(result, path):
    """Export the scan result to a file based on the extension."""
    lower = path.lower()
    if lower.endswith(".json"):
        helpers.export_json(path, result)
        return "JSON"
    elif lower.endswith(".html"):
        helpers.export_html(path, result)
        return "HTML"
    elif lower.endswith(".csv"):
        helpers.export_csv(path, result)
        return "CSV"
    elif lower.endswith(".txt"):
        helpers.export_txt(path, result)
        return "Text"
    elif lower.endswith(".pdf"):
        export_pdf(path, result)
        return "PDF"
    else:
        helpers.export_json(path, result)
        return "JSON (default)"


def export_pdf(path, result):
    """Export scan result as a PDF report using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.units import mm
    except ImportError:
        raise ImportError(
            "PDF export requires reportlab. Install it with: pip install domainscan[pdf]"
        )

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DomainScanTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=HexColor("#2f7cf6"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "DomainScanSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#666666"),
        spaceAfter=16,
    )
    heading_style = ParagraphStyle(
        "DomainScanHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=HexColor("#1a1a2e"),
        spaceBefore=14,
        spaceAfter=6,
        borderPadding=(0, 0, 2, 0),
    )
    cell_key = ParagraphStyle("CellKey", parent=styles["Normal"], fontSize=8, textColor=HexColor("#555555"))
    cell_val = ParagraphStyle("CellVal", parent=styles["Normal"], fontSize=8, textColor=HexColor("#222222"), wordWrap="CJK")

    story = []
    host = result["target"]["host"]
    meta = result["meta"]

    story.append(Paragraph("DomainScan Report", title_style))
    story.append(Paragraph(
        str(host) + " &bull; " + str(meta["scanned_at"]) + " &bull; " +
        str(meta["duration_seconds"]) + "s &bull; " + str(meta["findings"]) + " findings",
        subtitle_style,
    ))
    story.append(Spacer(1, 8))

    for section, items in result["sections"].items():
        if not items:
            continue
        story.append(Paragraph(section + " (" + str(len(items)) + ")", heading_style))
        table_data = []
        for key, value in items:
            safe_key = str(key).replace("&", "&amp;").replace("<", "&lt;")
            safe_val = str(value).replace("&", "&amp;").replace("<", "&lt;")
            if len(safe_val) > 300:
                safe_val = safe_val[:297] + "..."
            table_data.append([Paragraph(safe_key, cell_key), Paragraph(safe_val, cell_val)])
        if table_data:
            table = Table(table_data, colWidths=[55 * mm, 110 * mm])
            table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [HexColor("#ffffff"), HexColor("#f5f7fa")]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, HexColor("#e0e0e0")),
            ]))
            story.append(table)
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Generated by DomainScan " + __version__ + " &mdash; https://github.com/thesyntax1/DomainScan",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=HexColor("#999999")),
    ))
    doc.build(story)


def print_results(result, quiet=False):
    """Print scan results to the terminal with colors and formatting."""
    host = result["target"]["host"]
    meta = result["meta"]
    cancelled = bool(meta.get("cancelled"))

    if not quiet:
        print()
        print("  " + styled("─" * 68, DIM))
        if cancelled:
            print("  " + danger("SCAN CANCELLED") + "  " + muted("| " + host))
        else:
            print("  " + success("SCAN COMPLETE") + "  " + muted("| " + host + " | " + str(meta["duration_seconds"]) + "s | " + str(meta["findings"]) + " findings"))
        print("  " + styled("─" * 68, DIM))
        print()

    for section, items in result["sections"].items():
        if not items:
            continue
        count = len(items)
        section_display = header(section)
        count_display = muted("(" + str(count) + " items)")
        print("  " + section_display + "  " + count_display)
        print("  " + styled("  " + "─" * min(len(section) + len(str(count)) + 8, 60), DIM))
        for key, value in items:
            key_display = styled("  " + str(key), BOLD, WHITE)
            val_display = str(value)
            if len(val_display) > 200:
                val_display = val_display[:197] + "..."
            print("  " + key_display + muted("  →  ") + val_display)
        print()


class ProgressPrinter:
    """Thread-safe progress printer for CLI scans."""

    def __init__(self, quiet=False):
        self.quiet = quiet
        self.lock = threading.Lock()
        self.last_line_len = 0

    def __call__(self, percent, message):
        if self.quiet:
            return
        with self.lock:
            bar_len = 30
            filled = int(bar_len * percent / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            line = "\r  " + styled("Scanning", CYAN) + " " + styled(bar, GREEN if percent < 100 else BLUE) + " " + styled(str(int(percent)) + "%", BOLD) + "  " + muted(message[:40])
            padding = max(0, self.last_line_len - len(line))
            sys.stdout.write(line + " " * padding)
            sys.stdout.flush()
            self.last_line_len = len(line)
            if percent >= 100:
                sys.stdout.write("\n")
                sys.stdout.flush()


def apply_proxy(proxy_url):
    """Set proxy environment variables for HTTP requests."""
    if not proxy_url:
        return
    os.environ["HTTP_PROXY"] = proxy_url
    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["http_proxy"] = proxy_url
    os.environ["https_proxy"] = proxy_url


def run_cli(args):
    """Execute a CLI scan with the given parsed arguments."""
    target = args.target.strip()
    if not target:
        print(danger("Error: ") + "No target specified. Use: domainscan example.com")
        sys.exit(1)

    caps = profiles.get_profile(args.profile.capitalize())
    include_ports = caps["include_ports"] and not args.no_ports
    include_subdomains = caps["include_subdomains"] and not args.no_subdomains
    timeout = args.timeout or caps["timeout"]

    if args.proxy:
        apply_proxy(args.proxy)
        if not args.quiet:
            print("  " + info("Proxy:") + " " + args.proxy)

    if not args.quiet and not args.json_output:
        print_banner()
        print("  " + info("Target:") + "      " + target)
        print("  " + info("Profile:") + "     " + args.profile.capitalize())
        print("  " + info("Ports:") + "       " + (success("Yes") if include_ports else muted("No")))
        print("  " + info("Subdomains:") + "  " + (success("Yes") if include_subdomains else muted("No")))
        print("  " + info("Timeout:") + "     " + str(timeout) + "s")
        print()

    progress = ProgressPrinter(quiet=args.quiet or args.json_output)

    cancel_event = threading.Event()

    def signal_handler(sig, frame):
        if not cancel_event.is_set():
            cancel_event.set()
            print("\n  " + warning("Cancelling scan..."))

    try:
        import signal
        signal.signal(signal.SIGINT, signal_handler)
    except Exception:
        pass

    started = time.perf_counter()
    result = None
    error = None

    try:
        result = scanner.run_scan(
            target,
            on_progress=progress,
            include_ports=include_ports,
            include_subdomains=include_subdomains,
            timeout=timeout,
            crawl_pages=caps["crawl_pages"],
            js_files=caps["js_files"],
            subdomain_web=caps["subdomain_web"],
            include_recon=caps["include_recon"],
            cancel_event=cancel_event,
        )
    except ValueError as exc:
        error = "Invalid target: " + str(exc)
    except KeyboardInterrupt:
        cancel_event.set()
        if not result:
            error = "Scan interrupted by user."
    except Exception as exc:
        error = exc.__class__.__name__ + ": " + str(exc)

    if error:
        print("\n  " + danger("Error: ") + error)
        sys.exit(1)

    cancelled = bool(result["meta"].get("cancelled"))

    if args.json_output:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        sys.exit(0)

    if not args.quiet:
        print_results(result, quiet=False)

    if args.output:
        try:
            fmt = export_result(result, args.output)
            if not args.quiet:
                print("  " + success("Exported:") + " " + args.output + " (" + fmt + ")")
        except Exception as exc:
            print("  " + danger("Export failed: ") + str(exc))
            sys.exit(1)

    if not args.output and not args.quiet and not cancelled:
        host = result["target"]["host"]
        duration = result["meta"]["duration_seconds"]
        findings = result["meta"]["findings"]
        print("  " + styled("─" * 68, DIM))
        print("  " + muted("Scan of " + host + " completed in " + str(duration) + "s with " + str(findings) + " findings."))
        print("  " + muted("Use -o report.json|html|csv|txt|pdf to export results."))
        print()


def run_gui():
    """Launch the desktop GUI application."""
    try:
        from domainscan.app import main as gui_main
        gui_main()
    except ImportError as exc:
        print(danger("Error: ") + "Could not start GUI: " + str(exc))
        print("  Make sure tkinter is installed. On Linux: sudo apt install python3-tk")
        sys.exit(1)


def entry_point():
    """Main entry point for the domainscan command."""
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    if args.gui:
        run_gui()
        return

    if args.target is None:
        parser.print_help()
        print()
        print("  " + muted("Tip: run ") + styled("domainscan --gui", CYAN) + muted(" to launch the desktop application."))
        sys.exit(0)

    run_cli(args)
