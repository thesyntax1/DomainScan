"""DomainScan application entry point.

DomainScan is a tool that collects publicly available information
about a domain or website. It provides both a desktop GUI and a
command-line interface.

Usage:
    python main.py                    Launch the desktop GUI
    python main.py example.com        CLI scan of example.com
    python main.py --help             Show help
"""

import sys


def main():
    """Route to CLI or GUI based on arguments."""
    if len(sys.argv) <= 1:
        from domainscan.app import main as gui_main
        gui_main()
    else:
        from domainscan.cli import entry_point
        entry_point()


if __name__ == "__main__":
    main()
