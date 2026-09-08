"""DomainScan desktop application entry point.

DomainScan is a desktop tool that collects publicly available information
about a domain or website and presents it in one window.
"""


def run_gui():
    from domainscan.app import main
    main()


if __name__ == "__main__":
    run_gui()
