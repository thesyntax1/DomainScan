# Changelog

All notable changes to DomainScan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [1.11.0] - 2026-09-11

### Added

- **Command-line interface restored**: a full CLI behind the `domainscan`
  console script and the `DomainScan-cli.exe` build — interactive mode,
  one-shot scans, `--profile`, `--json`, `--proxy`, `--timeout`, `--no-ports`,
  `--no-subdomains`, `--quiet`, `--no-color`, and report export to JSON / HTML /
  CSV / TXT / PDF via `-o`.
- **PDF report export** through the optional `reportlab` dependency
  (`pip install "domainscan[pdf]"`).
- README overhaul: fixed broken markup in the tagline, switched screenshots to
  the bundled local images, corrected the version badge, documented the CLI and
  Windows executable, and added "Support the project" and "Contact" sections.

### Changed

- Project description and version metadata aligned with 1.11.0.

### Fixed

- **Build backend**: `setuptools.backends._legacy:_Backend` was removed in
  modern setuptools, so the package could not be built at all. Switched to the
  standard `setuptools.build_meta` backend and raised the minimum to
  `setuptools>=77.0`.
- **License metadata**: replaced the deprecated `license = {text = "MIT"}` with
  the PEP 639 `license = "MIT"` expression and dropped the now-superseded
  `License :: OSI Approved :: MIT License` classifier.

### Removed

- `Pillow` from `requirements.txt` (unused — image handling relies on tkinter
  and reportlab only).

## [1.10.0] - 2026-09-08

### Added

- **Cancel button**: a running scan can now be cancelled; the button flips to
  "Cancel" while scanning and in-flight checks stop at the next checkpoint.
- **Check for updates**: a Help menu item checks GitHub Releases for a newer
  version, with an optional "check on startup" setting (remembered).
- Real GUI smoke test (`tests/gui_smoke.py`) that instantiates the actual Tk
  window and runs in CI under a virtual display.

### Fixed

- Cancelled scans no longer appear in scan history.

## [1.9.0] - 2026-09-08

### Added

- Brand logo and application icon (bundled with the desktop app and the
  Windows executable).
- Project branding assets under `domainscan/assets/` (logo.png, icon.ico).
- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md` and this changelog.
- README badges, logo header and an expanded legal &amp; ethical note.
- Continuous integration: the offline test suite runs on every push and pull
  request across Python 3.9, 3.11 and 3.13.

### Changed

- **Speed**: `Quick` scans now skip slow recon and deep probes (BGP, blocklists,
  web archive, openssl chain/OCSP/cipher enumeration, SMTP probing, DNS
  resolver comparison / AXFR / NS identity, WebSocket / sensitive-path / API
  discovery), so they finish in seconds instead of 10+ seconds.
- DNS record collection now runs concurrently instead of serialising ~20
  lookups, and resolver timeouts were tightened.
- Removed the wasteful outer retry that re-ran an entire check (with a 1s
  sleep) after any failure; each check still retries transient network/DNS
  errors internally.
- The NSID probe now queries the target's own zone instead of a hardcoded
  `example.com`.

### Removed

- Command-line interface (`--profile`, `--export`, `--history`, `--compare`,
  `--watch`, `--help` and the `DomainScan-cli.exe` build). DomainScan is a
  desktop application.

### Fixed

- **Console window flash on Windows**: `openssl` and `ping` probes now run with
  `CREATE_NO_WINDOW`, so no CMD window pops up and closes during a scan.
- Deterministic ordering of concurrent DNS result rows.
- Collision between the two SRV lookups (`_https._tcp` / `_http._tcp`).
- The NSID probe now queries the target's own zone instead of a hardcoded
  `example.com`.

## [1.8.0] - earlier

- Initial public feature set: 30+ scan sections, scan history, comparison,
  watch mode, multilingual UI and offline test suite.
