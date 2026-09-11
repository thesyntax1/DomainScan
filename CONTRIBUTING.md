# Contributing to DomainScan

Thanks for helping improve DomainScan! This is a small, focused project, so a
few ground rules keep things healthy.

## Getting started

```bash
git clone https://github.com/thesyntax1/DomainScan.git
cd DomainScan
pip install -r requirements.txt
python -m unittest discover -s tests
```

The test suite is **fully offline** — it uses a local HTTP server, a local TLS
server and canned DNS/WHOIS responses, so you never need network access (or any
third-party API) to iterate.

## Ground rules

1. **Report, don't invent.** If a lookup cannot be resolved, return
   `None found` / `Skipped` / `Lookup failed`. DomainScan must never fabricate
   data to make a report look complete.
2. **Stay non-intrusive.** New checks should read public data or perform light,
   passive probes only. If a check is active (opens a connection), document it
   and make sure it sends the minimum possible (e.g. the SMTP relay probe stops
   at `RCPT TO` and never sends message data).
3. **Respect the profiles.** `Quick` must stay fast — put slow recon or deep
   probes behind the `include_recon`/`deep` gates so a Quick scan stays snappy.
4. **Keep rows translatable.** New UI strings belong in `domainscan/i18n.py`
   under all four languages (en, tr, es, de). Finding labels may stay in
   English as technical terms.

## Adding a check

- Add a module under `domainscan/` exporting `collect(...) -> {"rows": [...], ...}`.
- Register it in `scanner.run_scan` (main jobs or post jobs).
- Add offline unit tests to `tests/test_offline.py` using the existing fakes.

## Before you open a pull request

- Run `python -m unittest discover -s tests` and make sure everything passes.
- Run `python -m py_compile main.py domainscan/*.py`.
- Update the README's "What it collects" list if you add a section.

## Commit style

Keep commits small and self-contained. Use a clear imperative subject line,
e.g. `Add MTA-STS verification to mail checks`.

## Questions?

Open an issue first for anything larger than a small fix so we can agree on the
approach before you spend time on it.
