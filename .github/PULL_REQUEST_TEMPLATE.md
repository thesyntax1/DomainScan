## What does this change?

<!-- Describe the change and why it is needed. -->

## How did you test it?

<!-- e.g. `python -m unittest discover -s tests` — all tests are offline. -->

- [ ] `python -m unittest discover -s tests` passes
- [ ] `python -m py_compile main.py domainscan/*.py` passes
- [ ] README updated if a section was added or changed

## Checklist

- [ ] No fabricated data — missing results are reported as `None found`/`Skipped`
- [ ] New checks are non-intrusive and documented
- [ ] Quick-profile scans stay fast (slow probes are gated behind `deep`/recon)
- [ ] New UI strings exist in all four languages (en, tr, es, de)
