## What this changes

<!-- One paragraph. If it fixes a finding, name the check ID (e.g. PLUGIN_OUTDATED). -->

## Checklist

- [ ] `make lint test` passes (`make test-race` for anything concurrent or context-driven)
- [ ] `make hygiene` passes (nothing private, generated, or machine-specific is tracked)
- [ ] New or changed behaviour is covered by a fixture-driven test, with no network access
- [ ] `docs/checks.md` and the README check list are updated for a new/changed check
      (the docs-consistency tests will fail otherwise)
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`
- [ ] `SECURITY.md` is updated if this changes what the scanner executes, requests, or writes
- [ ] No secrets, tokens, absolute developer paths, or scanned-site data are included
- [ ] Report output stays machine-readable: one JSON document, lists always arrays, no
      decorative text on stdout

## Notes for the reviewer

<!-- Trade-offs, follow-ups, or anything you deliberately did not do. -->
