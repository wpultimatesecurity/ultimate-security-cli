# Contributing to Ultimate Security CLI

Thanks for helping make `wpus` better. This project values: correctness over
cleverness, boring dependable code, honest output (no inflated severities,
no guessed findings), and fast scans.

## Getting started

```bash
git clone https://github.com/wpultimatesecurity/ultimate-security-cli
cd ultimate-security-cli
make build test lint
./wpus scan --offline testdata/demo-site
```

## Ground rules

- **Read-only, always.** The scanner must never modify a scanned site. If a
  feature would write anything, it does not belong in `wpus scan`.
- **No fabricated findings.** Checks report `skipped`/`unknown` with a reason
  when they cannot determine their condition.
- **Secrets never leave the process.** Anything parsed from `wp-config.php`
  that looks secret-shaped flows through `internal/redaction` before output.
- **Stable IDs.** Check IDs, categories, exit codes, and the JSON schema are
  public API. Renames are breaking changes.
- **Boring dependencies.** No new third-party dependency without a strong
  justification, healthy maintenance status, and a compatible license.

## Contributing a check

1. Discuss first in an issue: what does it catch, what is the evidence, what
   is the false-positive story?
2. Implement in `internal/checks/<category>.go`, registering via
   `checks.Register` with a stable ID, category, description, and references.
3. Model WordPress defaults correctly (see `WP_DEBUG_DISPLAY` for the
   pattern where an unset constant still has a default behavior).
4. Use the bounded walker (`fsutil.go`) for anything that walks; never an
   unbounded `WalkDir`.
5. Tests: registry presence, pass case, fail case, skip cases, and fixture
   data. Keep the fixture-generation helpers in `checks_test.go`.
6. Update `docs/checks.md` (registry table + detail section) and the README
   check list.

## Pull requests

- Branch from `main`; keep commits tidy (`feat:`, `fix:`, `docs:`, `chore:`).
- `make lint && make test` must pass. CI runs the same on Linux and macOS
  plus cross-compile builds for all four release targets.
- Include tests for behavior changes; fixture-driven, deterministic, no
  network.
- Update docs (`README.md`, `docs/*.md`) and `CHANGELOG.md` when behavior,
  flags, or output change.

## Reporting bugs

Include: `wpus version`, OS/arch, the command line, redacted JSON output if
possible, and what you expected. Never paste real secrets, salts, or full
`wp-config.php` contents — redact them; we do not need them to reproduce.

## License

By contributing you agree your contributions are licensed under the MIT
License of this repository.
