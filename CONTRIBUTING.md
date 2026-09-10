# Contributing to Ultimate Security CLI

Thanks for helping make `wpus` better. This project values: correctness over
cleverness, boring dependable code, honest output (no inflated severities,
no guessed findings), and fast scans.

## Getting started

```bash
git clone https://github.com/wpultimatesecurity/ultimate-security-cli
cd ultimate-security-cli
make build test lint hygiene
./wpus scan --offline testdata/demo-site
```

`make integration` additionally downloads a real WordPress release and proves
the integrity path against the live WordPress.org checksum service; it needs
network access, so it is not part of `make test`.

## Ground rules

- **Read-only, always.** The scanner must never modify a scanned site. A
  report is never written inside an audited tree (`--output` refuses it), and
  caches live in the per-user cache directory.
- **Static by default.** A check must be able to run without executing the
  audited site's PHP. Facts that require loading WordPress belong behind
  `--live` and must degrade to `skipped` with a reason when it is off — never
  to a guess and never to a check that cannot run at all without it.
- **No fabricated findings.** Checks report `skipped`/`unknown` with a reason
  when they cannot determine their condition. Say "unverifiable" when that is
  the truth (a plugin with no WordPress.org release is not a modified plugin).
- **Secrets never leave the process.** Anything parsed from `wp-config.php`
  that looks secret-shaped flows through `internal/redaction` before output,
  and every target-controlled string passes `internal/sanitize` before it
  reaches a terminal, a Markdown document, or a log line.
- **Do not trust the target's own directory.** Configuration comes from the
  operator (`--config`, the user config directory, or an explicit
  `--trust-project-config`); nothing in a scanned tree may change what is
  checked or how results are scored.
- **Stable IDs.** Check IDs, categories, exit codes, and the JSON schema are
  public API. Renames are breaking changes and must be called out in
  `CHANGELOG.md` with the schema version bumped when the report shape changes.
- **Boring dependencies.** No new third-party dependency without a strong
  justification, healthy maintenance status, and a compatible license.

## Contributing a check

1. Discuss first in an issue: what does it catch, what is the evidence, what
   is the false-positive story?
2. Implement in `internal/checks/<category>.go`, registering via
   `checks.Register` with a stable ID, category, title, description, and
   references.
3. Set `Meta.Importance` deliberately. `ImpCore` is for checks whose absence
   is a blind spot (integrity, vulnerability data, authentication controls);
   `ImpContext` is for advisory/policy checks. Coverage is scored from these
   weights, so the choice changes what "coverage: 60%" means.
4. Model WordPress defaults correctly (see `WP_DEBUG_DISPLAY` for the pattern
   where an unset constant still has a default behaviour).
5. Use the bounded walker (`fsutil.go` / `ctx.walk`) for anything that walks;
   never an unbounded `WalkDir`, and never a walk that silently stops without
   reporting truncation.
6. Record what you could not examine with `ctx.AddGap` — an unresolved path
   constant, an unavailable provider, an unreadable subtree. A gap is how the
   report stays honest about a clean-looking result.
7. Emit `Occurrences` for anything a consumer might want to address
   individually (one per file, plugin, advisory, or user) instead of joining
   values into one evidence string.
8. Size the finding honestly: severity for impact, confidence for certainty,
   and `info` for exposure or policy signals that should stay visible without
   moving the risk score.
9. Tests: registry presence, pass case, fail case, skip cases, and fixture
   data. Keep fixture-generation helpers in `checks_test.go`. If the check
   parses hostile input, add a fuzz target (see `internal/wordpress/fuzz_test.go`).
10. Update `docs/checks.md` (registry table + detail section) and the check
    list in `README.md`.

## Repository hygiene

The repository is public and stays publishable:

- `.gitignore` covers build output, generated scan reports, local policy
  overrides, secret material, OS/editor state, and the maintainers' research
  dumps (dated folders under `docs/`). Those documents describe weaknesses of
  this tool, so they are never published.
- `make hygiene` enforces it: it fails when a private, generated, or
  machine-specific file is tracked, or when a tracked file leaks an absolute
  developer path. CI runs it on every change, so the rules cannot rot.
- Because ignore rules do not apply to files that are already tracked, remove
  such a file from the index (`git rm --cached`) as well as from `.gitignore`.

## Branch model

- **`dev`** is the default branch and the integration target: features, fixes,
  and documentation land here first, and CI runs on every push to it.
- **`main`** carries released states. It is updated from `dev` at release time,
  and release tags are cut from it.
- Work happens on short-lived topic branches off `dev`, merged back with a pull
  request. Nothing is pushed directly to `main`.

Maintainers configure the repository's GitHub settings with
`scripts/github-setup.sh` (idempotent, reports anything it cannot do yet).
Branch protection and secret scanning require a public repository or a paid
plan, so those steps complete after publication.

## Pull requests

- Branch from `dev`; keep commits tidy (`feat:`, `fix:`, `docs:`, `chore:`).
- `make lint && make test` must pass, and `make test-race` before a change to
  anything concurrent or context-driven. CI additionally runs the five fuzz
  targets, `govulncheck`, a four-platform build, and the integration job
  against a real WordPress release.
- Include tests for behaviour changes; fixture-driven, deterministic, no
  network. The one deliberate exception is `make integration`.
- Update docs (`README.md`, `docs/*.md`) and `CHANGELOG.md` when behaviour,
  flags, or output change. `SECURITY.md` states the trust model — update it if
  a change alters what the scanner executes, requests, or writes.

## Reporting bugs

Include: `wpus version`, OS/arch, the command line, redacted JSON output if
possible, and what you expected. Never paste real secrets, salts, or full
`wp-config.php` contents — redact them; we do not need them to reproduce.

## License

By contributing you agree your contributions are licensed under the MIT
License of this repository.
