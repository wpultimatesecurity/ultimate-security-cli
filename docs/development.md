# Development

## Requirements

- Go 1.25+ (`brew install go`). CI builds with the current stable toolchain
  (the standard library is part of the shipped binary, so patch releases
  matter) and a `minimum-go` job keeps the declared floor working.
- GNU make (or run the recipes manually)
- Optional: PHP on `PATH` for the differential version-comparator test
  (`brew install php` on macOS, `apt-get install php-cli` on Debian/Ubuntu).
  The test skips itself when `php` is absent.
- Optional: `curl`, `tar`, and `python3` for `make integration`, which also
  needs network access.

## Getting started

```bash
git clone https://github.com/wpultimatesecurity/ultimate-security-cli
cd ultimate-security-cli
make build          # ./wpus
make test           # unit tests (fixtures only; no network, no real sites)
./wpus scan --offline testdata/demo-site   # try it on the bundled fixture
```

## Daily commands

| Command | Purpose |
|---|---|
| `make build` | Build `wpus` for the current platform |
| `make hygiene` | Fail if a private, generated, or machine-specific file is tracked |
| `make test` | All tests |
| `make test-race` | Tests with the race detector |
| `make vet` | `go vet ./...` |
| `make fmt` | Format the tree |
| `make fmt-check` | Verify formatting (CI mode) |
| `make lint` | `fmt-check` + `vet` |
| `make fuzz` | 20–30s fuzz run over the five hostile-input targets |
| `make vulncheck` | `govulncheck ./...` over the module |
| `make integration` | End-to-end integrity check against a real WordPress release (network) |
| `make release-local` | All four release binaries + checksums into `dist/` |
| `make clean` | Remove build artifacts |

`make hygiene` (`scripts/check-public-tree.sh`) is the publish gate: it fails
if a file that must never be public is tracked (release binaries, research
dumps, local policy overrides, secret material, generated reports), or if a
tracked file contains an absolute developer path. `.gitignore` only stops new
files from being added, so this check looks at what git actually carries. Run
it before publishing or after touching `.gitignore`.

`make integration` (`scripts/integration.sh`) downloads a real WordPress
release, verifies it against the WordPress.org checksum service, tampers with a
core file, and asserts the tampering is reported with its exact path. It needs
network access, so it is deliberately separate from `make test`; CI runs the
same script, so a local run and CI cannot drift apart.

## Testing notes

- Tests never touch the network: release data, checksum APIs, feed downloads,
  REST probes, and WP-CLI are stubbed or disabled (`--offline`, and the static
  default never invokes WP-CLI at all).
- Fixtures are constructed in `t.TempDir()` at runtime, plus the committed
  `testdata/demo-site` used by docs and smoke tests.
- When adding a check, add: registry presence, one pass case, one fail case,
  and the skip conditions. See `internal/checks/checks_test.go` for the
  patterns.
- `t.Chdir` is used for config-path tests; `os.Chmod` for permission fixtures
  (CI is Linux/macOS only).

### Fuzz targets

`make fuzz` runs five targets for 20–30 seconds each:

| Target | Package | What it hunts |
|---|---|---|
| `FuzzParseWpConfig` | `internal/wordpress` | panics and unbounded reads in the lexical `wp-config.php` parser |
| `FuzzVersionCompare` | `internal/wordpress` | transitivity violations in PHP-compatible version ordering |
| `FuzzVersionBetween` | `internal/wordpress` | range-matching invariant breaks |
| `FuzzSanitizers` | `internal/sanitize` | output that escapes an output channel or grows unbounded |
| `FuzzScrubber` | `internal/redaction` | a secret the scrubber fails to remove |

To fuzz one target for longer, use the package directly:

```bash
go test ./internal/wordpress/ -run=XXX -fuzz=FuzzParseWpConfig -fuzztime=10m
```

Corpus files a failing run writes under `testdata/fuzz/` are worth committing
as regression seeds.

### PHP differential test

`TestVersionCompareMatchesPHP` in `internal/wordpress/version_test.go` feeds a
generated corpus to both `VersionCompare` and a real `php` binary in one
batched process; any disagreement fails, and the corpus is checked for
degeneracy so the comparison cannot pass vacuously. Install PHP to run it:

```bash
brew install php            # macOS
apt-get install php-cli     # Debian/Ubuntu
go test ./internal/wordpress/ -run TestVersionCompareMatchesPHP -v
```

Without PHP on `PATH` the test skips with a clear message; the pure-Go cases
still run.

The comparison requires **PHP 8.4 or newer**. PHP 8.4 changed
`version_compare()`'s canonicalization (a trailing dot is now stripped, see
php-src `ext/standard/versioning.c`), which is the semantics this port
implements; older versions order degenerate inputs such as `1.0 ` differently.
On an older PHP the corpus comparison skips with that reason, and the pinned
cases in `TestVersionCompare` — including the divergent inputs — still run.
CI installs PHP 8.4 on Linux so the comparison is exercised on every change.

### Documentation consistency

`internal/checks/docs_test.go` reads `docs/checks.md` and `README.md` and
compares them with the live registry: every registered check must appear in
both, with the same category and the same coverage importance, and no
documented check may be missing from the code. Adding or re-classifying a
check therefore fails the suite until the docs follow.

### Adversarial fixtures

Beyond ordinary unit tests, the suite contains fixtures for the trust boundary
itself:

| Concern | Test |
|---|---|
| A static scan never executes target PHP | `internal/app/app_test.go`: `TestStaticScanNeverExecutesTargetPHP` |
| A scanned directory cannot disable its own checks | `internal/app/app_test.go`: `TestProjectConfigIsNotTrustedByDefault` |
| Output injection cannot restructure a report | `internal/app/app_test.go`: `TestOutputIsInjectionSafe`, `internal/reporting/reporters_test.go`: `TestOutputInjectionCannotRestructureReports` |
| Zero targets fail the run | `internal/app/app_test.go`: `TestZeroTargetsFailsTheRun` |
| A secret never reaches output | `internal/redaction/redaction_test.go` |
| A hostile site URL cannot reach metadata or private hosts | `internal/probe/probe_test.go`, `internal/app/app_test.go`: `TestProberPolicyForSiteURL` |
| Integrity detects a tampered or missing core file | `internal/checks/integrity_test.go` |

## CI

`.github/workflows/ci.yml` runs five jobs:

| Job | What it does |
|---|---|
| `test` | Public-tree hygiene (`make hygiene`), gofmt check, `go vet`, and `go test -race ./...` on Linux and macOS |
| `fuzz` | The five fuzz targets, 20–30s each |
| `vulncheck` | `govulncheck ./...`; fails only on vulnerabilities reachable from called code |
| `build` | Cross-builds the four release targets (`linux`/`darwin` × `amd64`/`arm64`) |
| `integration` | Runs `make integration`: downloads a real WordPress release, asserts the core checksum checks pass on a pristine tree, then appends to a core file and asserts `CORE_INTEGRITY_MODIFIED` fails with the exact path |

The integration job is the end-to-end proof of the flagship path against the
real WordPress.org checksum service; it is not run by `make test` (run it with
`make integration`).

## Repository settings

`scripts/github-setup.sh` configures the GitHub side with `gh`: description,
topics, issue/wiki/project toggles, delete-branch-on-merge, vulnerability
alerts and automated security fixes, secret scanning, the default branch, and
branch protection for `dev` and `main`. It is idempotent and reports steps that
cannot run yet as `PENDING` with the reason — a private repository on a free
plan, for instance, gets no branch protection, and the default branch cannot
be changed before `dev` exists on the remote.

```bash
scripts/github-setup.sh              # everything except visibility
scripts/github-setup.sh --public     # also flip visibility (one-way door)
```

Making a repository public cannot be undone (forks and caches keep the
content), which is why it takes an explicit flag and is done by a human after
`make hygiene` passes.

## Versioning

- `internal/version` holds build identity; release builds inject values via
  `-ldflags -X` (see `Makefile` / `.goreleaser.yaml`).
- JSON output `schema_version` changes only when the report shape changes; 2.0
  renamed `score` to `risk_score` and added coverage, confidence, fingerprints,
  and occurrences.
- Check IDs and categories are stable API; renaming one is a breaking change
  and must be called out in `CHANGELOG.md`.

## Releases

Releases are produced with GoReleaser (`version: 2` config checked in):

```bash
goreleaser check     # validate config
goreleaser release --snapshot --clean   # local dry run into dist/
```

Publication is a manual, human task — CI never releases.

A tag matching `v*` runs `.github/workflows/release.yml`: it builds all four
targets plus `checksums.txt`, creates a **draft** release (so a bad tag is
fixable before anyone downloads it), and signs a build provenance attestation
for every artifact with `actions/attest-build-provenance`, which anyone can
check with `gh attestation verify <artifact> --repo <owner>/<repo>`.

Validate the release configuration locally before tagging:

```bash
goreleaser check                              # config validity
goreleaser release --snapshot --clean         # build every target into dist/ without publishing
```

Branch model: `dev` is the default (integration) branch, `main` holds released
states, and tags are cut from `main`. CI runs on pushes to both and on every
pull request.

Actions policy: every `uses:` is pinned to a commit SHA (Dependabot keeps the
pins current), the workflow token defaults to read-only, and the repository
rejects tag-pinned actions. Workflows request the permissions they need
explicitly — see the `permissions:` block in `release.yml`.

## Dependency licenses

Runtime dependencies (kept deliberately minimal):

| Module | License |
|---|---|
| `github.com/spf13/cobra` | Apache-2.0 |
| `github.com/spf13/pflag` (indirect) | BSD-3-Clause |
| `github.com/inconshreveable/mousetrap` (indirect) | MIT |
| `gopkg.in/yaml.v3` | MIT |

Everything else is the Go standard library. New dependencies require a
license and maintenance review (see CONTRIBUTING.md).

## Code style

- gofmt, no exceptions; `make fmt-check` runs in CI.
- Small, boring functions. Errors wrapped with context (`fmt.Errorf("...: %w", err)`).
- No new dependencies without: maintenance status, license check, and a
  clear reason the stdlib cannot do the job.
- Every package has a doc comment explaining its responsibility.
