# Development

## Requirements

- Go 1.25+ (`brew install go`)
- GNU make (or run the recipes manually)

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
| `make test` | All tests |
| `make test-race` | Tests with the race detector |
| `make lint` | `gofmt` check + `go vet` |
| `make fmt` | Format the tree |
| `make release-local` | All four release binaries + checksums into `dist/` |
| `make clean` | Remove build artifacts |

## Testing notes

- Tests never touch the network: release data, REST probes, and WP-CLI are
  either stubbed or skipped via `--offline`/`--skip-wpcli` paths.
- Fixtures are constructed in `t.TempDir()` at runtime, plus the committed
  `testdata/demo-site` used by docs and smoke tests.
- When adding a check, add: registry presence, one pass case, one fail case,
  and the skip conditions. See `internal/checks/checks_test.go` for the
  patterns.
- `t.Chdir` is used for config-path tests; `os.Chmod` for permission
  fixtures (skip on Windows-like filesystems is unnecessary — CI is
  Linux/macOS only).

## Versioning

- `internal/version` holds build identity; release builds inject values via
  `-ldflags -X` (see `Makefile` / `.goreleaser.yaml`).
- JSON output `schema_version` changes only when the report shape changes.
- Check IDs and categories are stable API; renaming one is a breaking change
  and must be called out in `CHANGELOG.md`.

## Releases

Releases are produced with GoReleaser (`version: 2` config checked in):

```bash
goreleaser check     # validate config
goreleaser release --snapshot --clean   # local dry run into dist/
```

Publication is a manual, human task — CI never releases.

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
