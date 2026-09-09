# Using wpus from AI agents

`wpus` treats autonomous coding agents (Codex, Claude Code, OpenCode, Cursor,
cron-driven bots) as first-class users. Everything an agent needs is
machine-readable, non-interactive, and exit-code driven.

## Design guarantees for agents

- `--json` emits exactly one parseable document; decorative text goes to
  stderr only (and quiet mode suppresses it).
- `schema_version` is stable; breaking changes bump it.
- Exit codes are a contract: `0` pass, `1` `--fail-on` threshold met,
  `2` usage error, `3` runtime error, `4` permission denied.
- `skipped`/`unknown` findings tell you *why* in `evidence.reason` — an agent
  never has to guess what a check could not see.
- No interaction, no TTY requirement, `--offline` for hermetic runs.
- Colors auto-disable when stdout is piped.

## Standard workflow

```text
1. Run: wpus scan --json [--offline] [--fail-on high]
2. Parse .sites[] — one entry per WordPress installation.
3. For each site, filter .findings to status == "failed".
4. Sort by severity (critical > high > medium > low > info).
5. Read .description and .evidence for root cause; weigh .confidence.
6. Produce remediation steps from .recommendation and .references.
7. Do not modify production without explicit user authorization.
```

### jq recipes

All findings at high or above, as TSV:

```bash
wpus scan --json | jq -r '
  .sites[] as $s | $s.findings[]
  | select(.status=="failed")
  | select(.severity=="critical" or .severity=="high")
  | [$s.path, .severity, .id, .title] | @tsv'
```

What was skipped and why:

```bash
wpus scan --json | jq -r '
  .sites[].findings[]
  | select(.status=="skipped")
  | "\(.id): \(.evidence.reason)"'
```

Score and category breakdown:

```bash
wpus scan --json | jq '.sites[] | {path, score, categories}'
```

## Sample prompts

- “Run `wpus scan --json`, review every high and critical finding, explain
  the root cause, and propose fixes. Do not modify anything.”
- “Run `wpus scan --json --fail-on high`. If it fails, analyze the findings
  and create an implementation plan.”
- “Run `wpus scan --offline --format markdown testdata/demo-site` and explain
  each finding to me like I'm the site owner.”
- “Run `wpus discover --json` and list the WordPress sites on this machine
  with their versions.”

## CI integration

```bash
# Fail the pipeline when high+ findings exist.
wpus scan /var/www/site --json --fail-on high

# Report only, never fail.
wpus scan --json
```

`--fail-on` accepts `critical`, `high`, `medium`, `low`. Informational
findings never fail a run by themselves.

## Writing reports

`--format markdown` renders a GitHub-flavored report suitable for pasting
into issues and pull requests: per-site score tables, grouped findings with
evidence and recommendations. `--output <file>` is on the roadmap; today
redirect stdout.

## Safety model

The scanner is read-only by construction (see
[architecture.md](architecture.md#read-only-guarantee)). Agents should still
follow the golden rule: audit results inform humans; remediation on live
systems requires explicit authorization.
