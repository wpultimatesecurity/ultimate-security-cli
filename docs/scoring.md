# Scoring

The scanner reports **two independent numbers**. Reading either one alone is
a mistake, and the reports are designed so that you cannot do it by accident:

```text
Risk:      92/100      how much risk the findings represent
Coverage:  61%         how much of the audit actually ran
Confidence: medium     derived from coverage
```

A high risk score with low coverage means *"not examined"*, not *"clean"*.
Terminal and Markdown reports print an explicit warning whenever coverage is
below 80%.

## Risk score

The risk score is a deterministic function of the findings: same findings →
same score, on any machine, in any order. It is documented, reproducible, and
severity-aware — and informational noise cannot distort it.

### Weights

Each failed finding contributes by severity:

| Severity | Weight |
|---|---|
| critical | 40 |
| high | 20 |
| medium | 10 |
| low | 4 |
| info | 0 |

### Volume decay

Within one severity group (ranked by weight, ties broken by check ID for
stability), the first three findings count at full weight; every subsequent
finding in that group counts at **half** weight (rounding up to stay
integral). Rationale: a critical vulnerability should move the score hard,
but fifty medium findings should not zero a site on their own.

### Formulas

- `overall = clamp(0, 100, 100 − Σ contributions)` over all failed findings
- `category = clamp(0, 100, 100 − Σ contributions of that category)`

Passed, skipped, unknown, and **suppressed** findings contribute nothing. A
suppressed finding stays in the report (with its reason) but stops moving the
score and the exit policy — that is the difference between "accepted risk" and
"deleted finding".

### Policy signals are informational

Some checks describe exposure or policy rather than a missing control, and
they must not debit a universal score. They fail at `info` severity (weight 0)
so they remain visible without moving the number, and they carry `ImpContext`
coverage weight:

| Check | Default severity | Why |
|---|---|---|
| `DEFAULT_DATABASE_PREFIX` | info | A prefix is not a control, and changing it on a live site is invasive. |
| `XMLRPC_ENABLED` | info | Legitimate on many sites; the real control is rate limiting. |
| `FILE_MODS_ALLOWED` | info | Correct for immutable/deployment-managed sites, wrong for others. |
| `FORCE_SSL_ADMIN_DISABLED` | info | Modern WordPress already forces HTTPS for admin when the site URL is HTTPS. |
| `REST_USER_ENUMERATION` | low | A verified exposure and a real footgun, but a public login name is not a broken control. |

Raise any of them with `severity_overrides` when your project treats them as
requirements:

```yaml
severity_overrides:
  XMLRPC_ENABLED: medium
```

### Worked example

Findings: 1× high (vulnerable plugin), 4× medium, 4× low.

- high: 20 → deduction 20
- medium: first three 10+10+10, fourth 10/2=5 → deduction 35
- low: first three 4+4+4, fourth 4/2=2 → deduction 14

`overall = 100 − 69 = 31`.

## Coverage score

Coverage answers a different question: **how much of the audit reached a
conclusion?** It is the share of check *weight* whose status is `passed` or
`failed`; `skipped` and `unknown` count against it.

Each check carries an importance weight:

| Importance | Weight | Assigned to |
|---|---|---|
| `ImpCore` | 3 | Integrity, vulnerability data, authentication controls, configuration secrets, exposure of backups/secrets, WordPress layout resolution. |
| `ImpStandard` | 2 | The default: most posture checks. |
| `ImpContext` | 1 | Advisory/policy checks (see the table above). |

A site whose vulnerability database was unavailable therefore loses more
coverage than one that could not read a server config file — which is the
point: a missing `PLUGIN_VULNERABILITY` is a blind spot, a missing
`DIRECTORY_LISTING` is a detail.

Confidence is derived from coverage:

| Coverage | Confidence |
|---|---|
| ≥ 90% | high |
| ≥ 70% | medium |
| < 70% | low |

### What reduces coverage

- `--offline` (release data, vulnerability lookups, checksum manifest, probes).
- A missing WP-CLI and no `--live`: update state, admin accounts, XML-RPC, PHP runtime facts.
- No configured vulnerability provider: every vulnerability check.
- `--verify-plugin-checksums` not passed: plugin file integrity.
- A filesystem walk hitting its time/file budget (`coverage.walk_truncated`).
- A WordPress path constant that could not be resolved statically
  (`CUSTOM_CONTENT_PATH` reports `unknown`, and the check appears as a gap).

Every gap is listed with its check ID, status, and the reason the check
reported, so a low coverage score is always explainable:

```json
"coverage": {
  "score": 61,
  "checks_determined": 26,
  "checks_total": 42,
  "confidence": "medium",
  "gaps": [
    {"check_id": "PLUGIN_VULNERABILITY", "status": "skipped",
     "reason": "vulnerability data unavailable — configure a provider", "importance": 3}
  ],
  "files_walked": 4213
}
```

## Coverage as a policy

```bash
wpus scan /srv/site --fail-on-coverage-below 80
```

or in configuration:

```yaml
fail_on_coverage_below: 80
```

This is the CI-grade guard: a pipeline cannot go green on a scan that did not
actually inspect the site.

## Category scores

Every failed finding also debits its own category, so reports show where risk
lives:

```text
Core            100
Configuration    86
Authentication  100
Plugins          80
Themes          100
Filesystem       96
Server          100
```

Implementation: `internal/scoring/scoring.go` (risk weights, decay, clamping,
and order-independence are unit-tested; coverage weighting and confidence
boundaries are covered by the same package's tests).
