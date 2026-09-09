# Scoring

The score is a deterministic function of the findings: same findings → same
score, on any machine, in any order. It is documented, reproducible, and
severity-aware — and informational noise cannot distort it.

## Weights

Each failed finding contributes by severity:

| Severity | Weight |
|---|---|
| critical | 40 |
| high | 20 |
| medium | 10 |
| low | 4 |
| info | 0 |

## Volume decay

Within one severity group (ranked by weight, ties broken by check ID for
stability), the first three findings count at full weight; every subsequent
finding in that group counts at **half** weight (rounding up to stay
integral). Rationale: a critical vulnerability should move the score hard,
but fifty medium findings should not zero a site on their own.

## Formulas

- `overall = clamp(0, 100, 100 − Σ contributions)` over all failed findings
- `category = clamp(0, 100, 100 − Σ contributions of that category)`

Passed, skipped, and unknown findings contribute nothing — an environment
that cannot run a check is not penalized for it.

## Worked example

Findings: 1× high (vulnerable plugin), 4× medium, 4× low.

- high: 20 → deduction 20
- medium: first three 10+10+10, fourth 10/2=5 → deduction 35
- low: first three 4+4+4, fourth 4/2=2 → deduction 14

`overall = 100 − 69 = 31` — and that is *before* decay matters much; the
shape just keeps 20 lows from being −80.

## Category scores

Every finding also debits its own category, so reports show where risk lives:

```text
Core            100
Configuration    86
Authentication  100
Plugins          80
Themes          100
Filesystem       96
Server          100
```

Implementation: `internal/scoring/scoring.go` (~80 lines, unit-tested for
weights, decay, clamping, and order-independence).
