# v5.49a Supplemental Threat Anchor Recovery

## Status

v5.49a is complete. Its protected review is closed and immutable. It preserved
the closed v5.48 review and did not consume the old v5.48/v5.49 evaluation.

- original review: `120/120`, invalid `0`, formally closed and immutable
- original aggregate support: benign-like `92`, suspicious `9`, malicious `0`
- v5.49 execution count: `0`
- supplemental pack: `60` unique development-evidence rows
- threat-enriched rows: `57`
- hard-negative controls: `3`
- represented strata: `9` (`8` threat-oriented)
- supplemental review: `60/60`, invalid `0`, closed and immutable
- supplemental support: benign-like `3`, suspicious `30`, malicious `27`
- combined support: benign-like `95`, suspicious `39`, malicious `27`
- v5.49b proposal: created privately and consumed by the separately locked
  v5.49b protocol
- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- model activation, automatic response, and real blocking: disabled

The suspicious and malicious minimums are evaluation preconditions, not
labeling quotas. Reviewers must record only evidence-supported decisions.

## Acquisition Evidence

The private PAN-OS source was streamed into disposable SQLite storage and
produced `773,551` successfully parsed rows with zero parser failures. The
source path, file name, raw rows, IP addresses, source identities, row
fingerprints, and secrets were not returned or written to tracked files.

The deterministic selection produced:

| Evidence stratum | Rows |
| --- | ---: |
| Vendor threat, high severity | 19 |
| Vendor threat, other severity | 8 |
| Scan-like behavior | 10 |
| Unknown correlated transport | 6 |
| C2 or exfiltration evidence | 5 |
| Brute-force or access attempts | 4 |
| High-risk rule context | 4 |
| Denied high-risk service | 1 |
| Hard-negative control | 3 |

Exclusions were enforced before selection:

- closed v5.48 anchor families: `125`
- duplicate families: `15,767`
- locked or reserved evidence roles: `44,741`
- outside supplemental evidence policy: `74,201`
- prior manual-anchor families excluded from consideration: `706`

No supervised prediction, model score, assisted label, hidden truth, or class
target was used for selection. Original-anchor and future-role selections are
both zero.

## Protected Workflow Result

The authenticated owner completed all `60` rows and formally closed the
workspace. Other users could see aggregate progress but could not open or
modify row evidence.

For each row:

1. Inspect only the approved parser, traffic, correlation, and deterministic
   rule evidence displayed.
2. Choose `benign`, `benign_unusual`, `needs_context`, `suspicious`, or
   `malicious`.
3. Enter confidence `1-100` and a rationale of at least eight characters.
4. Enter an attack type for suspicious or malicious decisions.
5. Confirm that the decision is independently human-made, then save.

Class-support totals and minimums remained hidden while review was open.
Closure made every decision immutable and revealed only aggregate support.

## Proposed v5.49b Boundary

The closed supplemental review produced combined support above the fixed
minimums and created a private **proposal** for a new versioned v5.49b
protocol. The proposal itself did not lock or execute a model evaluation and
never modified the original v5.48 protocol.

Any later evaluation requires a separate protocol-lock decision, explicit
execution confirmation, and its own verification phase. No automatic retry,
training, activation, promotion, alert mutation, or response action is part of
v5.49a.

## Commands

Safe status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v549a_supplemental_threat_anchor_acquisition --status-only --pretty
```

Preparation requires the private file through `--sample-path`, disposable
storage through `--use-temp-db`, and explicit `--prepare-review`. The private
path must remain outside Git and must never be copied into documentation.

## Measured Safety

The preparation run confirmed:

- configured database counts unchanged
- original v5.48 files unchanged
- active model artifacts unchanged
- labels, model runs, detection runs, alerts, and response actions created: `0`
- human-reviewed labels created automatically: `0`
- v5.49 claim and result created: no
- v5.49 execution count: `0`
- predictions used or exposed: no
- response automation allowed: no

## Verification

- Taskboard render and standards checks passed.
- Ruff and canonical `compileall` passed.
- Focused v5.49a backend tests passed `5/5`.
- Full backend tests passed `1021`, with `1` intentional live-environment skip.
- Alembic reported no schema drift.
- React lint and production build passed; Playwright passed `37`, with `1`
  intentional live-source skip.
- Controlled source acceptance parsed `10/10` rows, created the expected
  port-scan alert, and created zero response actions.
- Layered detection validation passed `288/288` with zero controlled false
  positives or false negatives.
- Assistant QA passed `20/20`, stayed deterministic/read-only, and created no
  response, detection, model, label, alert, or log side effects.
- Replay remained dry-run only. Performance smoke met every local budget with
  no warnings; Overview cold/cached timings were `0.7920s` and `0.0104s`.
- The release gate returned `ok: true` with no failed required checks.

## Remaining Work

The supplemental human action is complete. v5.49b subsequently locked and
consumed its separate fixed protocol exactly once; no diagnostic candidate
qualified. Independent activation still requires fresh development evidence,
a second physical source, a new untouched future window, governed blind
validation, and explicit activation approval.

Broader product closure remains approximately eight substantial phases:
real-source/parser qualification, rule FP/FN evidence, supervised lifecycle
validation, Gemini governance, MFU IAM acceptance, shared deployment/security,
accessibility/clean-room usability, and release-candidate closure.
