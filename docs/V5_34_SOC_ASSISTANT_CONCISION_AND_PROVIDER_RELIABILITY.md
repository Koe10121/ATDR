# v5.34 SOC Assistant Concision And Provider Reliability

## Status

v5.34 closes the known automated Assistant response-contract defect. The SOC
Assistant remains read-only decision support. It cannot run detection, change
labels, activate models, manage users, delete data, create response actions, or
perform firewall blocking.

The refreshed eight-case acceptance pack passes `8/8` automated content,
grounding, citation, privacy, and safety contracts. Human acceptance remains
`0/8`; no automated result is represented as human approval.

## Root Causes

The v5.33 investigation brief had two independent length paths. The visible
answer was bounded, but Gemini's structured evidence, next-step, and limitation
sections bypassed the shared compact presentation renderer. The acceptance
evaluator correctly counted those visible detail sections and rejected the
case. The old investigation contract also allowed 300 words, which was too
large for the intended SOC workflow.

The exact reason for the single historical v5.33 ML-governance fallback was
not retained because v5.33 stored only fallback use, not a normalized failure
category. v5.34 adds payload-free categories and reproduced real provider
degradation as quota/provider availability failures followed by the circuit
breaker. The deterministic fallback remained grounded and safe.

## Response Contracts

Both deterministic and external-provider answers now pass through the same
presentation builder. It applies semantic evidence deduplication, compact
sections, citation preservation, and mode-specific limits:

| Response mode | Limit |
| --- | ---: |
| Direct fact | 80 words |
| Alert explanation | 110 words |
| Safe next step | 100 words |
| Related logs | 120 words |
| Source health | 100 words |
| List summary | 100 words |
| Case handoff | 120 words |
| Investigation brief | 160 words |
| How-to | 180 words |
| AI governance | 100 words |

Investigation briefs now retain one compact summary, up to three evidence
points, one assessment, two checks, and one evidence-specific limitation.
Persistent dashboard safety badges carry generic safety policy; the answer
body repeats safety language only when the question concerns response,
containment, blocking, approval, or another safety boundary.

## Provider Reliability

Provider failures are classified without storing provider payloads:

- timeout;
- quota;
- rate limit;
- malformed output;
- citation rejection;
- safety rejection;
- grounding or quality rejection;
- provider availability;
- circuit breaker; and
- configuration/disabled state.

Safe aggregate telemetry includes counts, latency, token totals, and category.
It excludes prompts, answers, raw logs, IP addresses, API keys, provider error
payloads, and secrets. Timeout/retry limits and the circuit breaker remain in
force.

## Acceptance Result

The final bounded run produced these answer counts:

| Mode | Cases | Maximum words | Limit |
| --- | ---: | ---: | ---: |
| Alert explanation | 2 | 67 | 110 |
| Related logs | 1 | 68 | 120 |
| Safe next step | 1 | 56 | 100 |
| Investigation brief | 1 | 160 | 160 |
| Source health | 1 | 55 | 100 |
| Case handoff | 1 | 47 | 120 |
| AI governance | 1 | 43 | 100 |

Automated answer contracts pass `8/8`. The final external-provider run accepted
Gemini for one answer, encountered three quota outcomes, and then kept four
questions local through the circuit breaker. Measured request latency was
`1,592-4,071 ms` with median `1,622.5 ms`; the accepted provider output used
`4,895` total tokens. Cost rates are not configured, so no cost claim is made.

Provider availability is reported independently from answer quality. A safe,
grounded deterministic fallback can pass its answer contract while the
provider contract remains degraded. This avoids both hiding provider failures
and incorrectly calling a safe local answer defective.

## Safety Result

- Raw-log context sent to Gemini: false.
- IP redaction: enabled.
- Secrets/provider payloads returned: false.
- Configured-database authoritative mutations: zero.
- Disposable alert, detection, label, model, response, and user mutations:
  zero.
- Model activation/promotion: false.
- Automatic response and real blocking: false.

## Verification Result

- Focused compatibility and v5.34 regressions: `21 passed`; the repaired
  v5.24/v5.25 compatibility set adds `13 passed`.
- Full backend and official release-gate backend runs: `890 passed, 1 skipped`.
- Ruff, source compile, and Alembic no-drift: pass.
- npm audit: zero vulnerabilities; React lint/build: pass.
- Playwright: `31 passed, 1 skipped`; the skip requires external live-source
  hardware.
- Controlled detection: `24/24`; layered detection: `288/288` with zero
  controlled false positives or false negatives.
- Deterministic Assistant QA: `20/20`; replay dry-run wrote zero rows.
- Official release gate: `ok: true` with no failed required checks.

Performance smoke remained read-only and `ok: true`. At 145,232 logs, cached
Overview was `0.0197s`, but the cold Overview/ingestion summary was `5.8552s`
and exceeded the local SQLite budgets. This is an existing scale advisory,
not an Assistant regression, and remains visible rather than waived.

## Remaining Work

Four major external/evidence phases remain:

1. Complete legitimate independent human review of the sealed detection pack.
2. Validate source holdout/live collection using a second verified physical
   device.
3. Make a supervised lifecycle decision only after every frozen gate passes.
4. Complete Assistant human acceptance and obtain university/provider privacy,
   quota, retention, cost, and key-rotation approval.

The configured Gemini project's quota must be reviewed before expecting every
question in a burst to use the external provider. ATDR remains usable during
provider degradation because deterministic fallback is part of the governed
design.

## Commands

Run deterministic Assistant QA:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa --pretty
```

Refresh the untouched eight-case pack with bounded provider use:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v533_independent_detection_assistant_acceptance --prepare-assistant-review --refresh-assistant-review --execute-provider --provider-interval-seconds 2 --pretty
```

The refresh command refuses to overwrite human input. Generated acceptance
worksheets and reports remain ignored and must not be committed.
