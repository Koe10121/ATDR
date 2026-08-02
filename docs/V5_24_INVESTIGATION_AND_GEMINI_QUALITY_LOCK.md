# v5.24 Investigation and Gemini Quality Lock

## Status

`v5_24_quality_lock_passed` on 2026-08-02 for the bounded synthetic contract.
This is controlled quality evidence, not a claim that Gemini is always correct
or that ATDR is production-ready.

The v5.23 non-loopback sender gate was explicitly deferred by the owner. It
remains open with `phase_complete=false` and `real_device_validated=false`.

## What Changed

- Alerts now lead with what happened, why the rule flagged it, evidence
  strength, missing context, and recommended checks.
- Rule, ATT&CK-style mapping, anomaly, supervised-shadow, hybrid, and behavior
  details remain available under one collapsed detection-layer section.
- Log Investigation now shows evidence strength and missing context next to its
  deterministic flagged/not-flagged explanation.
- Assistant answers show the same evidence-first sections and keep verbose
  payload detail collapsed.
- Runtime navigation uses `Validation Controls`; remaining presentation/demo
  wording was removed from the affected runtime paths.
- Structured provider answers always receive the trusted primary citation from
  the server-side bounded citation list. Provider text cannot introduce a new
  record citation.

## Bounded Gemini Evaluation

The disposable evaluator asked six questions against synthetic ATDR records:

1. why an alert was flagged;
2. which logs are related as a same-conversation follow-up;
3. what the analyst should verify before response as a follow-up;
4. why a normalized log was or was not flagged;
5. source health and parser-quality review; and
6. computed case handoff.

Measured result:

| Measure | Result |
| --- | ---: |
| Quality gates | 11/11 passed |
| Provider answers used | 6/6 |
| Median latency | 3,125 ms |
| P95 latency | 3,731 ms |
| Total provider tokens | 18,675 |
| Unsupported record IDs | 0 |
| Implied action execution | 0 |
| Authoritative mutations | 0 |
| Raw-log context | disabled |
| IP redaction | enabled |

All six answers retained their requested alert/log/source/case context, had a
trusted record citation, contained expected evidence, met visible concision
limits, and passed the unsupported-ID/action-language checks. A deliberately
unreachable provider endpoint returned the deterministic fallback safely.

## Reproduce

No-provider preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v524_investigation_gemini_quality_lock --no-write --pretty
```

Bounded live-provider evaluation (uses private `.env` configuration and writes
only ignored diagnostics):

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v524_investigation_gemini_quality_lock --execute-provider --pretty
```

## Closure Verification

- Ruff and compileall passed.
- Full backend verification passed `817 passed, 1 skipped`; the first run found
  one stale RBAC source assertion for the intentional `Validation Controls`
  rename, and the corrected assertion passed in the full release rerun.
- Alembic reported no drift on local SQLite.
- React lint/build passed; Playwright passed `27 passed, 1 skipped`, with the
  external live-sender scenario intentionally skipped.
- Controlled detection passed `24/24`; layered detection passed `288/288` with
  zero controlled false positives or false negatives.
- Deterministic Assistant QA passed `20/20` with citation rate `1.0` and zero
  response-action mutations.
- Replay dry-run parsed the two-row safe sample and wrote zero rows.
- Read-only performance smoke passed without warnings: Overview `0.1653s`,
  cached Overview `0.0102s`, Alerts `0.0315s`, Cases `0.0212s`, and AI
  Governance `0.3250s` on 145,232 local logs.
- The official release gate returned `ok: true` with no failed required check.

## Safety And Limits

- The evaluator uses a disposable in-memory database and synthetic evidence.
- Raw log context remains disabled and IP addresses are redacted.
- No alert, detection run, label, model run, model artifact, user, or response
  action is created by assistant evaluation.
- Rules remain alert-authoritative. Supervised ML remains
  `shadow_observation` and advisory only.
- Gemini output is bounded decision support. The contract detects unsupported
  record IDs and unsafe action claims; it cannot prove every sentence is
  semantically correct on every future input.
- Provider latency, quota, model behavior, and availability can change.
- Real analyst-traffic evaluation and approved privacy/cost monitoring remain
  deployment gates.

## Next Phase

Proceed to v5.25 Integrated Acceptance. Carry forward the deferred v5.23
non-loopback sender gate and all supervised independent-evidence blockers as
open external requirements.

No commit or push is authorized by this phase.
