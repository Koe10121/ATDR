# v5.38 End-To-End Product Reliability And Failure-Mode Lock

## Status

v5.38 is a local product-reliability lock for the supported ATDR workflow. It
adds one disposable acceptance command, repairs three confirmed presentation
and operations defects, and verifies that important failures remain concise,
recoverable, and non-authoritative.

The measured local acceptance passes `11/11` gates. This is controlled
synthetic SQLite evidence and source-backed startup coverage, not production,
shared-host, MFU-provider, or real-device acceptance.

Supervised lifecycle remains `shadow_observation`. Deterministic rules remain
alert-authoritative. The SOC Assistant remains read-only. Automatic response
and real firewall blocking remain disabled.

## Confirmed Defects And Fixes

1. **Reused process identifiers could look active.** The launcher previously
   accepted a stored PID when any process currently owned that PID. Startup now
   also compares the recorded process start time before treating launcher
   metadata as active.
2. **Three critical pages lacked a page-level API failure state.** Overview,
   AI Governance, and Response & Audit now show one concise alert when their
   primary query fails. The response error explicitly confirms that no action
   was executed; the model error confirms that no model state changed.
3. **Viewport coverage omitted Response & Audit and User Admin.** The existing
   projector/laptop/mobile overflow test now covers all eight primary routes.

No parser, detection, deduplication, model, IAM, Assistant authority, database
schema, or API behavior was changed.

## Canonical Acceptance Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v538_product_reliability_acceptance --use-temp-db --pretty
```

The command refuses to run without `--use-temp-db`. It composes the existing
v4.8 product workflow with v5.38 startup, UI, RBAC, Assistant, review-integrity,
and response-safety checks. Detailed reports are written only under ignored
`demo_exports/v5_38_product_reliability/` unless `--no-write` is used.

The command never returns raw evidence, private paths, IP addresses, provider
payloads, or secrets. A top-level error reports only a bounded error type.

## Measured Workflow

The reference run used 64 synthetic records and produced:

- 64 attempted, raw, and normalized rows;
- three intentional raw-fallback parse failures with evidence preserved;
- 15 duplicate raw rows accounted for during recovery exercises;
- one `possible_port_scan` alert and one deduplication update;
- occurrence count and related-log count both equal to 20;
- source traceability, one case, and Why Flagged evidence;
- retained Assistant context, an alert citation, and deterministic provider
  failure fallback; and
- unchanged configured database state with temporary artifacts removed.

## Failure-Mode Coverage

The acceptance covers or composes tested contracts for:

- malformed records and parser fallback;
- duplicate import and alert deduplication;
- interrupted and cancelled import resume;
- stale worker lease recovery;
- malformed Assistant review packs;
- Assistant provider failure;
- missing alert and source references;
- unavailable database error handling;
- frontend API failure states;
- unauthorized RBAC requests; and
- Assistant refresh/navigation continuity.

Startup source contracts and focused PowerShell tests cover clean paths with
spaces, broken virtual environments, missing pip recovery, Node/dependency
preflight, missing shell configuration, unavailable database messaging,
occupied ports, stale launcher metadata, and start/check/stop identity rules.
They do not replace a separate clean-machine or approved MFU preproduction
exercise.

## Safety And Privacy Result

- missing response justification: denied;
- protected internal target: denied;
- approved block and unblock: simulated and audited;
- real response actions: zero;
- Assistant external provider in acceptance: false;
- Assistant raw-log context: false;
- Assistant authoritative mutations: zero;
- model activation/promotion: false;
- response automation: false; and
- real firewall blocking: false.

## Remaining External Gates

v5.38 closes the currently automatable local reliability loop. It does not
complete these externally owned gates:

1. genuine independent review of the sealed detection and Assistant packs;
2. second physical-device/native-source validation;
3. MFU IAM shared-preproduction acceptance, recovery, and deprovisioning;
4. institutional Gemini privacy, retention, quota, cost, and key-rotation
   approval;
5. approved-host PostgreSQL, monitoring, backup/restore, load, and disaster
   recovery evidence; and
6. any separately governed real response integration.

## Verification

- Taskboard render and standard checks: passed.
- Ruff: passed.
- Source compileall with ignored processed fixtures excluded: passed.
- Backend: `918 passed, 1 skipped`.
- Alembic: at head with no drift.
- React lint/build: passed.
- Playwright: `34 passed, 1 skipped` (intentional live-source skip).
- Final controlled source acceptance: passed.
- Layered detection: `288/288`, zero controlled FP/FN.
- Deterministic Assistant QA: `20/20`, all word budgets passed, zero
  authoritative side effects.
- v5.38 acceptance: `11/11`.
- Replay: dry-run only, zero writes.
- Performance smoke: all budgets passed with no warnings.
- Release gate: `ok: true`, including `918 passed, 1 skipped`.

The unadjusted local compileall command encountered intentionally malformed
Python fixture copies inside old ignored pytest directories under
`atdr/data/processed`. No tracked source failed compilation. The canonical
release command excludes the ignored processed area and passed; those local
artifacts were preserved rather than deleted.

No commit or push is authorized by this document.
