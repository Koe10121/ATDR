# T1-T20: v5.26 Native PAN-OS Blind Detection Qualification

## T1 Change Title

v5.26 Native PAN-OS Blind Detection Qualification and Error Analysis.

## T2 Requirement

Run a rigorous one-time prediction-before-label qualification of unchanged
ATDR detection layers against sealed native PAN-OS evidence while preserving
private-data, label-provenance, model-authority, database, and response-safety
boundaries.

## T3 Source Evidence

The source truth is the v5.21 native role manifest and blind pack, v5.22 frozen
candidate contract, v5.23-v5.25 runtime locks, detection services, existing
governed labels, private source supplied only through the CLI, and the current
tests and release gates. Private paths, row data, IP addresses, source
identities, and fingerprints remain outside tracked evidence.

## T4 Current Behavior

Before v5.26, ATDR had a 40-row suggestion-free blind pack and a frozen native
shadow candidate, but no one-time runner enforced prediction freeze, label
provenance separation, layer comparison, privacy-safe reporting, and repeat
execution lock together.

## T5 Impacted Areas/Agents

Orchestrator, detection engineering, AI/ML governance, data/evidence custody,
security and response safety, QA/UAT, release operations, and documentation.

## T6 Scope

In scope: evidence-lock validation, disposable private streaming, unchanged
rule/IsolationForest/supervised/hybrid scoring, private prediction lock,
legitimate-label audit, conservative readiness, tests, and governance.

Out of scope: label creation, label overwrite, model tuning on blind evidence,
artifact activation, alert-authority changes, automatic response, real
blocking, and production claims.

## T7 Functional Requirements

- Fail closed when role, duplicate, pack, source, or candidate locks mismatch.
- Remove human-decision fields before prediction.
- Persist a privacy-safe ignored prediction lock before opening labels.
- Count only independently human-reviewed decisions as blind ground truth.
- Withhold metrics when support or binary class coverage is insufficient.
- Reject repeat full qualification after the prediction lock exists.
- Preserve configured database, model registry, alerts, labels, and responses.
- Return no private path, raw row, IP, source identity, secret, or fingerprint.

## T8 Acceptance Criteria

The runner processes the private source only in disposable storage; blind rows
are absent from fit/calibration/threshold selection; predictions precede label
access; no fabricated human labels or misleading metrics appear; all safety
counters remain unchanged; and lifecycle stays `shadow_observation` unless
fixed independent-evidence gates legitimately pass.

## T9 API Contract

No API route or public schema changed. The safe CLI is:

```powershell
python -m atdr.scripts.run_v526_native_blind_qualification `
  --sample-path <private-panos-path> --use-temp-db --preflight-only --pretty
```

`--no-write` has preflight semantics. A consumed full qualification cannot be
rerun.

## T10 Data Model / Migration

No database schema or Alembic migration changed. Derived private evidence uses
disposable SQLite. Prediction locks and reports are generated under ignored
`ml_baseline_reviews/` and are excluded from the commit boundary.

## T11 Backend Plan / Changes

Add the v5.26 qualification service and CLI. Validate locks, reconstruct the
frozen candidate from development roles only, fit the advisory IsolationForest
on development evidence, score the sealed rows, persist the private lock,
audit labels after prediction, calculate metrics only with legitimate support,
and enforce one-shot execution.

## T12 Frontend Plan / Changes

No frontend change was required. Aggregate AI Governance exposure was judged
unnecessary while blind accuracy metrics are unavailable; existing lifecycle
and safety status remains the honest UI contract.

## T13 Security / Response / AI Safety

Rules stay alert-authoritative. IsolationForest, supervised, hybrid, and
Gemini remain advisory/read-only. No model artifact, activation, promotion,
alert mutation, automatic response, or real firewall action is permitted.
Private evidence and identifiers remain local and ignored.

## T14 Test Plan

Test label-field removal, pack-lock mismatch, insufficient-label metric
withholding, assisted-label rejection, legitimate balanced-label metrics,
redacted preflight, configured-DB/model/response immutability, repeat lock, and
the narrowly safe pre-lock repair. Run the complete repository verification
matrix after documentation is synchronized.

## T15 Implementation Summary

Implemented one privacy-safe, fail-closed native blind qualification workflow.
The measured run streamed 773,551 rows with zero parser failures, reconstructed
the frozen development contract in memory, and froze four-layer predictions
for 40 blind rows before checking human decisions.

## T16 Tests Run / Evidence

Focused v5.26 tests pass `8/8`. Taskboard, Ruff, compileall, backend `832
passed, 1 skipped`, Alembic no drift, React lint/build, Playwright `27 passed,
1 skipped`, rule/scenario contract 18/24, layered `288/288`, Assistant `20/20`,
v5.26 non-consuming preflight, replay dry-run, warning-free performance,
official release `ok: true`, and exact `15/15` privacy/hygiene checks pass.
The measured blind run completed with zero authoritative side effects. The pack
has zero genuine human decisions, so performance and calibration metrics were
correctly withheld. An in-repository pytest temp-root attempt was rejected by
the backup safety policy; targeted `21/21` and full `832 passed, 1 skipped`
reruns with an external temp root confirmed no product defect.

## T17 PRD / Docs Updated

v5.26 status, this T1-T20 record, exact allowlist, PRD, traceability,
compliance checklist, AI training runbook, current AI/ML status, lab runbook,
docs index, and taskboard Markdown/HTML.

## T18 Risks / Blockers / Assumptions / Decisions

The only source is one private collection and the blind pack has no independent
human labels. Queue distributions cannot be called true/false positives. The
initial run omitted a persistent row-matchable prediction lock; because zero
ground truth was observed and zero metrics were calculated, one deterministic
pre-lock correction was allowed and preserved. Full reruns now fail closed.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes the three v5.26 source/test
files and tracked documentation only. Ignored private evidence remains under
owner custody and must not be committed. No database rollback is required.

## T20 Final Handoff

Preserve the private prediction lock. Obtain independent blind human decisions
without exposing model/rule predictions, then evaluate against the existing
lock read-only. Do not tune on this consumed blind pack. Keep lifecycle
`shadow_observation` until a new independently validated candidate passes all
fixed gates.
