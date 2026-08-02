# T1-T20: v5.22 Supervised Model Rebuild

## T1 Change Title

v5.22 Supervised Model Rebuild.

## T2 Requirement

Compare and freeze at most one native PAN-OS supervised shadow configuration
using only locked development roles, without opening blind evidence or changing
model, alert, or response authority.

## T3 Source Evidence

v5.21 native role manifest, v5.4 governed evidence lock, v5.6 feature/model
machinery, configured reviewed-label provenance, and the private PAN-OS source
supplied only by CLI argument.

## T4 Current Behavior

Earlier candidates were unstable across chronology/schema and either noisy or
poorly calibrated. v5.21 provided a new native chronological role lock but no
ground truth or candidate rebuild.

## T5 Impacted Areas/Agents

Supervised detection, evidence governance, privacy/security, QA, documentation,
and orchestration.

## T6 Scope

Add a development-only runner, six-strategy comparison, honest provenance
classification, manual-provenance holdout, source-holdout fail-closed gate,
feature-contract stabilization, warning classification, tests, status,
candidate contract, taskboard, and allowlist.

## T7 Functional Requirements

Reproduce v5.21 roles exactly; keep future/blind evidence sealed; distinguish
human from assisted provenance; compare requested strategies; calibrate and
select thresholds only on dedicated roles; freeze one configuration; write no
artifact; and preserve all authority/safety controls.

## T8 Acceptance Criteria

The exact role lock must reproduce, no duplicate family may cross roles, the
manual holdout must be reported honestly, source holdout must fail closed when
unavailable, no private data may be returned, all authoritative counts must be
unchanged, and verification must pass.

## T9 API Contract

No API change. The CLI is:

```powershell
python -m atdr.scripts.run_v522_supervised_model_rebuild `
  --sample-path <private-path> --use-temp-db --pretty
```

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Private derived evidence uses disposable
SQLite; generated reports stay ignored.

## T11 Backend Plan / Changes

Add the v5.22 service and CLI; validate the v5.21 and governed locks; weak-label
development roles only; compare six strategies; rank by cross-view stability;
freeze a public configuration contract; and verify zero writes.

## T12 Frontend Plan / Changes

No frontend behavior change. A candidate is not exposed as active because no
artifact was activated.

## T13 Security / Response / AI Safety

No raw rows, IPs, private paths, fingerprints, secrets, fabricated human
labels, blind decisions, model artifact, activation, promotion, automatic
response, or real blocking.

## T14 Test Plan

Test future-role exclusion, provenance integrity, all-null contract handling,
real model comparison, stability ranking, informational warning handling,
v5.21 lock reproduction, redaction, and zero side effects.

## T15 Implementation Summary

Eight focused tests cover the new service. The complete run compared six
strategies across four development views and froze the hierarchical two-stage
ExtraTrees configuration at threshold `0.40` without serializing it.

## T16 Tests Run / Evidence

Focused v5.22 tests pass `8/8`. The complete 773,551-row run reproduces the
v5.21 role lock, keeps 112,004 future rows sealed, includes a 114-row human-only
holdout, writes no authoritative entity/artifact, and reports worst-case F1
`0.8025`, FPR `0.0476`, suspicious recall `0.5000`, malicious recall `1.0000`,
and ECE `0.3741`. Full backend/release verification passed
`808 passed, 1 skipped`; Playwright passed `27 passed, 1 skipped`; controlled
and layered detection passed `24/24` and `288/288`; Assistant QA passed
`20/20`; performance smoke had no warnings; and the release gate returned
`ok=true`. Full evidence is recorded in the v5.22 status.

## T17 PRD / Docs Updated

v5.22 status, candidate contract, this change record, PRD, traceability,
compliance, current AI/system status, runbooks, docs index, taskboard, and
cumulative allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Suspicious recall and calibration fail. One real source prevents source
generalization. Weak-policy agreement is not independent accuracy. Human or
provider-confirmed blind labels remain external.

## T19 Release / Rollback

No commit/push is authorized. Rollback removes the v5.22 service, CLI, tests,
and docs; no database or artifact rollback is required.

## T20 Final Handoff

Proceed to v5.23 live-source acceptance while leaving supervised ML in
`shadow_observation`. Do not open blind labels merely to improve the candidate.
