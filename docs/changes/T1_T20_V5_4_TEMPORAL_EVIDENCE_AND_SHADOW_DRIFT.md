# T1-T20: v5.4 Temporal Evidence Curation And Shadow Drift Monitoring

## T1 Change Title

v5.4 Temporal Evidence Curation and Shadow Drift Monitoring.

## T2 Requirement

Create a trustworthy development-evidence boundary after v5.3 without tuning
on locked final windows, fabricating human review, or changing model/response
state.

## T3 Source Evidence

- v5.3 partitions and diagnostics:
  `atdr/app/detection/v53_temporal_generalization.py`.
- Governed lifecycle:
  `atdr/app/detection/v51_supervised_lifecycle.py`.
- Label/source schema: `atdr/app/db/models.py`.
- Parser/rule evidence: `atdr/app/parsers/paloalto_parser.py` and
  `atdr/app/detection/rules.py`.
- Private aggregate preflight:
  `atdr/app/detection/v50_private_shadow_validation.py`.

## T4 Current Behavior

v5.3 selected no candidate. Temporal and rolling FPR were near 1.0, source
holdout lacked two real devices, and the locked external benchmark failed.
Evidence roles were reproducible but not stored as a permanent tracked lock.

## T5 Impacted Areas/Agents

Detection/AI governance, evidence management, privacy, backend CLI, AI
Governance UI, QA, documentation, and release governance.

## T6 Scope

In scope: tracked aggregate fingerprints, chronological audit, development-only
manifest, duplicate quarantine, private aggregate inspection, weak review pack,
shadow drift state, tests, UI telemetry, and governance records.

Out of scope: human label creation, model tuning/selection/activation, active
artifact writes, response behavior, real blocking, and a fabricated source.

## T7 Functional Requirements

1. Lock fit/calibration/threshold/final/rolling/external/artifact evidence.
2. Fail closed on lock mismatch.
3. Exclude final and quarantine roles from development.
4. Preserve provenance and duplicate-group containment.
5. Keep assisted suggestions weak and non-import-ready.
6. Inspect private files through a CLI argument and return aggregates only.
7. Report one of four conservative shadow drift states.
8. Preserve all configured database, artifact, and response state.

## T8 Acceptance Criteria

- Role fingerprints reproduce exactly.
- Development-to-final overlap is zero.
- Private path/raw/IP/secret fields are absent.
- Assisted provenance is never called human-reviewed.
- No label, model run, detection run, response, or artifact write occurs.
- AI Governance exposes aggregate drift and evidence counts only.
- Full release and hygiene checks pass.

## T9 API Contract

No new endpoint. Existing supervised lifecycle data gains optional aggregate
v5.4 fields for lock status, drift status/findings, development/exclusion
counts, and independent-evidence sufficiency. Existing clients remain
compatible.

## T10 Data Model / Migration

No database schema or migration change. The immutable evidence lock is tracked
under `data/samples/benchmarks/`; row-level reports remain ignored under
`ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the v5.4 evidence module and safe CLI, lock validation, chronological
quality audit, development manifest, review pack, private aggregate scanner,
drift classifier, lifecycle summary integration, and conservative readiness.

## T12 Frontend Plan / Changes

Add compact Evidence Drift and Development Evidence cards plus collapsible
aggregate findings to AI Governance. Do not expose row-level evidence.

## T13 Security / Response / AI Safety

No raw/private evidence enters tracked output or API/UI. No label, model,
detection, response, user, or active artifact mutation. Rules remain
alert-authoritative and automation remains disabled.

## T14 Test Plan

Test locked-final exclusion, duplicate containment, provenance classification,
lock mismatch behavior, private redaction, drift classification, weak review
pack policy, lifecycle summary, UI rendering, and zero state mutation.

## T15 Implementation Summary

v5.4 locks all v5.3 evidence roles, curates 1,467 development rows, excludes
768 final/quarantined rows, reports material chronological drift as
`OOD Warning`, and generates an optional 200-row weak review pack. It creates
no new model or human label.

## T16 Tests Run / Evidence

Focused v5.1/v5.3/v5.4 tests passed 21 tests. The configured read-only run
matched the tracked lock, changed no database/artifact counts, and created zero
side effects. A full 773,551-row private aggregate preflight produced eight
chronological windows with zero parser errors and no private output. Ruff,
compileall, Alembic, React lint/build, 26-pass/1-skip Playwright, 24/24
controlled scenarios, 288/288 layered validation, 20/20 assistant QA, replay
dry-run, and release gate passed. The full backend and release-gate suites each
passed 663 tests with one hardware-dependent skip. Performance smoke passed
with one ML Governance advisory at 2.1575 seconds.

## T17 PRD / Docs Updated

v5.4 status, this T1-T20 record, exact allowlist, PRD, traceability,
compliance, AI training runbook, current AI/ML status, docs index, and
taskboard.

## T18 Risks / Blockers / Assumptions / Decisions

- Evidence contains one real device and clustered review periods.
- Fit-to-final application/provenance/schema drift is material.
- The locked external evidence remains failed and cannot be reused.
- Assisted suggestions require a human and are not import-ready.
- Decision: lifecycle remains `shadow_observation`; no candidate is selected.

## T19 Release / Rollback

No commit or push is authorized. No migration or active artifact was written.
Rollback is a normal source/UI/docs revert; generated ignored reports can be
discarded without changing configured data.

## T20 Final Handoff

ATDR now has an explicit development-evidence boundary and aggregate shadow
drift warning. The next legitimate supervised repair requires new independent
human-reviewed chronological/multi-device evidence, not tuning on v5.3 final
labels.
