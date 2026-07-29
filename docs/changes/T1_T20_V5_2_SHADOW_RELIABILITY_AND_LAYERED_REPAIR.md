# T1-T20: v5.2 Shadow Reliability And Layered Detection Repair

## T1 Change Title

v5.2 Shadow Observation Reliability and Layered Detection Repair.

## T2 Requirement

Repair controlled rule/anomaly/hybrid failures, evaluate supervised strategies
under strict independent views, add aggregate shadow telemetry, and improve
governance/explanations without granting ML or anomaly output alert or response
authority.

## T3 Source Evidence

- Rule/runtime: `rules.py`, `attack_mapping.py`, `detection_service.py`.
- Explanations: `explanations.py`, `AlertsTriage.tsx`.
- Model evaluation: `v49_detection_ml_reliability.py`,
  `v331_noise_reduction.py`, `v52_shadow_reliability.py`.
- Lifecycle/telemetry: `v51_supervised_lifecycle.py`, `routers/ml.py`.
- Validation: `generate_detection_variants.py`,
  `run_layered_detection_validation.py` and controlled scenario reports.
- Prior baseline: v4.9 and v5.1 status/change records.

## T4 Current Behavior

The baseline passed 267/288 layered runs. Three rule timing misses, nine
field-poor anomaly false positives, and nine hybrid errors remained. The v5.1
shadow artifact passed 0/5 strict quality views and was not allowed to
influence alerts.

## T5 Impacted Areas/Agents

Detection runtime, validation tooling, supervised evaluation, model lifecycle,
AI Governance, alert explanations, QA, security/safety, and documentation.

## T6 Scope

In scope: controlled regression repairs, read-only strategy/calibration/drift
evaluation, aggregate telemetry, UI truth, tests, and governance records.

Out of scope: label creation, production promotion, automatic response, real
blocking, database reset, startup changes, and claims of real-world accuracy.

## T7 Functional Requirements

1. Deterministic rules remain alert-authoritative.
2. Anomaly and supervised output remain advisory/shadow.
3. Repair all reproducible layered regressions without relabeling.
4. Evaluate every candidate on predeclared splits and gates.
5. Fail closed when source-disjoint evidence is unavailable.
6. Persist only aggregate, privacy-safe telemetry.
7. Expose honest lifecycle, drift, calibration, and blockers.

## T8 Acceptance Criteria

- Controlled scenarios pass 24/24.
- Layered matrix passes 288/288 with zero FP/FN and zero responses.
- Model evaluation does not mutate DB counts or active artifacts.
- A candidate is selected only if every required internal split passes.
- External final evidence is never used for tuning.
- UI and explanations distinguish authoritative and advisory evidence.
- Full verification and hygiene checks pass.

## T9 API Contract

Adds admin-only, audited `POST /api/ml/supervised/telemetry/snapshot` and extends
the existing supervised lifecycle response with safe aggregate telemetry and a
sanitized v5.2 reliability summary. No endpoint returns raw logs, private paths,
secrets, or action authority.

## T10 Data Model / Migration

No migration. Aggregate telemetry uses existing `MLModelRun` and `AuditLog`
records with a dedicated operation name and aggregate-only marker.

## T11 Backend Plan / Changes

Separate authoritative rule matches from anomaly evidence, repair validation
cadence, bound field-poor anomaly interpretation, add the v5.2 evaluator,
support sigmoid/isotonic diagnostics, record drift and strict gates, and add
aggregate telemetry persistence.

## T12 Frontend Plan / Changes

Add concise Shadow Reliability visibility to AI Governance and separate Rule
Authority, Anomaly Advisory, Supervised Shadow, and Hybrid Interpretation in
alert detail. Preserve responsive/overflow behavior.

## T13 Security / Response / AI Safety

No automatic labels, activation, promotion, response, or blocking. Evaluation
is read-only. Private validation is aggregate-only. Assisted labels retain
their provenance and are not called human-authored.

## T14 Test Plan

Rule/hybrid grouping, variant cadence, anomaly quality, failure matrix,
explanation contract, strategy/calibration selection, telemetry privacy/audit,
API authorization, React rendering, and all existing release regressions.

## T15 Implementation Summary

The controlled layered result improved from 267/288 to 288/288. The supervised
evaluation found no candidate that passes all required views; the leading
comparator remains unselected and the lifecycle remains shadow observation.

## T16 Tests Run / Evidence

Targeted v5.2 lint and backend tests passed 85 tests. The read-only evaluator
completed in 37.9717 seconds, recorded 24/24 controlled scenarios and 288/288
layered runs, selected no candidate, changed no configured database/artifact
state, and created zero response actions. Whole-repo Ruff and compileall passed;
the full backend and release-gate suites each passed 651 tests with one
hardware-dependent skip; Alembic reported no drift; React lint/build passed;
Playwright passed 26 with one hardware-dependent skip; assistant QA passed
20/20; private 5,000-row shadow validation, replay dry-run, warning-free
performance smoke, taskboard checks, and the release gate all passed.

## T17 PRD / Docs Updated

v5.2 status, this change record, AI runbook, current ML status, PRD,
traceability, compliance checklist, docs index, taskboard, and exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

- Temporal FPR is 1.0 for the leading comparator.
- Source holdout fails closed due insufficient independent devices.
- Network-zone suspicious recall and calibration fail.
- Locked external transfer fails.
- Decision: select no candidate and preserve `shadow_observation`.
- Decision: controlled regression success is not an accuracy claim.

## T19 Release / Rollback

No commit/push is authorized by this document. No schema rollback is needed.
The existing governed artifact remains removable through audited disable or
rollback operations; runtime rule repairs are ordinary source changes.

## T20 Final Handoff

Rules are authoritative and controlled layered behavior is clean. The
supervised queue is still shadow-only because stability, source independence,
calibration, and external transfer do not pass. Independent multi-device/time
evidence is the next model-quality requirement.
