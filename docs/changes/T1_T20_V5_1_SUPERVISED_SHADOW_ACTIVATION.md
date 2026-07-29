# T1-T20: v5.1 Governed Supervised SOC Queue Activation

## T1 Change Title

v5.1 Governed Supervised SOC Queue Activation and Detection Closure.

## T2 Requirement

Register and operationally activate a reproducible supervised SOC review-queue
model without making it alert-authoritative. Start in shadow observation and
permit bounded decision-support influence only after every predeclared quality,
calibration, leakage, external-evidence, latency, and safety gate passes.

## T3 Source Evidence

- Runtime: `atdr/app/detection/supervised_detector.py`,
  `atdr/app/detection/supervised_workflow.py`,
  `atdr/app/services/detection_service.py`.
- Features/evaluation: `atdr/app/ml/features.py`,
  `atdr/app/detection/v398_independent_holdout_validation.py`,
  `atdr/app/detection/v49_detection_ml_reliability.py`.
- Registry/data model: `atdr/app/db/models.py`, `atdr/app/routers/ml.py`.
- Explanations/UI: `atdr/app/detection/explanations.py`,
  `atdr/app/services/assistant_service.py`,
  `frontend/src/pages/MLGovernance.tsx`.
- Private validation: `atdr/app/services/private_log_preflight_service.py`,
  `atdr/app/services/v50_shadow_validation_service.py`.
- Prior evidence: `docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md` and locked
  ignored v4.0/v4.9 reports.

## T4 Current Behavior

Before v5.1, ATDR had diagnostic supervised candidates and an unknown legacy
artifact, but no governed active model with complete registry provenance. Rules
were authoritative and supervised activation was not justified by the 0/5
strict split result.

## T5 Impacted Areas/Agents

Backend/ML, API, React AI Governance, assistant/explanations, QA, security and
response safety, release/docs, and private-lab validation.

## T6 Scope

In scope: reproducible reviewed-label dataset, duplicate/leakage isolation,
candidate comparison, calibrated binary queue artifact, registry lifecycle,
shadow inference, telemetry, explanations, admin disable/rollback, private-file
shadow validation, UI truth, tests, and documentation.

Out of scope: production promotion, autonomous response, real blocking,
automatic label creation, real-device accuracy claims, external-provider tuning,
database reset, and startup-command changes.

## T7 Functional Requirements

1. Use latest eligible reviewed labels and preserve source provenance.
2. Keep fit, calibration, threshold, and final-test roles separate.
3. Enforce temporal, source/group proxy, and random split gates.
4. Register a versioned ignored artifact with checksum and dataset metadata.
5. Activate only `shadow_observation` unless every gate passes.
6. Keep rules authoritative and inference failure safe.
7. Expose bounded queue evidence and honest limitations.
8. Audit activation, disable, and rollback without deleting evidence.

## T8 Acceptance Criteria

- Fresh artifact serializes, hashes, and scores within the shadow latency budget.
- Registry distinguishes governed state from the unknown legacy artifact.
- All leakage audits pass.
- Failed quality/calibration/external gates block `decision_support`.
- Shadow scoring creates no alerts, detection runs, labels, or response actions.
- Private validation changes neither configured DB nor artifacts.
- AI Governance shows real lifecycle metadata and disabled automation.
- Full verification passes.

## T9 API Contract

- `GET /api/ml/supervised/lifecycle`: analyst/admin lifecycle status.
- `POST /api/ml/supervised/models/{id}/activate`: admin, shadow by default;
  gated decision-support mode.
- `POST /api/ml/supervised/models/disable`: admin, audited and non-destructive.
- Existing model registry and prediction routes remain compatible.

No API returns an API key, raw private evidence, or response authority.

## T10 Data Model / Migration

No schema migration. Existing `MLModelRun` and `AuditLog` records store the
governed candidate, lifecycle operation, artifact identity, validation metrics,
and actor. Model binaries and generated reports remain ignored.

## T11 Backend Plan / Changes

- Add `v51_supervised_lifecycle.py`.
- Add training/lifecycle CLI commands.
- Route supervised prediction and registry through governed state.
- Add safe lifecycle API routes.
- Add queue evidence to explanations and assistant ML status.
- Extend disposable private shadow validation for the governed artifact.

## T12 Frontend Plan / Changes

Show lifecycle, model/version, feature set, calibration, validation, and response
state in AI Governance. Keep candidate details collapsed and never present the
legacy unknown artifact as selected.

## T13 Security / Response / AI Safety

- Rules remain alert-authoritative.
- Shadow scores cannot create/suppress alerts or change severity.
- Model output cannot execute containment.
- Production promotion is rejected.
- Response automation and real blocking stay false.
- Weak/unreviewed labels are excluded; assisted provenance is not called human.
- Private logs, paths, raw rows, reports, artifacts, DB, and secrets stay out of Git.

## T14 Test Plan

Backend lifecycle, checksum, scoring, failure fallback, authorization,
disable/audit, label/evidence preservation, registry truth, explanations,
private-log invariants, scenarios, release gate, and hygiene. Frontend lint,
build, Playwright lifecycle rendering, response-disabled state, and overflow.

## T15 Implementation Summary

The fresh calibrated ExtraTrees binary queue was registered and activated as
`shadow_observation`. It passed artifact/leakage/latency safety checks but failed
strict reliability and external-evidence gates, so decision-support influence
remains denied. The unknown legacy artifact is preserved but unselected.

## T16 Tests Run / Evidence

Targeted lifecycle/API/registry tests passed. Full backend verification passed
640 tests with one hardware-dependent skip; Ruff, compileall, Alembic no-drift,
React lint/build, Playwright 26 passed with one hardware-dependent skip, replay
dry-run, taskboard checks, and the official release gate passed. The controlled
scenario matrix passed 24/24 and assistant QA passed 20/20 with zero unsafe side
effects. The layered diagnostic retained 21 rule/anomaly/hybrid FP/FN failures
out of 288 runs while supervised-only passed 72/72; this is blocker evidence,
not a promotion result. Private aggregate validation parsed 5,000/5,000
disposable rows and scored a 1,000-row sample with no configured-state mutation
or response action. Performance smoke passed with a narrow 2.1246-second ML
Governance advisory warning.

## T17 PRD / Docs Updated

- `docs/V5_1_SUPERVISED_SHADOW_ACTIVATION.md`
- `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
- `docs/AI_TRAINING_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md` and rendered HTML
- `README.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Blocker: temporal and source-transfer quality is unstable.
- Blocker: suspicious recall and calibration fail required gates.
- Blocker: locked external benchmark fails schema transfer.
- Assumption: network-zone split is a proxy, not true multi-device holdout.
- Decision: remain in shadow observation; do not weaken gates to force activation.
- Decision: private shadow queue rate is operational evidence, not accuracy.

## T19 Release / Rollback

No commit or push is authorized by this change. Disable with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --disable --pretty
```

Rollback with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.manage_supervised_lifecycle --rollback --pretty
```

Both operations are audited and preserve evidence and labels.

## T20 Final Handoff

Current state: fresh governed model active in shadow only; rules authoritative;
production false; response automation false. Next evidence must be independently
reviewed, multi-device/time, and schema-compatible before decision-support
influence is reconsidered.
