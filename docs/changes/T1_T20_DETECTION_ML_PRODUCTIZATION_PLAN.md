# T1-T20 Change Document: Detection And ML Productization Plan

## T1 Change Title

Detection And ML Productization Plan

## T2 Requirement

Create a source-backed plan for making ATDR detection and ML more product-grade while preserving safety constraints.

## T3 Source Evidence

- `atdr/app/detection/rules.py`
- `atdr/app/services/detection_service.py`
- `atdr/app/detection/ml_detector.py`
- `atdr/app/detection/supervised_detector.py`
- `atdr/app/ml/features.py`
- `atdr/app/detection/v355_severity_target_policy_reframing.py`
- `atdr/app/routers/ml.py`
- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/src/pages/AlertsTriage.tsx`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`
- `docs/V3_55_SEVERITY_TARGET_POLICY_REFRAMING.md`
- `docs/V3_56_SOC_QUEUE_DIAGNOSTIC_INTEGRATION.md`
- `docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md`
- Supervisor template PRD/workflow/taskboard under `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`

## T4 Current Behavior

ATDR has a layered detection stack with parser/normalization, deterministic rules, alert grouping/deduplication, IsolationForest anomaly scoring, supervised ML diagnostics, AI Governance, and SOC Assistant explanation support.

## T5 Impacted Areas / Agents

- Detection
- AI/ML Governance
- Backend/API
- Frontend/Dashboard
- SOC Assistant
- QA
- Docs/Release

## T6 Scope

Documentation and planning only. No runtime thresholds, model behavior, schema, IAM, response, or dashboard behavior changed.

## T7 Functional Requirements

- Identify current strengths and limitations.
- Define a safe product direction for rules, anomaly scoring, and supervised queue output.
- Keep exact severity classification as explanation/ranking only until stronger evidence exists.
- Define next implementation phases.

## T8 Acceptance Criteria

- Plan cites source evidence.
- Plan does not claim production readiness.
- Plan preserves no automatic response and no real firewall blocking.
- Plan identifies immediate next work.

## T9 API Contract

No API contract change.

## T10 Data Model / Migration

No schema or migration change.

## T11 Backend Plan / Changes

No backend code change in this planning step.

## T12 Frontend Plan / Changes

No frontend code change in this planning step.

## T13 Security / Response / AI Safety

- ML remains decision support.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- Generated reports and review files stay ignored.

## T14 Test Plan

- Regenerate tasklist HTML.
- Run tasklist standards check.
- Run `git diff --check`.
- Run a sensitive-file hygiene check.

## T15 Implementation Summary

Created `docs/DETECTION_ML_PRODUCTIZATION_PLAN.md` with rule-pack, scenario-corpus, SOC queue, exact severity, registry, drift, and promotion-gate direction.

## T16 Tests Run / Evidence

To be recorded in `docs/tasks/tasklist-progress.md`.

## T17 PRD / Docs Updated

- `docs/DETECTION_ML_PRODUCTIZATION_PLAN.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- The supervisor template does not provide a ready detection/ML pipeline.
- Real-source validation still requires lab hardware or sustained syslog source access.
- Future supervised model activation remains blocked until formal gates pass.

## T19 Release / Rollback

Rollback is documentation-only: remove the plan and index/taskboard references.

## T20 Final Handoff

Recommended next implementation phase: v3.71 Rule Pack And Scenario Contract.
