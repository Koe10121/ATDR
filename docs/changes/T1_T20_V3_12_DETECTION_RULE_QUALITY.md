# T1-T20 Change Document: v3.12 Detection Rule Quality

## T1. Change Title

v3.12 Detection rule quality and alert noise reduction.

## T2. Requirement

Improve alert quality by reducing noisy duplicate alert rows while preserving strong detection, explanation quality, and response safety.

## T3. Source Evidence

| Evidence | Source |
| --- | --- |
| Rule definitions | `atdr/app/detection/rules.py` |
| Detection grouping | `atdr/app/services/detection_service.py` |
| Alert grouping and dedup | `atdr/app/services/alert_service.py` |
| Scenario expectations | `data/samples/scenarios/scenario_expectations.json` |
| Validation scripts | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Tests | `atdr/tests/test_detection_validation_suite.py` |
| Rule catalog | `docs/DETECTION_RULE_CATALOG.md` |

## T4. Current Behavior

v3.11 validation passed but produced 13 actual alerts against a simple positive-scenario expected count of 8. The extra rows were not missed detections; they were grouping/noise clarity issues in repeated beaconing and app-risk policy scenarios.

## T5. Impacted Areas / Agents

Detection, Alert Grouping, Scenario Validation, QA, Documentation, and Release/Ops.

## T6. Scope

In scope:

- Rule catalog.
- Scenario expectation clarity.
- Grouping improvements for repeated outbound and app-risk policy behavior.
- Validation report classification of expected/allowed/unexpected alert types.
- Regression tests.

Out of scope:

- ML retraining, activation, or promotion.
- Detection threshold tuning.
- Real response enforcement.
- Database schema changes.
- Startup command changes.

## T7. Functional Requirements

- Normal traffic scenarios must stay quiet.
- Port scan, brute force, malware/C2-like beaconing, exfiltration, DDoS/flood, and dedup scenarios must still detect.
- Validation must report expected primary attack type and allowed secondary attack types.
- Validation must flag unexpected/noisy attack types instead of hiding them.
- Response actions must remain zero.

## T8. Acceptance Criteria

- Validation reports expected alerts equal actual alerts.
- Mixed subnet scenario produces port_scan, brute_force, and malware_c2 alerts without duplicate beaconing rows.
- Suspicious app policy scenario groups into one alert.
- Explanation completeness remains 1.0.
- Full verification passes.

## T9. API Contract

No API contract changes.

## T10. Data Model / Migration

No migration or schema change.

## T11. Backend Plan / Changes

- Adjust detection grouping for app-risk policy rules and repeated destination rules.
- Improve scenario expectation checks in validation scripts.
- Improve grouped alert source/destination completeness detection.

## T12. Frontend Plan / Changes

No frontend runtime changes required.

## T13. Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No model activation or production promotion.
- No raw evidence deletion.

## T14. Test Plan

- Scenario validation tests for expected/actual counts.
- Regression tests for mixed subnet and policy app-risk grouping.
- Existing source scenario, response safety, and release tests.

## T15. Implementation Summary

v3.12 reduced controlled validation alert rows from 13 to 10 while preserving all required detections. It also made scenario expectations more explicit and added a rule catalog for advisor/team review.

## T16. Tests Run / Evidence

Final verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

Updated or added:

- `docs/DETECTION_RULE_CATALOG.md`
- `docs/V3_12_DETECTION_RULE_QUALITY.md`
- `docs/changes/T1_T20_V3_12_DETECTION_RULE_QUALITY.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- Decision: tune grouping/noise clarity, not rule thresholds.
- Decision: keep app-risk rules as triage signals with business-context caveats.
- Risk: real-source traffic may show additional noisy patterns.
- Risk: scenario validation is controlled and does not prove production readiness.

## T19. Release / Rollback

Rollback:

- Revert detection grouping changes.
- Revert scenario expectation/reporting changes.
- Revert docs/tests.

No data rollback is required.

## T20. Final Handoff

ATDR v3.12 improves rule quality and alert queue clarity while preserving detection coverage, explanation completeness, and response safety.
