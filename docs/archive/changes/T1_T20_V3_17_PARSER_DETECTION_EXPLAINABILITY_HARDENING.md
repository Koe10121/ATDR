# T1-T20: v3.17 Parser, Detection, And Explainability Hardening

## T1. Change Title

v3.17 Parser, Detection, And Explainability Hardening

## T2. Requirement

Strengthen ATDR's core advisor requirements: parse and normalize logs safely, validate detection behavior with rules and decision-support ML context, and explain why logs/alerts are or are not flagged.

## T3. Source Evidence

| Area | Evidence |
| --- | --- |
| Parser | `atdr/app/parsers/paloalto_parser.py` |
| Log persistence | `atdr/app/services/log_service.py` |
| Detection | `atdr/app/services/detection_service.py`, `atdr/app/detection/rules.py` |
| Explanations | `atdr/app/detection/explanations.py` |
| Log/alert APIs | `atdr/app/routers/logs.py`, `atdr/app/routers/alerts.py` |
| Dashboard | `frontend/src/pages/LogExplorer.tsx`, `frontend/src/pages/AlertsTriage.tsx` |
| Existing validation | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Current docs | `docs/DETECTION_RULE_CATALOG.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

## T4. Current Behavior

ATDR already parses Palo Alto logs, preserves raw evidence, supports generic/raw fallback profiles, runs rule-based detection, supports anomaly/supervised decision support, and shows "Why flagged?" / "Why not flagged?" panels. v3.17 adds clearer validation commands and richer explanation fields.

## T5. Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Parser / Data Quality | Adds read-only validation script |
| Detection / QA | Adds controlled detection-quality summary script |
| Backend / API | Enriches explanation payload fields |
| Frontend | Existing panels consume payload without redesign |
| Docs / Governance | Updates PRD, traceability, compliance, catalog, and progress board |

## T6. Scope

In scope:

- Parser/normalization validation report.
- Detection quality validation report.
- Explanation payload improvements.
- Tests and docs.

Out of scope:

- Detection threshold changes.
- ML retraining, activation, or promotion.
- External IAM.
- Real SMTP.
- Real firewall blocking.
- Automatic response.
- Database schema changes.

## T7. Functional Requirements

- Parser validation reports parsed rows, failures, raw fallback, missing key fields, unknown apps, and top normalized values.
- Detection quality validation reports expected/actual alerts, missing/unexpected alerts, dedup count, explanation completeness, and no-response safety.
- Explanations include normalized fields, rule/anomaly/ML evidence, analyst next steps, and safety notes.

## T8. Acceptance Criteria

- `python -m atdr.scripts.validate_parser_normalization --pretty` succeeds on safe samples.
- `python -m atdr.scripts.validate_detection_quality --pretty` succeeds on core scenarios.
- Malformed/raw fallback lines do not crash.
- No response action is created.
- Existing dashboard explanation panels remain stable.

## T9. API Contract

No new HTTP API route. Existing log detail and alert detail payloads include richer explanation fields.

## T10. Data Model / Migration

No schema change and no Alembic migration.

## T11. Backend Plan / Changes

- Add `atdr/scripts/validate_parser_normalization.py`.
- Add `atdr/scripts/validate_detection_quality.py`.
- Enrich `atdr/app/detection/explanations.py`.

## T12. Frontend Plan / Changes

No redesign. Existing Log Explorer and Alerts panels already present concise explanation sections.

## T13. Security / Response / AI Safety

- Current DB is not mutated by default validation.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- ML remains decision support only.
- External IAM is not enabled.

## T14. Test Plan

- Parser normalization report test.
- Malformed/generic/raw fallback parser tests.
- Detection quality validation test.
- Explanation field tests.
- Full release verification.

## T15. Implementation Summary

Added parser and detection quality validators, enriched explanation payloads, added tests, and updated governance documentation.

## T16. Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

- `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`

## T18. Risks / Blockers / Assumptions / Decisions

| Item | Status |
| --- | --- |
| Real-source validation | Still future work |
| Unknown app-heavy scenarios | Expected in incomplete/scanning samples |
| Explanation quality | Structural validation only; analyst judgment still required |
| Decision | Do not change detection thresholds or ML model status in this phase |

## T19. Release / Rollback

Rollback is low risk because no schema changes were made. Remove the two scripts, tests, docs, and explanation field additions if needed.

## T20. Final Handoff

ATDR v3.17 improves parser/detection validation and analyst explanation quality while preserving all safety constraints.

