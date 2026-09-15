# T1-T20: v3.18 Detection Corpus And FP/FN QA

## T1. Change Title

v3.18 Controlled Detection Corpus Expansion and False Positive / False Negative QA

## T2. Requirement

Expand ATDR's safe detection validation corpus and report false-positive / false-negative scenario outcomes clearly, while preserving current detection behavior, ML safety, response safety, and local workflow.

## T3. Source Evidence

| Area | Evidence |
| --- | --- |
| Parser | `atdr/app/parsers/paloalto_parser.py` |
| Log persistence | `atdr/app/services/log_service.py` |
| Detection | `atdr/app/services/detection_service.py`, `atdr/app/detection/rules.py` |
| Explanations | `atdr/app/detection/explanations.py` |
| Scenario registry | `atdr/scripts/run_source_scenario.py` |
| Validation | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/validate_detection_quality.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Scenario samples | `data/samples/scenarios/` |
| Current docs | `docs/DETECTION_RULE_CATALOG.md`, `docs/V3_17_PARSER_DETECTION_EXPLAINABILITY_HARDENING.md` |

## T4. Current Behavior

ATDR already parses safe Palo Alto-like, generic syslog, and raw fallback samples; runs rule-first detection; groups/deduplicates alerts; preserves raw evidence; and exposes analyst explanations. v3.18 expands the safe corpus and makes FP/FN validation explicit.

## T5. Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Parser / Data Quality | More safe scenario samples and malformed vendor rows |
| Detection / QA | Scenario-level FP/FN and unexpected attack-type reporting |
| Backend / Explanations | Adds clearer evidence aliases in alert summaries |
| Frontend | Type definitions updated only; no dashboard redesign |
| Docs / Governance | PRD, traceability, compliance, catalog, and progress board updated |

## T6. Scope

In scope:

- Safe synthetic scenario samples.
- Scenario expectations.
- Detection-quality report improvements.
- Explanation field aliases.
- Backend tests and docs.

Out of scope:

- Detection threshold changes.
- ML retraining, activation, or promotion.
- External IAM.
- Real SMTP.
- Real firewall blocking.
- Automatic response.
- Database schema changes.

## T7. Functional Requirements

- Validate benign/no-alert and positive-alert scenario groups.
- Report false-positive and false-negative scenario counts.
- Report parser warnings, raw fallback, dedup, and unexpected attack types.
- Preserve no-response safety checks.
- Keep explanations source-backed and decision-support only.

## T8. Acceptance Criteria

- Parser validation succeeds on expanded safe corpus.
- Detection-quality validation returns zero false-positive scenarios and zero false-negative scenarios.
- Positive scenarios create expected attack types.
- Benign scenarios do not create alerts.
- Malformed rows do not crash parser.
- No response action is created.

## T9. API Contract

No new HTTP API route. Existing alert/log explanation payloads include clearer optional evidence aliases.

## T10. Data Model / Migration

No schema change and no Alembic migration.

## T11. Backend Plan / Changes

- Add new scenario samples under `data/samples/scenarios/`.
- Update `scenario_expectations.json`.
- Update `run_source_scenario.py`.
- Extend `validate_detection_quality.py`.
- Extend explanation summary fields.

## T12. Frontend Plan / Changes

No redesign. Update TypeScript API types for optional explanation fields.

## T13. Security / Response / AI Safety

- Current DB is not mutated by default validation.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- ML remains decision support only.
- External IAM is not enabled.

## T14. Test Plan

- Expanded detection corpus tests.
- Benign/no-alert control tests.
- Positive attack-type expectation tests.
- Malformed vendor mixed-field parser test.
- Explanation section test.
- Full release verification.

## T15. Implementation Summary

Added ten safe synthetic scenario files, scenario expectations, explicit FP/FN validation reporting, rule-level QA summaries, explanation aliases, tests, and documentation updates.

## T16. Tests Run / Evidence

Verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

- `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`

## T18. Risks / Blockers / Assumptions / Decisions

| Item | Status |
| --- | --- |
| Real-source validation | Still future work |
| Scenario-level FP/FN | Controlled QA only, not production SOC metrics |
| Detection thresholds | Intentionally unchanged |
| Decision | Expand validation confidence before touching real IAM, ML activation, or response actions |

## T19. Release / Rollback

Rollback is low risk because no schema changes were made. Remove new scenario files, expectation entries, validation report changes, tests, and docs if needed.

## T20. Final Handoff

ATDR v3.18 improves detection QA coverage and false-positive / false-negative visibility while preserving all safety constraints.
