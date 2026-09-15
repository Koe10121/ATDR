# T1-T20 Change Document: v3.11 Detection Explainability Hardening

## T1. Change Title

v3.11 Detection quality and explainability hardening.

## T2. Requirement

Strengthen ATDR's core ability to parse and normalize logs, detect suspicious activity using layered detection, and explain why an alert or selected log was or was not flagged.

## T3. Source Evidence

| Evidence | Source |
| --- | --- |
| Parser profiles | `atdr/app/parsers/paloalto_parser.py` |
| Log detail API | `atdr/app/routers/logs.py`, `atdr/app/schemas/logs.py` |
| Detection rules and orchestration | `atdr/app/detection/rules.py`, `atdr/app/services/detection_service.py` |
| Explanation helpers | `atdr/app/detection/explanations.py` |
| Assistant deterministic answers | `atdr/app/services/assistant_service.py` |
| Dashboard log drawer | `frontend/src/pages/LogExplorer.tsx` |
| Validation CLI | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/run_detection_validation_suite.py` |
| Tests | `atdr/tests/test_parser.py`, `atdr/tests/test_detection_explanations.py`, `atdr/tests/test_detection_validation_suite.py`, `frontend/tests/smoke.spec.ts` |

## T4. Current Behavior

Before this pass, alert details had "Why flagged?" evidence, but selected log details did not expose a concise "why flagged / why not flagged" explanation. Scenario validation existed but did not provide a standalone compact detection-pipeline report with explanation-completeness scoring.

## T5. Impacted Areas / Agents

Backend/API, Detection, Parser/Normalization, Assistant, Frontend Dashboard, QA, Documentation, and Release/Ops.

## T6. Scope

In scope:

- Add log-level triage explanations.
- Add alert explanation completeness scoring.
- Add safe temporary-database detection validation CLI.
- Improve parser fallback tests.
- Lightly extend the read-only assistant to answer log explanation questions.
- Add concise dashboard display for log explanations.

Out of scope:

- Detection threshold changes.
- ML retraining, activation, or production promotion.
- Database schema changes.
- Real response enforcement.
- Automatic response.
- Raw-log context sharing through external LLMs.

## T7. Functional Requirements

- Normalized log detail should include a concise triage explanation.
- Explanation should distinguish flagged vs not-flagged status.
- Explanation should include normalized signals, parser warnings, alert IDs, safety flags, and analyst next steps.
- Detection validation should report expected/actual alerts, missed/unexpected alerts, parse failures, dedup behavior, and explanation completeness.
- Assistant should remain read-only while answering alert/log explanation questions.

## T8. Acceptance Criteria

- Parser tests cover Palo Alto, generic syslog, and raw fallback behavior.
- Explanation helper tests cover flagged and not-flagged logs.
- Detection validation CLI returns no response actions and a passing report for safe scenarios.
- Dashboard log drawer renders explanation text and safety badges without raw JSON overflow.
- Full verification passes.

## T9. API Contract

`GET /api/logs/{id}` now includes a read-only `triage_explanation` object:

```json
{
  "status": "flagged",
  "summary": "...",
  "reasons": ["..."],
  "normalized_signals": ["..."],
  "parser_warnings": ["..."],
  "alert_ids": [1],
  "decision_support_only": true,
  "response_automation_allowed": false,
  "analyst_next_steps": ["..."]
}
```

## T10. Data Model / Migration

No schema migration was added.

## T11. Backend Plan / Changes

- Add `explain_log_triage`.
- Add `alert_explanation_completeness`.
- Attach log triage explanation to log detail API responses.
- Add `validate_detection_pipeline` CLI.
- Extend assistant read-only deterministic explanation handling.

## T12. Frontend Plan / Changes

- Show concise log explanation panel in the Investigation log drawer.
- Keep safety badges visible.
- Keep detailed/raw evidence separated and non-overflowing.

## T13. Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- Assistant remains read-only.
- ML remains decision support only.
- Raw logs remain excluded from assistant context by default.

## T14. Test Plan

- Parser fallback tests.
- Explanation helper tests.
- Detection validation script tests.
- Log detail API response test.
- Frontend smoke coverage for log explanation panel.
- Existing response safety tests remain authoritative.

## T15. Implementation Summary

v3.11 adds source-backed explanation support to normalized log details and a safe detection-validation CLI. The implementation improves observability and advisor-facing explainability without changing detection thresholds, ML activation status, response safety, or schema.

## T16. Tests Run / Evidence

Final verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

Updated or added:

- `docs/V3_11_DETECTION_EXPLAINABILITY_HARDENING.md`
- `docs/changes/T1_T20_V3_11_DETECTION_EXPLAINABILITY_HARDENING.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- Decision: keep all output decision support only.
- Decision: validate with temporary synthetic scenarios rather than mutating the local dashboard DB.
- Risk: explanation completeness checks are structural and do not replace analyst judgment.
- Risk: more real-source validation is still needed for production-like claims.

## T19. Release / Rollback

Rollback:

- Remove `triage_explanation` from log detail schema/API.
- Remove log explanation panel from `LogExplorer`.
- Remove `validate_detection_pipeline`.
- Revert assistant log-triage branch.
- Revert docs/tests.

No data rollback is needed.

## T20. Final Handoff

ATDR now better explains both alerts and selected logs. The system can produce a compact safe detection-validation report for parser, detection, deduplication, and explanation completeness while preserving all existing safety constraints.
