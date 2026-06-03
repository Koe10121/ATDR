# PRD: MFU ATDR

| Field | Value |
| --- | --- |
| Product | MFU AI-Driven Log-Based Threat Detection and Response System |
| Short name | ATDR |
| Current stage | v0.3 controlled lab-ready release candidate |
| Production claim | None. ATDR is not certified production software. |
| Main workflow doc | `docs/ATDR_AI_WORKFLOW.md` |
| Agent model | `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| Change template | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| Current runbook | `docs/LAB_RUNBOOK.md` |

## Source Evidence

| Evidence | Repository Source |
| --- | --- |
| Product summary, startup commands, API highlights, CLI workflow | `README.md` |
| FastAPI app and mounted routers | `atdr/app/main.py` |
| Database entities and indexes | `atdr/app/db/models.py` |
| Backend routes | `atdr/app/routers/*.py` |
| React route/page truth | `frontend/src/App.tsx`, `frontend/src/pages/*` |
| Frontend scripts and dependencies | `frontend/package.json` |
| AI feature generation | `atdr/app/ml/features.py` |
| Detection and explanation services | `atdr/app/detection/*`, `atdr/app/services/detection_service.py` |
| Release gate | `atdr/scripts/verify_release.py` |
| Current status | `docs/V0_3_STATUS.md` |
| Lab operations | `docs/LAB_RUNBOOK.md` |
| AI workflow | `docs/AI_TRAINING_RUNBOOK.md`, `docs/ML_BASELINE_TUNING.md` |
| IAM/RBAC permission matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

## Product Overview

ATDR is a defensive cybersecurity monitoring prototype for controlled small-office or university lab validation. It ingests firewall/syslog logs, preserves raw evidence, normalizes fields, runs explainable rule-based detection, adds ML-assisted anomaly and supervised scoring, groups alerts, supports analyst investigation, and records simulated analyst-approved response actions in audit logs.

ATDR does not currently perform real firewall blocking. It does not claim production readiness or production ML accuracy.

## System Purpose

ATDR exists to demonstrate and validate:

- Realistic firewall log ingestion and parsing.
- Raw evidence preservation for every investigation.
- Explainable alert generation.
- AI-assisted but analyst-controlled triage.
- Source health and parser profile visibility.
- Safe response simulation with audit trail.
- Lab-ready workflow that can later be validated with PostgreSQL, Docker, and real device syslog forwarding.

## Users And Roles

| Role | Purpose | Current Evidence |
| --- | --- | --- |
| Admin | Configure users, demo controls, source management, threat controls, response simulation actions | `atdr/app/routers/users.py`, `atdr/app/routers/demo.py`, `atdr/app/routers/response.py` |
| Analyst | Investigate alerts/logs, update alert status, review evidence, label logs, view audit and ML governance | `atdr/app/routers/alerts.py`, `atdr/app/routers/logs.py`, `atdr/app/routers/ml.py` |
| Supervisor/advisor | Review dashboard, evidence, runbooks, acceptance status, and lab-readiness claims | `docs/V0_3_STATUS.md`, `docs/ACCEPTANCE_TEST_CHECKLIST.md` |

The current role and permission matrix is documented in `docs/security/ATDR_IAM_RBAC_MATRIX.md`. ATDR does not currently include a viewer/read-only role, external SSO, OAuth, SAML, LDAP, or an enterprise identity provider.

## Current Capabilities

### Ingestion And Parsing

- Import log files through scripts and API.
- Replay logs to simulate near-real-time ingestion.
- Receive local UDP syslog in lab mode.
- Track log sources and source health.
- Support parser profiles: `palo_alto`, `generic_syslog`, `raw_fallback`.
- Preserve raw evidence even when parsing fails.

Evidence: `atdr/app/routers/logs.py`, `atdr/app/routers/sources.py`, `atdr/scripts/replay_logs.py`, `atdr/scripts/run_syslog_receiver.py`, `atdr/scripts/run_source_scenario.py`, `atdr/app/db/models.py`.

### Detection And Cases

- Rule-first detection.
- IsolationForest anomaly scoring.
- Supervised ML decision-support classifier.
- Hybrid risk scoring.
- Alert deduplication and occurrence counting.
- Case grouping for related alert patterns.
- ATT&CK-style mapping and "Why flagged?" explanations.

Evidence: `atdr/app/services/detection_service.py`, `atdr/app/detection/*`, `atdr/app/services/case_service.py`, `atdr/app/routers/alerts.py`.

### AI Governance

- `ml_labels` table with analyst-reviewed labels.
- Assisted weak-label generation.
- CSV review import/export.
- Active learning samples.
- Supervised model training, dataset snapshots, feature-set metadata, comparison experiments, tuning, error analysis, model registry, and evaluation reports.
- Promotion gate that keeps the model in analyst-review / candidate status unless readiness checks pass.

Evidence: `atdr/app/db/models.py`, `atdr/app/routers/ml.py`, `atdr/app/detection/supervised_workflow.py`, `atdr/scripts/train_supervised_model.py`, `atdr/scripts/export_supervised_dataset_snapshot.py`, `atdr/scripts/run_supervised_experiment.py`, `atdr/scripts/tune_supervised_model.py`, `atdr/scripts/supervised_sanity_report.py`, `atdr/scripts/analyze_supervised_errors.py`, `atdr/scripts/generate_assisted_labels.py`, `docs/AI_TRAINING_RUNBOOK.md`.

Recovery workflow evidence: `atdr/app/detection/supervised_recovery.py`, `atdr/scripts/supervised_dataset_audit.py`, `atdr/scripts/rebuild_supervised_baseline.py`, `atdr/scripts/run_binary_threat_experiment.py`, and `atdr/scripts/run_supervised_recovery_phase.py`. Recovery outputs are candidate-only diagnostics and must not be treated as production accuracy.

### Dashboard

- React-first dashboard with protected routes.
- Overview, Alerts, Investigation/Log Explorer, AI Governance, Response & Audit, Threat Controls, Detection Tuning, User Admin, and Demo Controls.
- Admin-only route protection for user/demo controls.

Evidence: `frontend/src/App.tsx`, `frontend/src/pages/*`, `frontend/src/lib/api.ts`.

### Response And Audit

- Simulated block/unblock response.
- Analyst/admin approval and justification.
- Protected IP safeguards.
- Denied and successful actions are audited.
- No real firewall connector is enabled.

Evidence: `atdr/app/routers/response.py`, `atdr/app/services/response_service.py`, `atdr/app/db/models.py`, `atdr/tests/test_response_safety.py`.

### Lab Operations

- Run history for ingestion and detection.
- Performance smoke checks.
- Release gate.
- Scenario runner with safe synthetic files.
- Lab runbook and acceptance checklist.

Evidence: `atdr/app/db/models.py`, `atdr/scripts/performance_smoke.py`, `atdr/scripts/verify_release.py`, `docs/LAB_RUNBOOK.md`, `docs/ACCEPTANCE_TEST_CHECKLIST.md`.

## Functional Requirements

| ID | Requirement | Status |
| --- | --- | --- |
| FR-ATDR-001 | Import firewall/syslog logs without losing raw evidence | Implemented |
| FR-ATDR-002 | Normalize Palo Alto traffic fields for investigation and detection | Implemented |
| FR-ATDR-003 | Preserve malformed/unmatched lines through raw fallback behavior | Implemented |
| FR-ATDR-004 | Track log source identity, parser profile, health, and quality | Implemented |
| FR-ATDR-005 | Run explainable rule-based detection | Implemented |
| FR-ATDR-006 | Run IsolationForest anomaly scoring as assistive ML | Implemented |
| FR-ATDR-007 | Train and evaluate supervised classifier from labels | Implemented as decision support with dataset snapshots, feature-set metadata, candidate comparison, threshold tuning, error analysis, and explicit activation/rollback |
| FR-ATDR-008 | Keep ML outputs explainable and non-authoritative | Implemented |
| FR-ATDR-009 | Generate alert evidence, lifecycle, notes, timelines, and reports | Implemented |
| FR-ATDR-010 | Deduplicate repeated alert patterns without deleting raw logs | Implemented |
| FR-ATDR-011 | Group related alerts into lightweight cases | Implemented |
| FR-ATDR-012 | Simulate response actions with approval and audit | Implemented |
| FR-ATDR-013 | Prevent automatic response from ML output | Implemented constraint |
| FR-ATDR-014 | Provide React dashboard for SOC workflow | Implemented |
| FR-ATDR-015 | Provide lab scenario validation with expected outcomes | Implemented |
| FR-ATDR-016 | Provide release verification and performance smoke checks | Implemented |
| FR-ATDR-017 | Enforce JWT authentication and admin/analyst RBAC on protected workflows | Implemented for lab roles |

## Non-Functional Requirements

| Area | Requirement |
| --- | --- |
| Safety | No real firewall enforcement until a future approved connector, allowlist, rollback, and change approval exist. |
| Auditability | Auth, imports, detection, labels, response, and workflow actions must be auditable. |
| Explainability | Alerts must show rule/model evidence and "Why flagged?" explanations where available. |
| Lab performance | SQLite is acceptable for local testing; PostgreSQL is recommended for shared lab scale. |
| Reliability | Release gate and tests must pass before declaring a checkpoint. |
| Security | JWT auth and role checks are required for protected endpoints. Demo secrets must be replaced before shared lab use. |
| Data privacy | Real logs, databases, model artifacts, generated exports, and `.env` files must stay out of Git. |

## IAM / RBAC Constraints

ATDR adapts the university IAM requirement as local authentication, authorization, role-based access control, response-safety permissions, and auditability.

- JWT authentication is implemented for protected API routes.
- `admin` and `analyst` roles are implemented.
- Admin-only actions include user management, demo controls, log import, source create/update, ML model training/scoring, and simulated block/unblock response.
- Analyst/admin actions include alert investigation, log investigation, detection runs, label review/import/export, ML report viewing, source health viewing, blocked-IP viewing, and audit viewing.
- Frontend role-aware navigation and `AdminRoute` help the user experience, but backend route dependencies are the authority.

Current limitations:

- No external SSO/OAuth/SAML/LDAP.
- No enterprise identity provider.
- No viewer/read-only role.
- Demo JWT secret must be replaced before shared lab or real deployment.
- Current role model is suitable for lab prototype validation, not production IAM.
- Role permissions must be fully reviewed before real deployment or response connector implementation.

## Safety Constraints

- Response mode remains simulation.
- Response requires analyst/admin approval and justification.
- Protected IP ranges must not be blocked by simulation actions.
- Denied response attempts must be audited.
- ML cannot automatically trigger containment.
- Weak labels cannot be presented as production ground truth.
- The project must not add offensive tooling.

## AI Governance Constraints

- Rule evidence remains primary.
- IsolationForest is anomaly support, not proof of malicious behavior.
- Supervised ML is SOC triage decision support.
- Threat-positive triage can prioritize analyst review, but flat five-class predictions are not production-promoted.
- Benign and needs_context exact classification remain known weak spots until reviewed coverage and live validation improve.
- Model status must distinguish `candidate_only`, `candidate_improved`, `eligible_for_analyst_review`, and any future promotion state.
- Production promotion cannot be claimed while reviewed labels and live validation are limited.
- Assisted labels must be marked as weak unless reviewed.

## Source Management Requirements

- `source_id` is optional so existing imports keep working.
- Unknown imports must use safe fallback source behavior.
- Source health must show healthy, idle, warning, error, or disabled.
- Disabling a source must not delete historical data.
- Parser profile mismatch or high parse failure rates must be visible.

## Lab-Readiness Requirements

- Normal local workflow remains unchanged.
- Docker/PostgreSQL is optional for this stage.
- Scenario validation uses synthetic safe logs under `data/samples/scenarios/`.
- Real device syslog validation is future/lab work and must be scoped safely.
- Performance smoke should stay healthy for local DB testing.

## Known Limitations

- SQLite slows down with large imports and is not the recommended shared lab database.
- PostgreSQL/Docker validation still needs a Docker-capable host.
- Real firewall blocking is not implemented.
- Real device forwarding needs controlled lab validation.
- Case grouping is lightweight and computed; it is not a full incident management system.
- Supervised ML still needs more reviewed labels and live validation before stronger claims.

## PRD Update Rules

Update this PRD when a change affects:

- Product scope or user workflow.
- API route, request, response, auth, or RBAC.
- Database schema, migration, indexes, or retention.
- React route, page, table/filter/action flow, or dashboard wording.
- Parser profile, source health, ingestion, replay, or syslog behavior.
- Detection logic, alert lifecycle, deduplication, case grouping, or report output.
- ML labels, feature generation, model training, evaluation, promotion gate, or governance wording.
- Response safety, simulation mode, protected-IP handling, or audit behavior.
- Test/release gates, runbooks, status docs, or known limitations.

If no PRD update is needed, record the reason in T17 of the ATDR T1-T20 change document.
