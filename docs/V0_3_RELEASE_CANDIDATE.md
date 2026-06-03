# ATDR v0.3 Release Candidate

ATDR v0.3 is a controlled lab-ready release candidate for small-office style firewall log monitoring. It is ready for teammate/advisor review and controlled lab validation, but it is not certified production software.

## Current Status

- Normal local workflow is preserved.
- FastAPI backend remains the API and service layer.
- React is the priority SOC dashboard.
- SQLite remains the default local database.
- Docker/PostgreSQL is optional future/lab deployment work.
- Real firewall blocking is not implemented.
- Automatic response is not enabled.
- ML remains SOC triage decision support only.

## What Works

- Palo Alto log import and raw evidence preservation.
- Normalized log explorer with filters, pagination, sorting, and detail views.
- Source management for file import, replay, syslog, router, firewall, and sample sources.
- Source health, parser profile visibility, source-level quality, and source-scoped detection.
- Parser profiles: `palo_alto`, `generic_syslog`, and `raw_fallback`.
- Rule-based detection, alert deduplication, lightweight case grouping, ATT&CK-style mapping, and "Why flagged?" explanations.
- IsolationForest anomaly scoring and supervised ML SOC triage decision support.
- AI Governance for label review, active learning, supervised model reports, readiness status, model registry visibility, and weak-label warnings.
- Reproducible supervised ML workflow with ignored dataset snapshots, feature-set metadata, candidate comparison, sanity/debug reports, threshold tuning, error analysis, and explicit activation/rollback commands.
- Supervised ML recovery workflow for dataset audits, weak-label diagnostics, clean registered baseline rebuilding, binary threat-positive experiments, SOC triage final recommendation, and recovery review samples. All outputs remain candidate-only and ignored from Git.
- Simulated block/unblock response with confirmation, justification, protected-IP denial, and audit logs.
- Ingestion run history, detection run history, Operations Health, and performance smoke checks.
- React dashboard with role-aware navigation and admin-only route protection.
- University workflow docs, PRD, IAM/RBAC matrix, requirement traceability, and completed T1-T20 example.

## Validated Scenarios

Safe synthetic scenario files live under `data/samples/scenarios/`.

| Scenario | What It Proves | Expected Result |
| --- | --- | --- |
| `normal_allowed_traffic` | Normal traffic baseline | No high/critical alerts. |
| `port_scan_like_traffic` | Suspicious scanning-like behavior | Source-scoped possible port-scan alert. |
| `repeated_dedup_traffic` | Alert deduplication | Repeated evidence updates occurrence count instead of creating endless duplicate alerts. |
| `generic_syslog_mixed` | Generic syslog fallback | Raw evidence preserved; limited parser warning visible. |
| `malformed_raw_fallback` | Parser resilience | Parser does not crash; raw evidence and parse failure details are preserved. |

Scenario output does not trigger response actions.

## AI Status

- Recommended AI mode: SOC triage decision support.
- Model status: analyst-review eligible / candidate, not production-promoted.
- Rule evidence remains primary.
- IsolationForest anomaly scoring is assistive.
- Supervised ML is decision support trained from mixed assisted and reviewed labels.
- Feature pipelines are versioned in supervised model metadata.
- Candidate model activation is explicit and does not equal production promotion.
- Threat-positive triage is useful for analyst review, but exact five-class classification is not production-promoted.
- Benign and needs_context exact classification remain weak.
- Suspicious vs malicious separation still needs more reviewed labels and real lab validation.
- Weak-label metrics must not be presented as production accuracy.

## Response Safety Status

- Response mode is simulation.
- Real firewall/device enforcement is not implemented.
- Simulated block/unblock is role-protected.
- Analyst approval, confirmation, and justification are required.
- Protected internal/management IP ranges are denied.
- Denied and successful response attempts are audited.
- ML output cannot trigger automatic containment.

## IAM/RBAC Status

- Local JWT authentication is implemented.
- Current roles: `admin` and `analyst`.
- Admin-only areas include user admin, demo controls, source create/update, log import, model training/scoring, and simulated response actions.
- Analysts can investigate alerts/logs, run detection, review labels, view AI Governance, and view audit evidence.
- No external OAuth, SSO, SAML, LDAP, or enterprise identity provider is implemented.
- Viewer/read-only role is future work.

See `docs/security/ATDR_IAM_RBAC_MATRIX.md`.

## Source Management Status

- Sources track name, type, parser profile, enabled status, last seen, log counters, parse success/failure, and latest error.
- Source health supports healthy, idle, warning, error, and disabled states.
- Source filters are available in investigation workflows.
- Replay and UDP syslog lab paths can attach logs to named sources.
- Existing imports still work without requiring a source selection.

## Performance Status

The v0.3 smoke checks remain usable on the current local SQLite DB, but the
largest local database can show intermittent Overview / ingestion-summary
slowdowns. This is a lab-readiness warning, not a data-loss issue. PostgreSQL
and another summary-query optimization pass should be evaluated before shared
larger lab use.

| Metric | Latest Result |
| --- | ---: |
| Raw logs | 145002 |
| Normalized logs | 145002 |
| Alerts | 3223 |
| Overview / ingestion summary | 5.8287s |
| ML Governance lightweight summary | 1.6863s |
| Alert list | 0.0325s |
| Case summary | 0.038s |
| Feature generation sample | 0.4796s |
| Warnings | Overview / ingestion summary exceeded local lab budget |

SQLite remains appropriate for local testing. PostgreSQL should be validated later for shared/larger lab use.

## What Remains Simulated

- Block/unblock actions.
- Firewall enforcement.
- Response connector behavior.
- Lab scenario traffic.

## Not Production-Ready Yet

- Real firewall/router syslog forwarding still needs controlled lab validation.
- Real response enforcement is not implemented.
- External IAM/SSO is not implemented.
- PostgreSQL/Docker lab deployment needs validation on a suitable host.
- More reviewed labels are needed for stronger supervised ML claims.
- Security hardening, retention policy, backups, and operational monitoring need production-level review.

## Recommended Next Phase

The best next phase is real router/firewall/syslog lab validation:

1. Register a real or simulated lab source.
2. Forward harmless syslog traffic to the ATDR lab receiver.
3. Verify source health, raw logs, normalized logs, parser warnings, detection, alerts, cases, and audit behavior.
4. Keep response simulated.
5. Capture results for advisor/team review.

Use `docs/LAB_RUNBOOK.md` for the operational steps.
