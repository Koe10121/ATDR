# ATDR Final Status Summary For Supervisor

## Project Summary

ATDR is an AI-assisted, log-based threat detection and response prototype for
controlled SOC triage. It ingests firewall and syslog-style data, preserves
raw evidence, normalizes investigation fields, tracks log-source health,
applies layered detection, generates explainable alerts, groups related
activity into cases, supports human label review, and records
analyst-approved simulated response actions in an audit trail.

The implemented stack is FastAPI and Python for the backend, React and
TypeScript for the dashboard, SQLAlchemy and Alembic for relational
persistence, SQLite for normal local use, and scikit-learn for anomaly and
supervised ML evaluation.

## Current Readiness

- Status: `final_controlled_validation_candidate`
- Candidate/profile: `independent_fpr_stabilized`
- Readiness v8: 22/22 checks passed
- Decision Support Only
- Not Production Promoted
- Response Automation Disabled
- Model activation: none
- Real firewall blocking: disabled

This status means the engineering system is complete for controlled academic
demonstration. It is not a production certification.

## Validated Capabilities

- File, replay, safe source-scenario, and local syslog test ingestion.
- Raw evidence preservation and normalized log storage.
- Palo Alto, generic syslog, and raw fallback parser profiles.
- Source management, health, data quality, and run history.
- Explainable rule-based detection and behavior-window evidence.
- IsolationForest anomaly scoring.
- Supervised SOC triage and hybrid risk scoring.
- `Why flagged?` explanations and ATT&CK-style context.
- Alert lifecycle, deduplication, occurrence tracking, and lightweight cases.
- Human review CSV workflow, active learning, and AI Governance.
- Local JWT authentication and admin/analyst RBAC.
- Simulated response with confirmation, justification, protected-IP denial,
  and audit.
- React SOC dashboard, performance smoke, scenario tests, and release gate.

## Final Validation Results

The frozen candidate was evaluated on a fresh blind holdout containing 700
rows from seven sources and sixteen scenario families. Thresholds were not
tuned on this holdout.

| Metric | Result |
| --- | ---: |
| Threat precision | 0.8906 |
| Threat recall | 0.9459 |
| Threat F1 | 0.9174 |
| Benign-like false-positive rate | 0.1303 |
| Suspicious recall | 0.8556 |
| Malicious recall | 0.9000 |
| Macro F1 | 0.8680 |
| Weighted F1 | 0.8753 |

Confidence assessment passed without fitting a calibrator on blind labels:

- ECE: 0.0757
- Threat-positive Brier score: 0.0751
- Maximum confidence gap: 0.1878

The final controlled-source workflow preserved 28 raw logs, recorded 25 parse
successes and three tracked failures, created two alerts and two cases,
verified deduplication, verified alert explanations, denied a protected-IP
response, recorded audit evidence, and created zero automatic responses.

The final ten-log port-scan demonstration produces one critical explainable
alert, one case, ten related evidence records, a run-scoped attack type of
`port_scan (1)`, a healthy source, and zero response actions.

## Safety Position

ML output is advisory. It cannot directly create a response action. Response
requires an authorized user, confirmation, and justification. Protected
internal and management targets are denied and audited. All current response
records are simulations. No real firewall connector is implemented.

## Limitations

- No completed real router/firewall forwarding pilot.
- No long-duration production soak or high-availability collector.
- SQLite is the normal local database and has not been approved for shared
  production scale.
- Local JWT/RBAC is not enterprise IAM.
- External OIDC groundwork is disabled and incomplete.
- Controlled synthetic and reviewed validation does not establish production
  accuracy.
- Cases are lightweight correlation rather than full incident management.
- No real firewall enforcement or automated containment.

## Recommended Future Work

The next technical phase should be a controlled real-device syslog pilot with
one approved router or firewall. The pilot should measure parser quality,
source stability, false positives, drift, and analyst workload over multiple
days while keeping response simulated. Later work may validate PostgreSQL,
TLS, secret management, backup, retention, monitoring, university OIDC, and a
formally approved response connector with rollback.

## Supervisor Conclusion

ATDR demonstrates a complete and defensible senior-project workflow:
source-aware ingestion, evidence-preserving parsing, explainable layered
detection, AI-assisted triage, analyst investigation, safe simulated response,
and audit. The project is ready for final presentation and submission within
its stated controlled lab scope.
