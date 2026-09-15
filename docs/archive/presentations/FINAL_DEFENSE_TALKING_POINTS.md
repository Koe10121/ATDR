# ATDR Final Defense Talking Points

## 1. Project Problem

Small organizations and university labs can collect large volumes of firewall
logs but may not have a full SOC platform or enough analysts to inspect every
record. Static rules alone can miss unusual behavior, while unconstrained ML
can create excessive false positives and unsafe automation.

ATDR addresses this problem with an explainable, human-controlled log
detection and response workflow.

## 2. System Objective

ATDR aims to:

- ingest firewall and syslog-style data;
- preserve original evidence;
- normalize fields for investigation;
- detect rule matches and unusual behavior;
- prioritize suspicious activity for analysts;
- explain why an alert was created;
- group related alerts into lightweight cases;
- record analyst-approved simulated responses and audit evidence.

The system is a controlled lab prototype, not production security software.

## 3. Technology Stack

- Backend: Python, FastAPI, Pydantic, SQLAlchemy, Alembic.
- Local database: SQLite.
- Frontend: React, TypeScript, Vite, TanStack Query/Table, Recharts.
- Authentication: local JWT with admin and analyst RBAC.
- ML: scikit-learn, including IsolationForest and supervised tree-based
  classifiers.
- Testing: Pytest, Ruff, Python compileall, Alembic checks, ESLint, TypeScript
  build, Playwright, scenario validation, performance smoke, and release gate.

SQLite keeps teammate setup simple. PostgreSQL is a future shared-lab option.
MongoDB is not required because ATDR's users, alerts, labels, sources, runs,
responses, and audit records are relational.

## 4. Architecture Summary

The main data path is:

```text
Log source
  -> raw log preservation
  -> parser profile
  -> normalized log
  -> rule/anomaly/supervised detection
  -> hybrid risk and explanation
  -> alert and case
  -> analyst investigation
  -> simulated approved response
  -> audit trail
```

FastAPI exposes authenticated APIs. React provides the SOC workflow. Database
migrations are managed by Alembic.

## 5. Log Ingestion Pipeline

ATDR supports:

- file import;
- direct replay;
- UDP syslog lab testing;
- safe synthetic source scenarios.

Each source can have a name, type, host/port, parser profile, enabled status,
health, counters, and recent run history.

The ingestion layer stores raw evidence before normalization. This means a
parser failure does not discard the original line.

## 6. Parser Operation

ATDR provides three parser profiles:

- `palo_alto`: extracts firewall fields such as timestamps, IPs, ports,
  actions, applications, zones, and risk indicators;
- `generic_syslog`: extracts limited common syslog context;
- `raw_fallback`: preserves unmatched evidence and records parse limitations.

Blank, malformed, incomplete, or unexpected lines are counted and exposed in
data-quality reporting instead of crashing ingestion.

## 7. Detection Layers

### Rule-Based Detection

Rules identify explainable patterns such as:

- scanning-like behavior;
- repeated denied access;
- suspicious applications;
- possible credential abuse;
- flood-like behavior;
- exfiltration suspicion;
- command-and-control-like beaconing.

### Anomaly Detection

IsolationForest provides assistive anomaly scoring. It identifies records that
are unusual relative to observed feature distributions. An anomaly is a
review signal, not proof of an attack.

### Supervised ML

Supervised classifiers learn from assisted and human-reviewed labels. They
provide triage predictions and confidence estimates.

The current validated candidate is `independent_fpr_stabilized`. It is not
automatically activated as a production model.

### Hybrid Detection

Hybrid scoring combines rule evidence, anomaly signals, supervised output, and
behavior-window features. This design is used because:

- rules provide explainability;
- anomaly scoring can reveal unfamiliar behavior;
- supervised learning can improve prioritization;
- no single layer is trusted as perfect ground truth.

## 8. Explainability

Alert details show:

- detection source;
- matched rule evidence;
- anomaly and supervised signals when available;
- behavior-window evidence;
- risk score and confidence;
- ATT&CK-style mapping;
- top evidence and recommended analyst checks.

This supports the question: "Why was this activity flagged?"

## 9. Human Review And AI Governance

ATDR supports:

- assisted weak labels;
- reviewed-label CSV import/export;
- active-learning review samples;
- label-quality checks;
- class/temporal support reporting;
- model comparison;
- conservative promotion gates;
- calibration and false-positive analysis.

Weak-label and mixed-label metrics are not presented as production accuracy.
The model remains SOC triage decision support.

## 10. Validation Journey

- v0.7: fixed synthetic detection scenarios.
- v0.8: generated variation/generalization checks.
- v0.9: rule, anomaly, supervised, and hybrid comparison.
- v1.0: ingestion-to-investigation and response/audit workflow.
- v1.1-v1.5: reliability, benchmark, reviewed-label, and readiness work.
- v1.6-v1.8: separate unseen holdout, external boundary improvement, and
  calibration.
- v1.9: independent revalidation and controlled source validation.
- v1.9b: identity-independent false-positive stabilization.
- v2.0: frozen candidate, fresh blind holdout, and final controlled
  acceptance.

The fresh blind set was not used for threshold tuning.

## 11. Final Metrics

Fresh blind holdout:

- rows: 700;
- sources: 7;
- scenarios: 16;
- exact prior overlap: 0;
- near-pattern overlap: 335, reported honestly;
- threat precision: 0.8906;
- threat recall: 0.9459;
- threat F1: 0.9174;
- benign-like false-positive rate: 0.1303;
- suspicious recall: 0.8556;
- malicious recall: 0.9000;
- macro F1: 0.8680;
- weighted F1: 0.8753.

Raw-confidence calibration passed without fitting on blind labels:

- ECE: 0.0757;
- Brier score: 0.0751;
- maximum confidence/accuracy gap: 0.1878.

Readiness v8 passed 22/22 checks with:

`final_controlled_validation_candidate`

This is not a production-promotion decision.

## 12. Response Safety

- ML cannot trigger a response.
- Response automation is disabled.
- Responses remain simulated.
- Authorized analyst confirmation is required.
- A justification note is required.
- Internal/management IP ranges are protected.
- Denied and successful attempts are audited.
- No real firewall connector is implemented.

## 13. What Is Complete

- local installation and startup;
- source-aware ingestion and replay;
- raw evidence preservation;
- parser profiles and data-quality visibility;
- layered detection;
- alert lifecycle, explanations, and deduplication;
- lightweight case correlation;
- AI Governance and human review;
- admin/analyst RBAC;
- simulated response safeguards;
- audit trail;
- controlled scenario, blind-holdout, performance, and release validation.

## 14. What Is Not Complete

- real router/firewall forwarding certification;
- production-grade IAM/SSO;
- TLS, secret management, backup, retention, and monitoring hardening;
- sustained soak and high-scale load testing;
- PostgreSQL/shared deployment validation;
- production incident/ticketing integration;
- real response connector and change approval;
- independent security assessment;
- larger independently reviewed real-world datasets.

## 15. Future Work

Recommended next steps:

1. Connect one controlled router/firewall syslog source.
2. Run a multi-day stability and drift observation.
3. Validate PostgreSQL for shared lab operation.
4. Add school OIDC only after provider details and role policy are approved.
5. Expand reviewed real-source labels and monitor false positives.
6. Design, but do not enable, a vendor-approved response connector with formal
   change control.

## 16. Final Defense Statement

> ATDR demonstrates that rule-based evidence, anomaly scoring, supervised
> learning, and human review can be combined into an explainable SOC triage
> workflow. The project prioritizes trustworthy evidence and analyst control
> over automatic enforcement. Its validated scope is controlled lab decision
> support, not production deployment.

