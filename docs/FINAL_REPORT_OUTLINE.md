# ATDR Final Academic Report Outline

## Working Title

**AI-Driven Log-Based Threat Detection and Response for Controlled SOC Triage**

## Front Matter

- Title page
- Approval page
- Declaration of originality
- Acknowledgements
- Abstract
- Table of contents
- List of figures
- List of tables
- List of abbreviations

## Abstract

Summarize the cybersecurity monitoring problem, the ATDR solution, the hybrid
detection approach, the controlled validation method, the final results, and
the safety boundary. State that ATDR is a controlled lab-scale prototype,
classified as a `final_controlled_validation_candidate`, and not a
production-promoted autonomous response system.

## Chapter 1: Introduction

### 1.1 Background

- Growth of firewall and network-security logs.
- Analyst workload and alert fatigue.
- Strengths and weaknesses of signature/rule detection.
- Potential and risks of machine-learning-assisted SOC triage.

### 1.2 Problem Statement

Small organizations and university labs may collect useful firewall evidence
without having a complete SOC platform or enough analysts to inspect every
event. Rule-only systems may miss unfamiliar behavior, while unconstrained ML
can create false positives and unsafe automation.

### 1.3 Project Aim

Design and validate an explainable, source-aware, AI-assisted log detection and
response prototype that preserves analyst control.

### 1.4 Objectives

1. Preserve and normalize firewall/syslog evidence.
2. Detect explainable suspicious behavior using layered detection.
3. Provide AI-assisted triage without autonomous enforcement.
4. Support alert investigation, case correlation, response simulation, and
   auditability.
5. Validate the workflow using controlled scenarios, reviewed labels,
   independent holdouts, and release gates.

### 1.5 Scope

- Palo Alto-style firewall logs and generic/raw syslog fallback.
- Local file import, replay, safe scenarios, and lab syslog support.
- Rule, anomaly, supervised, and hybrid detection layers.
- React SOC dashboard and FastAPI APIs.
- Simulated analyst-approved response only.

### 1.6 Limitations

- No production certification.
- No real firewall enforcement.
- No automatic response.
- No completed real-device forwarding pilot.
- SQLite remains the default local database.
- Synthetic and reviewed benchmark results do not prove production accuracy.

## Chapter 2: Literature And Technical Background

### 2.1 Security Information And Event Management

Discuss log collection, normalization, correlation, investigation, and audit
requirements.

### 2.2 Rule-Based Threat Detection

Explain deterministic detection, signatures, thresholds, behavior windows,
explainability, and maintenance costs.

### 2.3 Anomaly Detection

Explain unsupervised anomaly detection and the use of IsolationForest as an
assistive signal rather than proof of malicious intent.

### 2.4 Supervised Security Classification

Discuss class imbalance, weak labels, reviewed labels, temporal validation,
false positives, confidence calibration, and generalization.

### 2.5 Hybrid Detection

Explain why multiple imperfect signals can provide stronger analyst triage
when their contributions remain visible.

### 2.6 Human-In-The-Loop Security Operations

Discuss analyst review, active learning, approval, protected targets, and audit
trails.

### 2.7 Related Frameworks

- MITRE ATT&CK-style contextual mapping.
- Role-based access control.
- Secure software testing and release gates.

## Chapter 3: Requirements And Methodology

### 3.1 Functional Requirements

- Authentication and admin/analyst RBAC.
- Source-aware ingestion and parser profiles.
- Raw evidence preservation.
- Detection and risk scoring.
- Alert lifecycle, explanation, deduplication, and cases.
- AI Governance and label review.
- Simulated response and audit.

### 3.2 Non-Functional Requirements

- Safety
- Explainability
- Auditability
- Data integrity
- Lab-scale performance
- Maintainability
- Reproducibility
- Repository hygiene

### 3.3 Development Method

Describe iterative v0.x-v2.1 development, T1-T20 change documentation,
source-evidence rules, acceptance gates, and conservative model readiness
decisions.

### 3.4 Technology Selection

- Python and FastAPI for APIs and ML integration.
- React and TypeScript for the SOC dashboard.
- SQLAlchemy and Alembic for relational persistence and migrations.
- SQLite for easy local setup.
- scikit-learn for anomaly and supervised experiments.
- Pytest, Ruff, ESLint, TypeScript, Playwright, and custom release tooling.

## Chapter 4: System Architecture

### 4.1 High-Level Architecture

Present the pipeline:

```text
Source -> Raw Evidence -> Parser -> Normalized Log
       -> Rule / Anomaly / Supervised Signals
       -> Hybrid Risk -> Alert -> Case -> Analyst
       -> Simulated Response -> Audit Trail
```

### 4.2 Backend Architecture

Describe FastAPI routers, services, detection modules, ML modules, security
dependencies, and configuration.

### 4.3 Frontend Architecture

Describe React routes, TanStack Query/Table, reusable controls, SafeSelect,
progressive disclosure, and role-aware navigation.

### 4.4 Database Design

Describe users, raw logs, normalized logs, sources, ingestion runs, detection
runs, alerts, evidence, labels, response actions, and audit records.

### 4.5 Security Boundaries

Describe JWT authentication, admin/analyst authorization, protected-IP
controls, response simulation, and ignored sensitive/generated artifacts.

## Chapter 5: Data And Log Pipeline

### 5.1 Source Registration And Health

Explain source identity, parser profile, last-seen tracking, counters, and
healthy/idle/warning/error/disabled states.

### 5.2 Raw Evidence Preservation

Explain why raw input is stored before parsing and how normalized records
retain traceability.

### 5.3 Parser Profiles

- `palo_alto`
- `generic_syslog`
- `raw_fallback`

### 5.4 Data Quality

Discuss parse success/failure, missing fields, unknown applications,
duplicates, parser examples, and source-level warnings.

### 5.5 Replay And Scenario Inputs

Explain dry-run replay, direct replay, local syslog testing, and safe synthetic
scenario samples.

## Chapter 6: Detection Methodology

### 6.1 Rule Layer

Document scanning, repeated deny, brute-force-like behavior, flood behavior,
policy violations, suspicious applications, exfiltration suspicion, and
command-and-control-like behavior.

### 6.2 Behavior-Window Features

Discuss event counts, unique destinations/ports, deny ratios, repeated
attempts, rare services/apps, directionality, and scanning-like scores.

### 6.3 IsolationForest Anomaly Layer

Describe training, feature preprocessing, anomaly score interpretation, and
limitations.

### 6.4 Supervised SOC Triage Layer

Describe assisted labels, human review, active learning, model comparison,
class weighting, temporal validation, threshold profiles, calibration, and
candidate locking.

### 6.5 Hybrid Risk And Explainability

Describe signal combination, `Why flagged?`, rule/model evidence, ATT&CK-style
mapping, confidence, and recommended analyst checks.

### 6.6 Alert Deduplication And Case Correlation

Explain occurrence counts, related logs, first/last seen, grouped patterns,
and preservation of raw evidence.

## Chapter 7: Response And Safety Design

### 7.1 Alert Lifecycle

New, Investigating, Needs More Context, Contained, Resolved, and False
Positive.

### 7.2 Simulated Response

Explain confirmation, justification, authorized roles, target preview, and
recorded simulation.

### 7.3 Protected-IP Safeguards

Explain internal/management allowlists and denied-attempt audit behavior.

### 7.4 Automation Boundary

State that ML cannot directly trigger response, response automation is
disabled, and no real firewall connector is implemented.

## Chapter 8: Dashboard Design

### 8.1 Overview And Operations Health

### 8.2 Alert Triage And `Why Flagged?`

### 8.3 Investigation / Log Explorer

### 8.4 Source Detail And Data Quality

### 8.5 AI Governance

### 8.6 Response And Audit

### 8.7 Admin, Settings, And IAM Groundwork

## Chapter 9: Validation Methodology

### 9.1 Unit, API, And UI Testing

### 9.2 Fixed Scenario Validation

### 9.3 Generalization Variants

### 9.4 Layered Detection Comparison

### 9.5 End-To-End Workflow Validation

### 9.6 Benchmark And Reviewed-Label Evaluation

### 9.7 Independent And Fresh Blind Holdouts

### 9.8 Controlled Source Acceptance

### 9.9 Performance Smoke And Release Gate

Clarify data separation and state that the fresh blind set was not used for
threshold tuning.

## Chapter 10: Results

### 10.1 Fresh Blind Holdout

| Metric | Result |
| --- | ---: |
| Rows | 700 |
| Sources | 7 |
| Scenario families | 16 |
| Threat precision | 0.8906 |
| Threat recall | 0.9459 |
| Threat F1 | 0.9174 |
| Benign-like false-positive rate | 0.1303 |
| Suspicious recall | 0.8556 |
| Malicious recall | 0.9000 |
| Macro F1 | 0.8680 |
| Weighted F1 | 0.8753 |

### 10.2 Confidence Assessment

- ECE: 0.0757
- Threat-positive Brier score: 0.0751
- Maximum confidence gap: 0.1878
- Blind labels used to fit calibration: no

### 10.3 Controlled Source Acceptance

- 28 raw logs
- 25 parse successes
- 3 tracked parse failures
- 2 alerts
- 2 cases
- Deduplication, explanation, protected-IP denial, and audit verified
- 0 automatic responses

### 10.4 Final Demonstration Scenario

- 10 raw/normalized/parsed logs
- Healthy source
- 1 critical port-scan alert
- `port_scan (1)` run-scoped attack type
- 1 case
- 10 occurrences and 10 related logs
- 0 response actions

### 10.5 Performance And Release Verification

Report the final measured local timings and complete automated gate results
from the presentation-day verification.

## Chapter 11: Discussion

### 11.1 Interpretation Of Detection Results

### 11.2 False-Positive Reduction Journey

### 11.3 Suspicious/Malicious Boundary

### 11.4 Value Of Hybrid Evidence

### 11.5 Why Human Approval Remains Necessary

### 11.6 Threats To Validity

Discuss synthetic data, near-pattern overlap, reviewed-label limitations,
source diversity, hardware absence, and local SQLite constraints.

## Chapter 12: Security, Ethics, And Safety

- Defensive-only scope.
- Data privacy and repository hygiene.
- No autonomous containment.
- No real firewall changes.
- Honest model claims.
- Protected infrastructure safeguards.
- Auditability and accountability.

## Chapter 13: Limitations And Future Work

### 13.1 Current Limitations

### 13.2 Controlled Real-Device Pilot

### 13.3 Shared PostgreSQL Deployment

### 13.4 Production IAM, TLS, Secrets, Backup, And Monitoring

### 13.5 Larger Independently Reviewed Real-Source Dataset

### 13.6 Long-Duration Drift And Soak Testing

### 13.7 Future Vendor-Approved Response Connector

## Chapter 14: Conclusion

Conclude that ATDR demonstrates a complete controlled SOC workflow with
explainable layered detection and analyst-controlled response. Restate that
the result is a final controlled validation candidate, not production
deployment approval.

## References

Add references for:

- SIEM and SOC operations
- Firewall log analysis
- IsolationForest
- Supervised classification and calibration
- MITRE ATT&CK
- FastAPI, React, SQLAlchemy, Alembic, and scikit-learn documentation
- Human-in-the-loop and trustworthy AI security research

Use the university-required citation style consistently.

## Appendices

- Appendix A: Installation and startup
- Appendix B: API and route summary
- Appendix C: Database entity summary
- Appendix D: Scenario definitions
- Appendix E: Validation commands
- Appendix F: Final metrics and confusion matrices
- Appendix G: Screenshots and demo evidence
- Appendix H: IAM/RBAC matrix
- Appendix I: Requirement traceability
- Appendix J: Release and acceptance checklists

## Repository Evidence

- `README.md`
- `docs/FINAL_SYSTEM_STATUS.md`
- `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`
- `docs/FINAL_DEMO_RUNBOOK.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/prd/PRD-ATDR.md`
- `atdr/app/`
- `atdr/tests/`
- `frontend/src/`
- `frontend/tests/`
