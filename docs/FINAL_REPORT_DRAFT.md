# ATDR Final Academic Report Draft

## Abstract

The AI-Driven Log-Based Threat Detection and Response system (ATDR) is a
controlled lab-scale cybersecurity prototype designed to assist security
analysts in monitoring firewall and syslog data. The system preserves raw log
evidence, normalizes investigation fields, tracks source health, applies
explainable rule-based detection, adds IsolationForest anomaly scoring and
supervised SOC triage support, generates deduplicated alerts, groups related
activity into lightweight cases, and records analyst-approved simulated
responses in an audit trail. ATDR was developed using FastAPI, React,
SQLAlchemy, Alembic, SQLite, and scikit-learn. Its final frozen candidate,
`independent_fpr_stabilized`, was evaluated on a fresh blind holdout of 700
rows from seven synthetic sources and sixteen scenario families without
threshold tuning on the holdout. The candidate achieved threat precision of
0.8906, threat recall of 0.9459, threat F1 of 0.9174, and a benign-like
false-positive rate of 0.1303. A separate controlled source workflow verified
raw evidence preservation, parser fallback, alert explanation, case grouping,
deduplication, protected-IP denial, and audit recording. The final readiness
decision is `final_controlled_validation_candidate`. This decision represents
strong controlled academic evidence, but it does not indicate production
promotion. Machine learning remains decision support only, response
automation is disabled, and real firewall blocking is not implemented.

## 1. Project Overview

Modern firewalls produce large volumes of traffic and security logs. These
records can contain evidence of scanning, repeated denied access, unusual
applications, data-transfer anomalies, command-and-control-like activity, and
policy violations. However, raw logs are difficult to review manually at
scale. Small organizations and university laboratories may not have a
commercial SIEM platform or a dedicated security operations center capable of
investigating every event.

ATDR was created to demonstrate an end-to-end, explainable, and
human-controlled SOC workflow. The system does not treat artificial
intelligence as an autonomous security authority. Instead, deterministic
rules, behavior-window features, anomaly scoring, supervised predictions, and
hybrid risk signals are presented as evidence for analyst review. The project
therefore prioritizes traceability and safe decision support over automatic
enforcement.

The final system includes source-aware ingestion, raw evidence preservation,
parser profiles, data-quality reporting, detection run history, alert
deduplication, case correlation, human labeling, AI Governance, role-based
access control, simulated response, and audit logging. A React dashboard
organizes these functions into Overview, Alerts, Investigation, AI Governance,
Response and Audit, and Admin workflows.

## 2. Problem Statement

Rule-based monitoring is valuable because its decisions are understandable,
but static rules cannot describe every unusual or evolving behavior. Machine
learning can identify patterns that are difficult to express as fixed rules,
but poorly governed ML may generate excessive false positives, hide class
imbalance, or appear more reliable than its labels justify. Automatic response
adds an additional safety risk because an incorrect classification could
interrupt legitimate services.

The central project problem was therefore not simply how to classify logs.
The challenge was to build a trustworthy workflow that could preserve source
evidence, detect meaningful patterns, explain why an alert was raised, support
human review, and prevent an experimental model from directly changing network
infrastructure. ATDR addresses this problem through layered detection,
explicit readiness gates, response simulation, protected-target controls, and
auditability.

## 3. Objectives

The first objective was to ingest Palo Alto-style firewall logs and
syslog-style inputs without losing the original evidence. The second was to
normalize useful investigation fields such as timestamps, source and
destination addresses, ports, actions, applications, zones, and risk
indicators. The third was to combine explainable detection rules with anomaly
and supervised signals. The fourth was to provide an analyst workflow for
triage, alert lifecycle updates, evidence review, case grouping, label review,
and model governance. The fifth was to simulate response approval safely while
ensuring that machine-learning output could not trigger an automatic action.
The final objective was to validate the complete system through repeatable
tests, controlled scenarios, independent holdouts, performance measurements,
and a release gate.

## 4. Scope

The implemented scope covers local file import, direct replay, controlled UDP
syslog testing, and synthetic source scenarios. The primary structured parser
targets Palo Alto log formats, while generic syslog and raw fallback profiles
preserve evidence when complete normalization is not possible. Detection
includes rule-based logic, behavior-window features, IsolationForest anomaly
scoring, supervised SOC triage, and hybrid risk scoring. The dashboard supports
source health, operations history, alerts, investigation, AI Governance,
response simulation, and audit review.

The project does not include real firewall enforcement, automatic response,
production-grade external IAM, high-availability collection, a completed
real-device forwarding pilot, or certified production accuracy. SQLite is used
for straightforward local setup. PostgreSQL remains a future shared-lab
deployment option rather than a requirement for the final academic
demonstration.

## 5. System Architecture

ATDR uses a layered client-server architecture. FastAPI exposes authenticated
REST APIs and coordinates ingestion, detection, alert, source, ML, response,
and audit services. React and TypeScript provide the primary SOC dashboard.
SQLAlchemy maps relational entities, and Alembic manages schema migrations.
SQLite stores local lab data. scikit-learn provides the IsolationForest anomaly
model and supervised candidate models.

The primary information flow is:

```text
Log source
  -> raw evidence storage
  -> parser profile
  -> normalized event
  -> rule, anomaly, and supervised signals
  -> hybrid risk and explanation
  -> alert and lightweight case
  -> analyst investigation
  -> simulated approved response
  -> audit record
```

This separation is important because each layer has a different level of
trust. Raw logs are the original evidence. Normalized logs are derived
representations. Detection outputs are analytical findings. Response records
are controlled analyst actions. The database links these layers so an alert
can be traced back to the evidence that caused it.

Authentication uses local JWT tokens with `admin` and `analyst` roles. Backend
route dependencies provide the authoritative permission checks, while the
frontend also hides or blocks unauthorized controls. External OIDC
configuration groundwork exists but remains disabled because no university
identity provider has been configured.

## 6. Data And Log Pipeline

Each ingestion path identifies a safe source when possible. A source contains
its name, type, parser profile, enabled state, recent activity, parse counters,
and health status. Existing imports remain compatible because source identity
is optional and can fall back to a local import source.

ATDR stores the raw line before attempting normalization. This design preserves
evidence even when a line is malformed or contains an unexpected field count.
The `palo_alto` profile extracts structured firewall fields. The
`generic_syslog` profile captures limited common syslog context. The
`raw_fallback` profile records the original evidence and a clear parse
limitation instead of raising an ingestion failure.

Source-level data quality includes raw and normalized counts, parse successes,
parse failures, unknown application rates, parser error examples, and alert
counts. A warning does not automatically mean a source failed. For example,
the final port-scan scenario intentionally uses incomplete or unknown
application values because rapidly denied scan sessions may not establish a
complete application identity.

## 7. Detection Methodology

### 7.1 Rule-Based Detection

Rules form the primary explainable layer. They identify evidence such as
scanning-like access across many ports, repeated denied or incomplete
connections, suspicious application characteristics, repeated service
attempts, flood-like behavior, possible exfiltration, policy violations, and
command-and-control-like patterns. Rule explanations are attached to alerts so
the analyst can understand which conditions were observed.

### 7.2 Behavior-Window Features

Individual firewall records may appear harmless when viewed alone. ATDR
therefore calculates behavior over time windows, including event counts,
unique destination addresses, unique destination ports, deny/drop/reset
counts, allow counts, deny ratios, repeated attempts, traffic direction, rare
services, rare applications, and scanning-like behavior scores. These
features help identify repeated activity and support both explainability and
supervised evaluation.

### 7.3 Anomaly Detection

IsolationForest is used as an assistive unsupervised detector. It scores how
unusual an event appears relative to the available feature distribution.
Because unusual activity is not automatically malicious, the anomaly score is
presented as supporting evidence. It cannot independently authorize response.

### 7.4 Supervised SOC Triage

The supervised workflow evolved through assisted weak labeling, human review,
active learning, class-support analysis, time-based validation, model
comparison, false-positive analysis, threshold profiles, confidence
assessment, and independent revalidation. Candidate families included
RandomForest, ExtraTrees, logistic regression, histogram gradient boosting,
and hierarchical threat-positive approaches.

The final frozen profile is named `independent_fpr_stabilized`. It was selected
for controlled SOC triage after earlier work identified an unacceptable
benign-like false-positive rate. The final profile preserves threat evidence
while routing ambiguous unresolved high-port service patterns toward analyst
review. It is a validation candidate, not an automatically activated
production model.

### 7.5 Hybrid Detection And Explainability

Hybrid scoring combines rule evidence, anomaly information, supervised triage,
and behavior-window context. The purpose is not to hide multiple signals
behind one score. Alert details expose the detection source, matched rule,
model/anomaly evidence where available, risk score, ATT&CK-style context,
behavior summary, and recommended analyst checks. The `Why flagged?` section
is the main explanation surface.

Repeated equivalent detections are deduplicated into an existing alert when
appropriate. The alert occurrence count, related-log count, first-seen time,
last-seen time, and evidence links are updated while raw logs remain intact.
Related alerts are grouped into lightweight cases using source, destination,
attack type, time, and repeated behavior.

## 8. Human Review And AI Governance

ATDR distinguishes assisted weak labels from human-reviewed labels. Review
files can be exported, completed by analysts, and imported through AI
Governance. Active-learning exports prioritize uncertainty, disagreement,
rare patterns, class gaps, and important threat boundaries. Quality checks
identify inconsistent labels or high-risk evidence that conflicts with a
benign label.

AI Governance reports label distributions, reviewed coverage, class support,
split strategy, model candidates, validation metrics, calibration status,
readiness checks, and safety warnings. Metrics are identified by evaluation
source. Weak-label, mixed-label, reviewed-label, benchmark, and blind-holdout
results are not treated as interchangeable. This prevents weak labels from
being presented as final production ground truth.

## 9. Response Simulation And Safety

Response remains simulated and requires an authorized user, explicit
confirmation, and a justification note. The interface shows the target and
action before recording the request. Protected internal and management
addresses are denied. Both accepted simulations and denied attempts are
written to the audit trail.

No model output can directly create a response action. Response Automation
Disabled and Decision Support Only are explicit system states. Real firewall
blocking is disabled because no vendor-approved enforcement connector,
rollback procedure, production allowlist governance, or network change
approval process has been implemented.

## 10. Dashboard Design

The React dashboard presents a SOC-oriented workflow. Overview summarizes
system status, controlled validation, operations health, sources, and severe
alerts. Alerts provides a triage table and detailed evidence. Investigation
offers search-first log exploration with source-aware filters. AI Governance
shows model status, validation evidence, label controls, and safety language.
Response and Audit presents simulated containment records and actor-attributed
history. Admin and Settings manages local users, source configuration, and
disabled external IAM status.

The dashboard uses progressive disclosure so high-level status appears first,
while technical details remain available in drawers or collapsible sections.
SafeSelect controls and browser regression tests protect against the earlier
dropdown overlay interaction defect.

## 11. Validation Journey

Validation was performed incrementally rather than relying on one final score.
Early phases validated fixed synthetic threat scenarios and negative controls.
Generalization phases generated safe variants to reduce dependence on one
sample. Layered tests compared rule, anomaly, supervised, and hybrid
contributions. End-to-end tests verified ingestion, detection, investigation,
response simulation, and audit behavior.

Later phases introduced benchmark adapters, human-reviewed labels, class and
temporal coverage analysis, false-positive reduction, calibration, separate
unseen holdouts, and independent revalidation. The v1.9b phase stabilized the
benign boundary without using source identity as a shortcut. For v2.0, the
candidate profile was frozen before a newly generated blind holdout was
evaluated. Thresholds were not tuned on this blind set.

The controlled source acceptance test separately validated source
registration, parser success and fallback, source health, deduplication, alert
explanation, case creation, simulated response, protected-IP denial, and audit
recording using temporary SQLite databases and safe synthetic data.

## 12. Final Results

The fresh blind holdout contained 700 rows from seven source identities and
sixteen scenario families. Exact overlap with earlier snapshots was zero.
Near-pattern overlap was 335 and is reported as a limitation rather than
hidden. The candidate achieved threat precision of 0.8906, threat recall of
0.9459, and threat F1 of 0.9174. The benign-like false-positive rate was
0.1303. Suspicious recall was 0.8556, malicious recall was 0.9000, macro F1
was 0.8680, and weighted F1 was 0.8753.

Raw-confidence assessment passed without fitting a calibrator on blind labels.
Expected calibration error was 0.0757, the threat-positive Brier score was
0.0751, and the maximum confidence-to-accuracy gap was 0.1878.

Readiness v8 passed 22 of 22 configured checks. The decision was
`final_controlled_validation_candidate`. This means the frozen candidate met
the controlled blind and source-validation requirements. It does not mean
that the model was production-promoted or activated.

The broader controlled source acceptance processed 28 raw logs, recorded 25
successful parses and three expected parse failures, created two alerts and
two cases, verified one deduplicated update, and produced zero automatic
responses. The final presentation scenario processes ten synthetic
port-scan-like logs, creates one critical explainable alert and one case,
reports the run-scoped attack type as `port_scan (1)`, links ten evidence
records, and creates no response action.

## 13. Discussion

The final results demonstrate strong threat-positive triage under the
controlled validation design. The project also shows why security ML should be
evaluated beyond accuracy. Earlier candidates detected threats but produced
too many benign false positives. The development process therefore emphasized
false-positive analysis, class-level recall, calibration, temporal support,
independent sources, and analyst review.

The distinction between suspicious and malicious remains more difficult than
the broader distinction between threat-positive and benign-like activity.
ATDR handles this limitation by preserving evidence and routing ambiguous
activity to analysts rather than forcing a high-impact automatic decision.

The hybrid design improved operational usefulness because deterministic rules
could explain known behaviors while anomaly and supervised signals provided
additional prioritization. The design also prevented one model family from
becoming a single point of trust.

## 14. Security And Ethical Considerations

ATDR is defensive-only. Safe synthetic traffic is committed to the repository,
while real logs, databases, model artifacts, environment secrets, review
exports, and generated validation reports remain ignored. Response actions
are simulations, and protected infrastructure targets cannot be selected for
containment. Model limitations and data provenance are shown in AI Governance.
These controls reduce the risk of overstating the system or causing
operational harm.

## 15. Limitations

The evaluation uses controlled synthetic, reviewed, benchmark, and blind
scenario data. This is useful engineering evidence but cannot reproduce all
real network behavior. Near-pattern overlap remains in the blind set. The
system has not completed a sustained real router/firewall forwarding pilot.
SQLite is suitable for local development but not validated as a shared,
high-volume production database. Local JWT roles are not enterprise identity
management. There is no high-availability collector, formal retention policy,
disaster-recovery test, independent penetration test, or vendor response
connector.

## 16. Future Work

The recommended next technical phase is the v3.0 production-readiness track
documented in `docs/V3_0_PRODUCTION_READINESS_TRACK.md`. One approved router
or firewall should forward logs to a test receiver while source health, parser
behavior, false positives, drift, and operational stability are monitored over
multiple days. A shared deployment should validate PostgreSQL, TLS, secret
management, backup, retention, and monitoring.
University OIDC could be completed after provider metadata, redirect URLs,
allowed domains, and role-mapping policies are approved.

ML work should focus on independently reviewed real-source labels and ongoing
drift/calibration monitoring rather than repeated tuning against the same
synthetic scenarios. A future response connector would require vendor support,
formal change approval, allowlist governance, dry-run previews, rollback, and
separate authorization. It should not be enabled merely because a model score
is high.

## 17. Conclusion

ATDR demonstrates a complete controlled SOC triage workflow from source-aware
ingestion through evidence-preserving parsing, layered detection, explainable
alerts, case correlation, human review, response simulation, and audit. The
project combines deterministic and machine-learning signals while keeping
analysts responsible for security decisions.

The final candidate achieved strong fresh blind threat-positive metrics and
passed the configured controlled readiness checks. The correct conclusion is
that ATDR is a Final Controlled Validation Candidate for lab-scale academic
demonstration. It remains Decision Support Only, is Not Production Promoted,
keeps Response Automation Disabled, and performs no real firewall blocking.

## Implementation Evidence

- `README.md`
- `docs/FINAL_SYSTEM_STATUS.md`
- `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/prd/PRD-ATDR.md`
- `atdr/app/`
- `atdr/scripts/`
- `atdr/tests/`
- `frontend/src/`
- `frontend/tests/`
