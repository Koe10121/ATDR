# ATDR Final Presentation Slide Content

## Slide 1: Title

**Title**

AI-Driven Log-Based Threat Detection and Response

**Key bullets**

- Senior project final defense
- AI-assisted SOC triage for firewall and syslog logs
- Controlled lab-scale validation

**Suggested visual**

ATDR dashboard Overview screenshot with the project title, student name,
advisor, program, and presentation date.

**Speaker notes**

"ATDR is an AI-assisted security operations prototype. It receives firewall
and syslog evidence, explains suspicious behavior, supports analyst
investigation, and records simulated analyst-approved responses. It is a
controlled lab-scale prototype, not a production autonomous defense system."

## Slide 2: Problem Background

**Key bullets**

- Firewalls generate more events than analysts can inspect manually.
- Rules are explainable but may miss unfamiliar behavior.
- Machine learning can assist triage but can also create false positives.
- Automatic blocking based on uncertain predictions can disrupt legitimate
  services.

**Suggested visual**

A simple funnel: many logs -> fewer alerts -> analyst-reviewed cases.

**Speaker notes**

"The project problem is not only detecting attacks. It is reducing analyst
workload without hiding evidence or giving an experimental model unsafe
authority."

## Slide 3: Project Objectives

**Key bullets**

- Preserve raw security evidence.
- Normalize logs for search and detection.
- Combine rule, anomaly, supervised, and hybrid signals.
- Explain why alerts are created.
- Support source health, cases, response approval, and audit.
- Validate the complete workflow conservatively.

**Suggested visual**

Six objective icons arranged around an analyst.

**Speaker notes**

"The system was designed around analyst decision support. Every detection
should lead back to evidence, and every response should remain under human
control."

## Slide 4: Scope And Limitations

**Key bullets**

**Implemented scope**

- Palo Alto-style logs, generic syslog, and raw fallback
- File import, replay, local syslog testing, and source scenarios
- React SOC dashboard and FastAPI APIs
- Simulated response with audit

**Outside current scope**

- Production certification
- Real firewall blocking
- Automatic response
- Completed real-device forwarding pilot

**Suggested visual**

Two-column "Included / Future Work" diagram.

**Speaker notes**

"The project makes a strict distinction between validated lab capability and
future production engineering. This prevents the final results from being
overstated."

## Slide 5: System Architecture

**Key bullets**

- Frontend: React + TypeScript + Vite
- Backend: FastAPI + Python
- Persistence: SQLAlchemy + Alembic + SQLite
- ML: scikit-learn
- Security: JWT + admin/analyst RBAC

**Suggested visual**

```text
Sources -> FastAPI ingestion -> Raw/Normalized DB
        -> Detection layers -> Alerts/Cases
        -> React analyst workflow
        -> Simulated response -> Audit
```

**Speaker notes**

"FastAPI fits the Python detection and ML pipeline. React provides the
analyst-facing workflow. The relational database is appropriate because
users, logs, alerts, evidence, labels, runs, responses, and audits have strong
relationships."

## Slide 6: Log Ingestion And Source Management

**Key bullets**

- Source registration and parser profile
- Raw evidence stored before parsing
- Source health: healthy, idle, warning, error, disabled
- Ingestion run history and source-level quality
- Safe replay and scenario tools

**Suggested visual**

Screenshot of the Log Sources panel and source detail drawer.

**Speaker notes**

"A parser failure does not destroy the evidence. The raw line remains
available, and the source records its parse quality and latest errors."

## Slide 7: Parser And Data Quality

**Key bullets**

- `palo_alto`: structured firewall fields
- `generic_syslog`: limited common syslog context
- `raw_fallback`: preserve unmatched evidence
- Missing fields and malformed rows are counted, not fatal
- Unknown application values are shown as data-quality context

**Suggested visual**

Three parser-profile boxes flowing into raw and normalized storage.

**Speaker notes**

"The parser is designed to fail safely. Structured fields may be limited, but
the original evidence remains available for investigation."

## Slide 8: Detection Layers

**Key bullets**

- Rules: explainable known behavior
- Behavior windows: repeated activity over time
- IsolationForest: unusual-pattern signal
- Supervised model: reviewed-label SOC triage
- Hybrid risk: combines evidence for prioritization

**Suggested visual**

Layered stack with the analyst above the final risk output.

**Speaker notes**

"No detection layer is treated as perfect. Rules explain known patterns,
anomaly scoring finds unusual events, and supervised ML supports
prioritization. The analyst sees their contributions."

## Slide 9: AI And Human Review Workflow

**Key bullets**

- Assisted weak labels remain marked as weak.
- Human-reviewed CSV import/export
- Active learning prioritizes useful review cases.
- Time split and independent holdouts reduce unrealistic evaluation.
- Promotion and readiness gates remain conservative.

**Suggested visual**

```text
Assisted labels -> Human review -> Candidate training
                -> Independent validation -> Governance decision
```

**Speaker notes**

"ATDR does not present weak-label metrics as production accuracy. Human review
and evaluation-source labeling are part of the ML workflow."

## Slide 10: Alert Explanation And Investigation

**Key bullets**

- Severity, risk score, and attack type
- Detection source and matched rules
- Behavior-window evidence
- Anomaly/supervised support when available
- ATT&CK-style context
- `Why flagged?` and recommended next checks

**Suggested visual**

Alert-detail screenshot focused on `Why flagged?` and linked logs.

**Speaker notes**

"An analyst can trace a finding from the alert to normalized fields and then
to the original raw evidence."

## Slide 11: Alert Deduplication And Cases

**Key bullets**

- Repeated findings update one alert.
- `occurrence_count` and `related_log_count` increase.
- First seen and last seen are preserved.
- Related alerts are grouped into lightweight cases.
- Raw logs are never deleted by deduplication.

**Suggested visual**

Ten repeated events -> one alert with occurrence 10 -> one case.

**Speaker notes**

"Deduplication reduces dashboard noise without discarding evidence. Case
grouping gives the analyst a larger behavioral view."

## Slide 12: Simulated Response And Safety

**Key bullets**

- Decision Support Only
- Response Automation Disabled
- Analyst confirmation and justification required
- Protected IPs are denied
- Allowed and denied attempts are audited
- Real firewall blocking disabled

**Suggested visual**

Response confirmation dialog beside an audit-log entry.

**Speaker notes**

"Even a high-confidence detection cannot block anything automatically. The
current response action is a recorded simulation, not a network change."

## Slide 13: Validation Journey

**Key bullets**

- Fixed safe scenarios
- Generated generalization variants
- Layered detection comparison
- End-to-end workflow validation
- Reviewed-label and benchmark evaluation
- Independent holdout and false-positive stabilization
- Frozen-candidate fresh blind validation
- Final controlled source acceptance

**Suggested visual**

Timeline from v0.7 to v2.1b.

**Speaker notes**

"The project did not rely on one final accuracy number. Each phase addressed a
different risk: behavior coverage, false positives, data leakage, calibration,
source handling, or response safety."

## Slide 14: Final Blind Holdout Results

**Key bullets**

- 700 rows, 7 sources, 16 scenario families
- Threat precision: 0.8906
- Threat recall: 0.9459
- Threat F1: 0.9174
- Benign-like FPR: 0.1303
- Suspicious recall: 0.8556
- Malicious recall: 0.9000
- Readiness v8: 22/22

**Suggested visual**

Metric table plus precision/recall/F1 bar chart.

**Speaker notes**

"The candidate was frozen before this holdout and was not tuned on blind
labels. Near-pattern overlap still exists and is documented as a limitation."

## Slide 15: Confidence And Controlled Source Results

**Key bullets**

**Confidence assessment**

- ECE: 0.0757
- Brier: 0.0751
- Max confidence gap: 0.1878
- No blind-label calibration fitting

**Controlled source**

- 28 raw logs
- 25 parse successes, 3 tracked failures
- 2 alerts, 2 cases
- Deduplication and protected-IP denial verified
- 0 automatic responses

**Suggested visual**

Calibration summary beside controlled-source pipeline results.

**Speaker notes**

"The source test validates system behavior, not only classification. It checks
parsing, health, evidence, cases, response denial, and audit."

## Slide 16: Final Dashboard Demonstration

**Key bullets**

- Source: `final-demo-firewall-live`
- 10 logs received, normalized, and parsed
- Healthy source
- 1 critical port-scan alert
- Run attack type: `port_scan (1)`
- 10 occurrences and related logs
- 1 case
- 0 response actions

**Suggested visual**

Four screenshots: source, alert, case, and response/audit.

**Speaker notes**

"The unknown-application note is expected because the scan sessions are
incomplete. It is data-quality context, not ingestion failure."

## Slide 17: Current Readiness

**Key bullets**

- Final Controlled Validation Candidate
- Candidate: `independent_fpr_stabilized`
- Decision Support Only
- Not Production Promoted
- Response Automation Disabled
- Real firewall blocking disabled

**Suggested visual**

Dashboard readiness badges.

**Speaker notes**

"This status means the engineering prototype passed its controlled academic
validation gates. It does not authorize production deployment."

## Slide 18: Limitations

**Key bullets**

- Synthetic and reviewed datasets cannot represent all real traffic.
- Real firewall/router forwarding pilot remains incomplete.
- SQLite is not validated for shared production scale.
- Local JWT/RBAC is not enterprise IAM.
- No high availability, retention certification, or disaster recovery.
- No real response connector.

**Suggested visual**

Risk/limitation matrix.

**Speaker notes**

"These are not hidden defects. They define the boundary between a successful
senior-project prototype and a production security platform."

## Slide 19: Future Work

**Key bullets**

1. Controlled real-device syslog pilot
2. Multi-day stability and drift observation
3. Independently reviewed real-source labels
4. PostgreSQL/shared-lab validation
5. TLS, secrets, backup, monitoring, and retention
6. Approved university OIDC integration
7. Vendor-approved response connector design with rollback

**Suggested visual**

Roadmap with lab pilot, shared deployment, and production hardening stages.

**Speaker notes**

"The next step should not be more tuning on the same synthetic data. It should
be controlled real-source validation while keeping response simulated."

## Slide 20: Conclusion

**Key bullets**

- Complete controlled SOC workflow demonstrated
- Explainable layered detection
- Strong threat-positive blind validation
- Human review and response safety preserved
- Honest readiness boundary

**Suggested visual**

End-to-end architecture with green checks and a clear production boundary.

**Speaker notes**

"ATDR demonstrates that rules, anomaly scoring, supervised learning, and human
review can work together in an explainable SOC triage system. The project is
complete for controlled academic demonstration, while production deployment
remains future work."

## Optional Backup Slides

- Technology stack details
- Database entity diagram
- IAM/RBAC matrix
- Confusion matrix and per-class metrics
- Calibration method
- Scenario catalog
- Repository hygiene and release gate
- Validation timeline with commands
