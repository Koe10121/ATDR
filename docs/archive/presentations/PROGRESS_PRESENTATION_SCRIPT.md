# ATDR Progress Presentation Script

## Opening

My project is MFU AI-Driven Log-Based Threat Detection and Response, or ATDR. The problem is that firewall logs contain useful security evidence, but manually reviewing large log files is slow and easy to miss. ATDR turns those logs into a SOC-style workflow where an analyst can ingest logs, see alerts, investigate evidence, review AI signals, and record simulated response decisions.

This is a controlled lab prototype. It does not perform real firewall blocking, it does not enable automatic response, and the AI is decision support only.

## What Data The System Uses

The system works with firewall/syslog-style data, especially Palo Alto-style logs. When a log is imported or replayed, ATDR stores the raw line first. This matters because the raw log is the original evidence. Then the parser normalizes useful investigation fields such as timestamp, source IP, destination IP, ports, action, application, zones, bytes, and protocol.

If the line is not a complete Palo Alto record, the parser does not crash. Generic syslog and raw fallback profiles preserve the raw evidence and mark parse quality clearly.

## Technology Stack

The backend is FastAPI because it gives a clean Python API layer and works well with security, detection, and ML code.

The database layer uses SQLAlchemy and Alembic. SQLite is the default local database because it is simple for a student project and easy for teammates to run. PostgreSQL is planned for shared-lab validation, but it is not required for normal testing.

The frontend is React with Vite. React is the main dashboard path because it supports a richer SOC workflow than the older prototype UI.

The AI and detection layer uses Python. Rule-based detection provides explainable security logic. IsolationForest provides unsupervised anomaly scoring. Supervised ML provides analyst decision support after labels are reviewed. A hybrid score combines rule, anomaly, and ML signals while keeping the analyst in control.

## What Is Complete

ATDR can import logs, replay logs, track log sources, show source health, parse logs, run detection, deduplicate repeated alerts, create cases, show "Why flagged?" evidence, support AI Governance, import reviewed labels, train/evaluate supervised models, simulate response actions, and audit actions.

The dashboard now includes Overview, Alerts, Investigation, AI Governance, Response & Audit, and Admin areas. Safety badges show Decision Support Only, Response Automation Disabled, Not Production Promoted, and Simulation Mode.

## Validation Status

The system has automated tests, release gate checks, safe source scenarios, replay dry-runs, performance smoke checks, and final controlled scenario validation.

The final demo scenario uses safe synthetic port-scan-like traffic. It receives 10 logs, parses 10 logs, creates one critical possible port-scan alert, groups the related evidence, and creates no automatic response action.

## Safety Limitations

The system is not production-certified. It does not claim production model accuracy. Real firewall blocking is disabled. Response actions are simulated and require analyst approval. External school-email IAM is planned through OIDC groundwork, but full external login is not enabled yet.

## Dashboard Walkthrough

First, I will show the Overview page for system health, log counts, source status, and safety posture.

Next, I will show Alerts, where the analyst can triage severity, risk score, attack type, source, destination, evidence count, status, and related case context.

Then I will show Investigation, where the analyst can search logs, filter by IP/action/app/source, and inspect raw evidence.

In AI Governance, I will explain that the model is analyst-review eligible but not production-promoted. The key point is that AI helps prioritize review; it does not automatically respond.

Finally, I will show Response & Audit. Any block/unblock action is simulated, requires confirmation and a note, and is recorded in audit logs.

## Closing

The main achievement is that ATDR connects log ingestion, explainable detection, AI-assisted triage, human review, simulated response, and audit evidence into one defensive workflow. The next phase is controlled real-source validation with a real or virtual firewall/router forwarding syslog into ATDR.

