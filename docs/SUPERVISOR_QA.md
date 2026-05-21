# Supervisor Q&A

## Why preserve raw logs?

Raw logs are the evidence. Parsed fields are useful for searching and detection, but raw lines let an analyst prove exactly what the firewall produced. Every normalized log links back to the raw record.

## Why use rules before ML?

Rules are explainable. A supervisor or analyst can understand why an alert was created: deny/drop action, app risk, outside-to-inside traffic, suspicious app characteristics, unknown traffic, port scanning, watchlist match, or anomaly support. ML is helpful, but it should not be the only reason for a cybersecurity response.

## What does IsolationForest prove?

It does not prove an attack. It identifies traffic that looks unusual compared with the training baseline. In ATDR, ML is assistive evidence used to prioritize investigation, not an autonomous decision maker.

## Why are response actions simulated?

Real blocking can interrupt legitimate users and campus services. ATDR records block/unblock actions and audit evidence, but it does not modify firewall devices by default. Real enforcement needs approvals, allowlists, rollback, and testing with a non-production firewall first.

## What makes this more than a script?

ATDR has a backend API, database schema, parser, detection service, ML governance, authentication, role checks, Streamlit dashboard, SOC workflow, response center, audit trail, migrations, Docker scaffolding, tests, and deployment documentation.

## What remains before production?

- PostgreSQL/Docker validation on a real host
- HTTPS and reverse proxy
- backup and retention jobs
- real syslog pilot from a lab firewall
- baseline tuning with reviewed normal traffic
- approved firewall integration for enforcement
- stronger identity integration such as campus SSO

## How is false-positive noise handled?

Analysts can mark alerts as false positive. Admins can create suppression rules, but those rules have review status and audit records so useful security signals are not silently hidden forever.

## How can the project be evaluated?

Use the demo evidence bundle, incident reports, audit logs, tests, and dashboard screenshots. The strongest acceptance checks are: logs import correctly, alerts are explainable, evidence is traceable, response is safe, audit attribution works, and ML is governed honestly.
