# ATDR Progress Presentation Status

## Current Status

ATDR is a controlled lab prototype for AI-assisted log-based threat detection and response. It is ready to demonstrate the defensive SOC workflow in a local lab setting, but it is not production software.

The current system can:

- import and replay firewall/syslog-style logs;
- preserve raw evidence for every ingested row;
- parse Palo Alto-style logs plus generic syslog/raw fallback samples;
- manage log sources and source health;
- run rule-based detection and grouped alert deduplication;
- create SOC-style alerts and lightweight cases;
- explain alerts with "Why flagged?" evidence;
- provide IsolationForest anomaly scoring and supervised ML decision support;
- support human label review, active learning, and AI Governance;
- simulate analyst-approved response actions;
- audit important security and workflow actions;
- run safe source scenarios and release verification checks.

## Completed Work

- FastAPI backend with JWT authentication, admin/analyst RBAC, SQLAlchemy, Alembic, and SQLite local workflow.
- React SOC dashboard as the primary dashboard.
- Source management, source health, parser profiles, replay mode, scenario runner, run history, alert deduplication, and case grouping.
- AI Governance with reviewed labels, weak-label warnings, model readiness gates, and conservative model status.
- Response safety with simulation mode, justification notes, protected IP checks, and audit logging.
- University workflow alignment docs, PRD, requirement traceability, IAM/RBAC matrix, and T1-T20 change template.
- Team quickstart and lab runbooks for Windows-based setup.

## Current Limitations

- Real firewall/router forwarding has not been fully validated on physical hardware.
- Real firewall blocking is not implemented.
- Response automation is disabled.
- ML is decision support only and not production-promoted.
- SQLite is suitable for local/lab work; PostgreSQL remains optional future shared-lab work.
- External school-email IAM groundwork exists, but full OAuth/OIDC login is not enabled yet.

## Demo Flow

1. Open GitHub/repo and explain the project structure, safety rules, and technology stack.
2. Start backend and frontend using the normal local commands.
3. Show the React dashboard Overview and system safety badges.
4. Run or describe the final controlled source scenario:

   ```powershell
   .\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty
   ```

5. Show the source health, parsed logs, generated alert, related case, and "Why flagged?" evidence.
6. Show AI Governance as decision support, not production accuracy.
7. Show Response & Audit with simulated analyst-approved action behavior.

Expected final scenario result:

- 10 logs received and normalized;
- 1 critical possible port-scan alert;
- 1 case;
- occurrence count and related logs linked;
- 0 automatic response actions;
- real firewall blocking disabled.

## Next Plan

- Controlled real firewall/router syslog validation when hardware or a virtual firewall is available.
- PostgreSQL/shared-lab validation if multiple users need the same database.
- External school-email OIDC login after provider details are confirmed.
- More analyst-reviewed labels and independent validation for ML confidence.
- Production hardening only after safety, IAM, deployment, and response connector reviews.

