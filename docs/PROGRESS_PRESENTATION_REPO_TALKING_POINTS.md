# ATDR Repo Talking Points

## What To Show In GitHub Or VS Code

- `README.md`: project overview, safety scope, startup commands, current lab snapshot.
- `atdr/app/main.py`: FastAPI application entry point.
- `atdr/app/routers/`: backend API routers for logs, alerts, detection, ML, response, audit, sources, and admin flows.
- `atdr/app/db/models.py`: relational entities for users, logs, alerts, labels, sources, runs, responses, and audit.
- `atdr/app/parsing/`: parser behavior and raw evidence preservation.
- `atdr/app/detection/`: rule/anomaly/supervised detection entry points.
- `atdr/app/ml/`: feature generation, supervised training, and governance helpers.
- `frontend/src/pages/`: React dashboard pages.
- `data/samples/scenarios/`: safe synthetic scenario logs.
- `docs/`: runbooks, PRD, workflow, IAM/RBAC matrix, traceability, final demo docs, and progress presentation docs.

## Why The Stack Was Chosen

- FastAPI: Python-native API layer for parsing, detection, ML, and security workflows.
- React: professional dashboard with SOC workflow, drawers, tables, filters, and role-aware pages.
- SQLAlchemy/Alembic: relational model with migrations for users, logs, alerts, labels, responses, sources, and audit history.
- SQLite: simple default local database for student/team setup.
- Python ML stack: supports IsolationForest, supervised classifiers, feature engineering, and validation scripts.
- Playwright/tests/release gate: repeatable verification before demo or release.

## What NewSystem Means In This Repo

`NewSystem/` is a university template/reference. ATDR adapts useful process and UI ideas from it, such as formal navigation, permission thinking, IAM/RBAC documentation, and workflow traceability.

ATDR does not migrate to NewSystem's Node/Vue/MongoDB stack. The active runtime remains FastAPI + React + SQLAlchemy/Alembic + Python ML.

## Safety Talking Points

- ML outputs do not trigger automatic response.
- Response actions are simulated and analyst-approved.
- Real firewall blocking is disabled.
- Raw evidence is preserved for auditability.
- Generated reports, real logs, databases, model artifacts, review CSVs, and `.env` files stay out of Git.

## Recommended Next Phase

The next strong development phase is controlled real-source validation:

- connect a real or virtual firewall/router syslog source;
- verify source health and parser quality;
- validate alerts and cases from live forwarded logs;
- keep response simulation-only;
- document limitations and evidence.

