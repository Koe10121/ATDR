# Production Readiness Roadmap

ATDR is currently a strong local prototype with a realistic architecture. This roadmap describes what remains before real network deployment.

## Current Strengths

- FastAPI backend with JWT authentication and role-based access.
- Streamlit SOC dashboard with alert workflow, assignment, notes, timeline, and response center.
- Robust Palo Alto syslog CSV parser that preserves raw evidence.
- SQLAlchemy models and Alembic migrations.
- Rule-first detection with explainable scoring.
- IsolationForest anomaly scoring with model metadata, run history, and baseline-training controls.
- Simulated response actions by default.
- Audit trail for alert workflow, response actions, demo controls, and ML operations.
- Structured JSON logs and request IDs.
- Alert suppression rules, incident report export, and admin user management.
- Incident report export in JSON, CSV, HTML, and PDF formats.
- Computed SLA indicators for alert triage without changing alert status semantics.
- Watchlist indicators with audited create/disable actions and detection scoring.
- Suppression review status for governance of noisy benign activity.
- ML run comparison and baseline drift signals.
- Optional localhost-bound UDP syslog receiver for lab ingestion.

## Required Before Real Deployment

1. Move from SQLite to PostgreSQL.
2. Set `AUTO_CREATE_TABLES=false` and require Alembic migrations.
3. Replace demo credentials and set a strong `JWT_SECRET_KEY`.
4. Put FastAPI and Streamlit behind HTTPS and a reverse proxy.
5. Add backup/retention policy for raw logs, normalized logs, alerts, and audit records.
6. Add centralized log forwarding for ATDR application logs.
7. Add user management UI or integrate with an identity provider.
8. Add rate limits and brute-force protection for login.
9. Define alert retention and audit retention policies.
10. Validate detection thresholds with real MFU baseline traffic.
11. Review suppression rules and user accounts on a fixed schedule.

## ML Deployment Guidance

Do not train the anomaly model blindly on all available logs.

Recommended process:

1. Import a representative baseline window.
2. Run dataset profiling.
3. Use baseline-only training:
   - allow traffic only
   - app risk at or below 3
   - exclude unknown/incomplete apps
   - exclude existing anomaly-flagged logs
4. Score a broader validation window.
5. Review anomaly rate and top anomalous IPs/apps/ports.
6. Adjust contamination and filters if the model is too noisy or too quiet.
7. Record every model run and explain model limitations in reports.

## Safe Response Design

ATDR should remain in simulation mode until a formal firewall enforcement connector is designed and approved.

Before real blocking:

- require admin approval
- add allowlist protection for critical infrastructure IPs
- add dry-run preview
- add rollback plan
- add change ticket reference
- test with a non-production firewall first

## Suggested Next Engineering Milestones

1. PostgreSQL Docker Compose verification.
2. End-to-end Playwright dashboard smoke tests.
3. Browser smoke test execution in CI or on a lab workstation.
4. Password policy and session revocation.
5. Alert suppression review workflow and watchlist ownership.
6. Syslog receiver service for live ingestion.
7. Production deployment guide with network diagram.
