# ATDR v3.1 PostgreSQL Performance Validation Plan

PostgreSQL is optional for local development, but it is the recommended next production-readiness validation path for larger shared-lab datasets.

## Source Evidence

- Configuration: `atdr/app/core/config.py`
- Database setup: `atdr/app/db/database.py`
- Migrations: `migrations/versions/`
- PostgreSQL validator: `atdr/scripts/run_postgres_lab_validation.py`
- Performance smoke: `atdr/scripts/performance_smoke.py`
- Lab docs: `docs/LAB_RUNBOOK.md`, `docs/DEPLOYMENT_GUIDE.md`

## Validation Goals

The PostgreSQL lab should prove that ATDR can run the same workflow as SQLite while improving confidence in larger-dataset performance:

- Alembic migrations apply cleanly.
- Seed users are idempotent.
- Source registration works.
- Sample import/replay works.
- Detection creates source-linked alerts and cases.
- Overview summary is fast.
- ML Governance lightweight summary is fast.
- Alert list and case summary stay fast.
- Release gate passes.
- Response mode remains simulated.

## Suggested Flow

Use this only on a PostgreSQL/Docker-capable host:

```powershell
Copy-Item .env.lab.example .env
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
.\.venv\Scripts\python.exe -m atdr.scripts.seed_users
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --send-to direct --source-name pg-lab-firewall --source-type firewall --limit 100 --rate 0 --run-detection --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release --pretty
```

If run while SQLite is configured, `run_postgres_lab_validation` should report `postgres_lab_validation_blocked_by_environment`. That is expected and non-destructive.

## Metrics To Record

Capture:

- total raw logs
- normalized logs
- alert count
- Overview uncached summary time
- Overview cached summary time
- ML Governance lightweight summary time
- alert list time
- case summary time
- ingestion/detection run-history query time
- release gate result

## Acceptance Target

- Overview cached under `0.05s`.
- Overview uncached under `2s` for the lab dataset.
- ML Governance lightweight under `2s`.
- Alert list and case summary under `1s`.
- No response automation and no real firewall blocking.

## Remaining Production Gaps

This PostgreSQL validation is still not production certification. Production-like deployment would still need external IAM, TLS/reverse proxy hardening, backup/restore drills, monitoring, retention policy, real-device syslog validation, and security review.

