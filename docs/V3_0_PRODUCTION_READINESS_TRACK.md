# ATDR v3.0 Production-Readiness Track

v3.0 moves beyond the final controlled academic prototype into production-readiness planning. It does not make ATDR production ready.

## Current Status

- Final controlled validation candidate: complete.
- Real-device/source pilot: planned.
- PostgreSQL lab validation: planned.
- Observability plan: documented.
- Real-source ML monitoring plan: documented.
- Response automation: disabled.
- Real firewall blocking: disabled.
- Model production promotion: disabled.

## Readiness Gate v9

Implementation: `atdr/app/benchmarks/readiness.py`

Allowed decisions:

- `final_controlled_validation_candidate`
- `real_source_pilot_ready`
- `real_source_pilot_validated`
- `postgres_lab_validated`
- `production_readiness_candidate`
- `not_production_ready`

The gate always returns:

```text
production_ready=false
production_promoted=false
model_activated=false
response_automation_allowed=false
real_firewall_blocking_enabled=false
```

## New Commands

Production-readiness doctor:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.production_readiness_doctor --pretty
```

Read-only real-source pilot validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v30_real_source_pilot_validation --source-name lab-firewall-real-1 --expected-min-logs 100 --pretty
```

PostgreSQL lab validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

Read-only ML monitoring:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_real_source_ml_monitoring --pretty
```

## Recommended v3.0 Sequence

1. Keep normal local SQLite workflow for development.
2. Run production-readiness doctor and fix shared-lab blockers.
3. Register a real/lab source.
4. Forward syslog from real/lab router/firewall.
5. Run source-scoped detection.
6. Run real-source pilot validator.
7. Review dashboard source health, alerts, cases, and audit.
8. Validate PostgreSQL lab deployment on a Docker/PostgreSQL-capable host.
9. Collect reviewed labels from real-source rows.
10. Re-evaluate ML only as decision support.

## Production Claim Policy

Do not claim production readiness until real-device forwarding, PostgreSQL/shared deployment, external IAM, TLS/secrets, backup/retention, monitoring, security review, and response connector governance are validated.
