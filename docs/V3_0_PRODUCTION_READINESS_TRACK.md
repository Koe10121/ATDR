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

## v3.1 Performance Stabilization

The v3.1 follow-up documents large-SQLite performance behavior and the PostgreSQL performance validation path:

- `docs/V3_1_PERFORMANCE_STABILIZATION_PLAN.md`
- `docs/V3_1_POSTGRESQL_PERFORMANCE_VALIDATION_PLAN.md`

Run performance smoke after large imports:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
```

## v3.2 No-Hardware Source Pilot

When no real firewall/router is available, run the safe no-hardware pilot:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --pretty
```

This validates the source pipeline with safe synthetic logs only. It reports `real_device_forwarding_validated=false` and `production_ready=false`.

See `docs/V3_2_NO_HARDWARE_SOURCE_PILOT.md`.

## v3.3 PostgreSQL and Shared Lab Readiness

v3.3 prepares the optional PostgreSQL/shared-lab path while keeping SQLite as the normal local workflow.

Run the read-only portability audit:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.database_portability_audit --pretty
```

Run the PostgreSQL validator:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

On SQLite, the validator should report `postgres_lab_validation_blocked_by_environment`. That is expected and non-destructive. On a Docker/PostgreSQL-capable host, use:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --include-smoke --include-sample-ingest --pretty
```

See:

- `docs/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md`
- `docs/V3_3_BACKUP_RESTORE_AND_RETENTION_PLAN.md`
- `docs/V3_3_DOCKER_POSTGRES_LAB_RUNBOOK.md`

## Production Claim Policy

Do not claim production readiness until real-device forwarding, PostgreSQL/shared deployment, external IAM, TLS/secrets, backup/retention, monitoring, security review, and response connector governance are validated.
