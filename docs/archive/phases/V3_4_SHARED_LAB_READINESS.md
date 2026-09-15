# ATDR v3.4 Shared-Lab Production-Readiness Foundation

ATDR remains a controlled lab prototype. v3.4 strengthens the shared-lab readiness foundation without claiming production readiness, changing startup commands, enabling automatic response, or enabling real firewall blocking.

## Source Evidence

| Area | Evidence |
| --- | --- |
| App startup and health | `atdr/app/main.py` |
| Runtime settings and safety validation | `atdr/app/core/config.py`, `atdr/scripts/config_doctor.py`, `atdr/scripts/production_readiness_doctor.py` |
| Database/session setup | `atdr/app/db/database.py` |
| Database model truth | `atdr/app/db/models.py` |
| PostgreSQL validation | `atdr/scripts/run_postgres_lab_validation.py`, `docs/V3_3_POSTGRESQL_SHARED_LAB_READINESS.md` |
| Backup/restore drill | `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/backup_demo.py`, `atdr/scripts/backup_postgres.py` |
| Dashboard performance profiling | `atdr/scripts/profile_dashboard_summary.py`, `atdr/scripts/performance_smoke.py`, `atdr/app/services/dashboard_service.py` |
| Real-source pilot validation | `atdr/scripts/run_v35_real_source_pilot_check.py`, `atdr/scripts/run_v30_real_source_pilot_validation.py`, `docs/V3_5_REAL_SOURCE_SYSLOG_PILOT.md`, `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md` |
| Operations readiness | `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/app/services/operation_run_service.py`, `atdr/app/services/source_service.py` |
| Release gate | `atdr/scripts/verify_release.py` |

## What v3.4 Adds

- A safe SQLite backup/restore drill that creates an ignored backup copy under `.tmp/atdr-backups` and verifies row counts from the copy.
- PostgreSQL validation output that clearly distinguishes local SQLite mode from PostgreSQL shared-lab validation.
- A read-only dashboard summary profiler for cold Overview/ingestion performance analysis.
- A v3.4 shared-lab readiness report that combines config safety, PostgreSQL readiness, backup/restore readiness, performance profile, real-source pilot status, and operations readiness.
- Config doctor warnings for default demo passwords, partial OIDC config, and missing TLS/API hardening in production-like settings.
- Source-pilot checklist evidence for real-device or lab-device validation. v3.5 distinguishes simulated/source-pipeline validation from real-device forwarding validation.

## Key Commands

Run the non-destructive shared-lab foundation report:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty
```

Run the same report and create an ignored SQLite backup copy:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --include-backup-copy --pretty
```

Run the backup/restore drill directly:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --dry-run --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_backup_restore_drill --pretty
```

Profile the dashboard summary path:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.profile_dashboard_summary --pretty
```

Validate optional PostgreSQL readiness when PostgreSQL is configured:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

## Real-Source Pilot Checklist

Before any production-like claim, validate one approved lab router/firewall source:

- source registered and enabled;
- logs received from the source;
- raw logs preserved and source-linked;
- normalized logs created and source-linked;
- parser profile selected and parser errors visible;
- source health updated;
- source-scoped detection run completed;
- alerts and cases trace back to source evidence;
- no automatic response actions created;
- response mode remains simulation.

## Status Meaning

Allowed v3.4 language:

- `shared_lab_foundation_ready`
- `shared_lab_foundation_ready_with_warnings`
- `shared_lab_foundation_blocked`
- `postgres_lab_validation_blocked_by_environment`

Disallowed language:

- `production_ready`
- `production_promoted`
- `automatic_response_enabled`
- `real_firewall_blocking_enabled`

## Remaining Production Blockers

- Real-device syslog forwarding must be validated over a sustained window.
- PostgreSQL must be validated on a separate shared-lab database host.
- Backup/restore must be drilled for the actual shared-lab database.
- TLS/reverse proxy and CORS exposure must be validated.
- External OIDC login is not implemented; only disabled groundwork exists.
- Observability is local/app-level; Prometheus/Grafana/ELK/cloud monitoring is future work.
- Real response enforcement is not implemented and remains future approved work only.
- ML remains SOC triage decision support and is not production-promoted.
