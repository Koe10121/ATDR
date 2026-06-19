# ATDR v3.0 Production-Readiness Gap Assessment

ATDR is a controlled academic SOC prototype. It has strong lab validation, but it is not production ready. This document records the remaining gaps before any production-like deployment claim.

## Source Evidence

| Area | Evidence |
| --- | --- |
| App startup, health, mounted routers | `atdr/app/main.py` |
| Runtime safety settings | `atdr/app/core/config.py` |
| Database models | `atdr/app/db/models.py` |
| Source management and health | `atdr/app/routers/sources.py`, `atdr/app/services/source_service.py` |
| Detection and run history | `atdr/app/services/detection_service.py`, `atdr/app/services/operation_run_service.py` |
| Response safety | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py` |
| Final controlled validation | `atdr/scripts/run_final_controlled_source_acceptance.py`, `atdr/app/benchmarks/readiness.py` |
| v3.0 readiness scripts | `atdr/scripts/production_readiness_doctor.py`, `atdr/scripts/run_v30_real_source_pilot_validation.py`, `atdr/scripts/run_postgres_lab_validation.py` |
| v3.4 readiness foundation | `atdr/scripts/run_v34_shared_lab_readiness.py`, `atdr/scripts/run_backup_restore_drill.py`, `atdr/scripts/profile_dashboard_summary.py`, `docs/V3_4_SHARED_LAB_READINESS.md` |

## Current Strengths

- Raw-first ingestion preserves evidence before normalization.
- Parser profiles support `palo_alto`, `generic_syslog`, and `raw_fallback`.
- Source management, source health, source quality, and source-scoped detection exist.
- Alert deduplication, case grouping, "Why flagged?", and ATT&CK-style context exist.
- AI Governance separates weak/reviewed labels, benchmarks, holdouts, and readiness gates.
- Response actions are simulated, analyst-approved, protected-IP aware, and audited.
- Normal local workflow remains FastAPI + React + SQLAlchemy/Alembic + SQLite.

## Production-Readiness Gaps

| Gap | Current State | Required Before Production-Like Claim |
| --- | --- | --- |
| Real device syslog pilot | Controlled replay/source validation only | Forward logs from a lab router/firewall for a sustained window and validate source health, parsing, detection, cases, and audit. |
| PostgreSQL lab validation | SQLite is normal local workflow; PostgreSQL is optional | Validate migrations, seed users, import/replay, detection, dashboard, performance, backup, and restore on PostgreSQL. |
| External IAM | Local JWT and OIDC placeholders only | Configure and test school OIDC/SSO provider, callback flow, allowed domains, role mapping, account disable policy, and audit. |
| Secrets | `.env.example` uses demo defaults for local use | Replace JWT and demo passwords for shared lab; use managed secrets for production-like deployment. |
| TLS/reverse proxy | Not verified by app-level tests | Validate TLS, HSTS, proxy headers, CORS, and network exposure controls. |
| Backup/retention | Docs and utility scripts exist | Validate backup, restore, audit retention, log retention, and data deletion policy. |
| Monitoring/alerting | Performance smoke and run history exist | Add operational metrics, dashboards, log aggregation, alerting, and failure notifications. |
| ML drift monitoring | Offline/read-only summaries exist | Monitor real-source distributions, false positives, calibration drift, label coverage, and source drift over time. |
| Real response connector | Not implemented by design | Requires formal approval, vendor API integration, allowlist, dry-run preview, rollback, and independent safety review. |

## v3.0 Readiness Status Language

Allowed statuses:

- `final_controlled_validation_candidate`
- `real_source_pilot_ready`
- `real_source_pilot_validated`
- `postgres_lab_validated`
- `production_readiness_candidate`
- `not_production_ready`

Disallowed for this phase:

- `production_ready`
- `production_promoted`
- `automatic_response_enabled`
- `real_firewall_blocking_enabled`

## Recommended Next Step

Run a controlled real-device syslog pilot using `docs/V3_0_REAL_DEVICE_SYSLOG_PILOT_PLAN.md`. Keep response simulation enabled and treat ML output as analyst decision support only.

For the shared-lab foundation step before real-device validation, run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v34_shared_lab_readiness --pretty
```

This command is conservative. It reports PostgreSQL status, backup/restore readiness, dashboard profiling, real-source pilot status, operations health, and config warnings, but it never marks ATDR production ready.
