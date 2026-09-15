# T1-T20 Change Document: v3.10 Configuration Safety Hardening

## T1. Change Title

v3.10 Local and shared-lab configuration safety hardening.

## T2. Requirement

Make ATDR easier and safer to run across normal local SQLite, optional PostgreSQL lab, and teammate laptops without changing startup commands or enabling production-like behavior.

## T3. Source Evidence

| Evidence | Source |
| --- | --- |
| Settings and validation | `atdr/app/core/config.py` |
| Database connection handling | `atdr/app/db/database.py`, `atdr/app/main.py` |
| Config doctor | `atdr/scripts/config_doctor.py` |
| Dev environment checker | `atdr/scripts/check_dev_environment.py` |
| Local SQLite helper | `atdr/scripts/use_local_sqlite_config.py` |
| Environment templates | `.env.example`, `.env.lab.example` |
| Team setup docs | `docs/QUICKSTART_FOR_TEAM.md`, `docs/LAB_RUNBOOK.md`, `README.md` |

## T4. Current Behavior

Before this pass, a local `.env` that pointed to PostgreSQL host `postgres` could make login fail with a confusing database traceback when Docker/PostgreSQL was not running.

## T5. Impacted Areas / Agents

Backend/API, Dev Onboarding, Release/Ops, Security/Config Safety, Documentation, and QA.

## T6. Scope

In scope:

- Config doctor detection for Docker-style PostgreSQL host `postgres`.
- Clearer local SQLite recommendation.
- Secret-redacted teammate environment checker output.
- Clean `503 Database unavailable` response for DB operational failures.
- Dry-run-first helper for switching `.env` back to local SQLite values.
- Docs and tests.

Out of scope:

- Database schema changes.
- Database reset or migration.
- Docker/PostgreSQL requirement for normal local use.
- Real firewall blocking.
- Automatic response.
- ML model activation or promotion.

## T7. Functional Requirements

- `config_doctor` should identify local SQLite as the normal teammate/laptop profile.
- `config_doctor` should warn when host `postgres` is used outside Docker.
- `check_dev_environment` should not expose DB passwords.
- Backend DB operational failures should return a clear 503 response.
- The local SQLite helper should be dry-run by default and write only with `--write`.
- The helper should back up `.env` under ignored `.tmp/env-backups/` before writing.

## T8. Acceptance Criteria

- Wrong Docker-style PostgreSQL config is diagnosed clearly.
- Normal SQLite config is accepted.
- DB unavailable response mentions `DATABASE_URL` but not secrets.
- No `.env` file is modified during tests or dry-runs.
- Assistant safety defaults remain unchanged.
- Full verification passes.

## T9. API Contract

No new public API endpoints. Existing API behavior is improved for database operational errors:

```json
{
  "detail": "Database unavailable. Check DATABASE_URL and make sure the configured database service is running.",
  "request_id": "..."
}
```

Status code: `503`.

## T10. Data Model / Migration

No schema migration was added.

## T11. Backend Plan / Changes

- Add `OperationalError` handler in `atdr/app/main.py`.
- Add startup DB connectivity logging.
- Extend `config_doctor`.
- Extend `check_dev_environment`.
- Add `use_local_sqlite_config`.

## T12. Frontend Plan / Changes

No frontend runtime changes.

## T13. Security / Response / AI Safety

- No real response connector.
- No automatic response.
- No secrets emitted in config checker outputs.
- Assistant external provider remains disabled by default.
- Assistant raw-log context remains disabled by default.

## T14. Test Plan

- Config doctor local SQLite detection.
- Config doctor Docker-style PostgreSQL warning.
- Config doctor assistant safety warnings.
- Dev environment DB URL redaction.
- Local SQLite helper dry-run behavior.
- DB unavailable 503 handler.
- Full release verification.

## T15. Implementation Summary

v3.10 adds clearer diagnostics and a safe recovery path for the exact local/backend failure mode where `.env` points at Docker PostgreSQL host `postgres` while running the normal local SQLite workflow.

## T16. Tests Run / Evidence

Final verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

Updated or added:

- `docs/V3_10_CONFIG_SAFETY_HARDENING.md`
- `docs/changes/T1_T20_V3_10_CONFIG_SAFETY_HARDENING.md`
- `README.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/LAB_RUNBOOK.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- Decision: keep SQLite as normal local workflow.
- Decision: keep PostgreSQL optional for shared-lab validation.
- Decision: helper is dry-run by default.
- Risk: users can still manually misconfigure `.env`; config doctor now makes this obvious.
- Risk: PostgreSQL validation still needs a real PostgreSQL/Docker service.

## T19. Release / Rollback

Rollback:

- Revert `config_doctor` and `check_dev_environment` changes.
- Remove `use_local_sqlite_config`.
- Remove the DB `OperationalError` handler.
- Revert docs/tests.

No data rollback is needed.

## T20. Final Handoff

ATDR now gives clearer local/shared-lab configuration guidance and avoids confusing database tracebacks for common `.env` mistakes. The normal backend/frontend startup commands remain unchanged.
