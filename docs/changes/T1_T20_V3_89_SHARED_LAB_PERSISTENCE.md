# T1-T20: v3.89 Shared-Lab Persistence And Backup/Restore

## T1 Change Title

v3.89 Shared-Lab Persistence And Backup/Restore Foundation.

## T2 Requirement

Validate PostgreSQL compatibility and provide non-destructive backup/restore operations while preserving the default local SQLite workflow.

## T3 Source Evidence

`atdr/app/db/database.py`, `migrations/env.py`, `migrations/versions/*`, existing v3.3/v3.4 persistence scripts, `.github/workflows/ci.yml`, and `docs/V3_88_PRODUCT_BASELINE_CHECKPOINT.md`.

## T4 Current Behavior

SQLite is the default local database. Existing PostgreSQL and backup scripts provided readiness evidence but did not provide a unified checksum-validated separate-target restore workflow.

## T5 Impacted Areas / Agents

Database, backend/configuration, release operations, QA, documentation, and CI.

## T6 Scope

Dialect-aware engine options, secret-safe diagnostics, isolated SQLite backup/restore validation, optional PostgreSQL CI validation, and operator documentation. No schema feature change or runtime workflow redesign.

## T7 Functional Requirements

- Preserve SQLite startup behavior.
- Keep PostgreSQL optional.
- Back up SQLite consistently and PostgreSQL through `pg_dump` only when available.
- Require an explicit separate empty target for restore.
- Verify manifest checksum, counts, migration revision, and SQLite integrity.
- Keep all backup output ignored or external.
- Hide credentials and connection details from reports.

## T8 Acceptance Criteria

- The current database is never overwritten by v3.89 tools.
- Fresh temporary SQLite migrations, backup, restore, and comparison pass.
- PostgreSQL CI uses isolated ephemeral databases.
- Local use does not require PostgreSQL or Docker.
- No response, model, assistant, or IAM action is enabled.

## T9 API Contract

`/health` returns safe database dialect, migration, and backup-tool status only. No persistence credentials, URLs, or host values are returned.

## T10 Data Model / Migration

No new table or migration. The existing `ml_labels.reviewed` migration default is changed to `sa.true()` so it compiles safely for PostgreSQL as well as SQLite.

## T11 Backend Plan / Changes

Added dialect-aware engine construction, safe runtime inspection, `backup_database`, `restore_database`, and `validate_persistence_profile` commands. Legacy backup/readiness scripts now use or report the safer behavior.

## T12 Frontend Plan / Changes

No dashboard behavior change. Existing health consumers receive additional safe database metadata.

## T13 Security / Response / AI Safety

Backups use explicit execution. Restore requires a confirmation phrase and refuses the active or non-empty target. External LLM/IAM calls remain disabled in persistence CI. Response automation, real blocking, and model activation remain disabled.

## T14 Test Plan

Focused SQLite engine/profile, backup dry-run, backup/restore, active-target refusal, checksum rejection, PostgreSQL-tool status, safe diagnostics, current-database fingerprint, API health, migration, and legacy regression tests. Full release verification follows.

## T15 Implementation Summary

Implemented the safe persistence service, CLI operations, PostgreSQL pool profile, CI PostgreSQL service job, migration portability correction, and source-backed runbook/documentation updates.

## T16 Tests Run / Evidence

Focused validation passed: v3.89 persistence plus API regression tests (`51 passed`), targeted Ruff, PostgreSQL offline migration SQL generation, backup dry-run, config doctor, and isolated SQLite persistence validation. The isolated validator applied migrations to a new synthetic SQLite source, backed it up, restored it to a separate empty target, verified SHA-256, `PRAGMA quick_check`, table counts, Alembic revision, zero response/model side effects, and unchanged configured-database fingerprint. Full release verification and remote PostgreSQL CI evidence are recorded separately in the task board after completion.

## T17 PRD / Docs Updated

README, quickstart, lab runbook, state lock, roadmap, PRD, traceability, compliance checklist, documentation index, task board, this record, the v3.89 phase document, and `docs/V3_89_CHANGESET_MANIFEST.md`.

## T18 Risks / Blockers / Assumptions / Decisions

No local PostgreSQL/Docker executable is available on this workstation. PostgreSQL runtime proof therefore relies on the new isolated GitHub Actions job or an approved lab host. This is documented as pending until the job runs successfully.

## T19 Release / Rollback

No automatic commit or push. Revert the v3.89 commit for code rollback. No data rollback is required because validation uses fresh temporary databases and restore refuses the configured current database.

## T20 Final Handoff

Status: local v3.89 foundation complete. Full local verification passed, and `docs/V3_89_CHANGESET_MANIFEST.md` provides the exact staging allowlist. The remote `postgres-persistence` result remains pending until the user deliberately commits and pushes; do not claim live PostgreSQL validation before it passes. Recommended next phase after that evidence is durable background-job architecture.
