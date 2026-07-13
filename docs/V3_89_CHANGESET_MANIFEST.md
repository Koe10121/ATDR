# v3.89 Changeset Manifest

Date: 2026-07-13

## Purpose

This manifest identifies the source-controlled v3.89 shared-lab persistence and backup/restore foundation. It is a staging aid only; it does not commit or push anything.

## Included Changes

### Persistence And Migration Safety

- `atdr/app/db/engine.py`
- `atdr/app/db/database.py`
- `atdr/app/db/models.py`
- `atdr/app/services/persistence_service.py`
- `migrations/env.py`
- `migrations/versions/9f4d2c7a1b8e_add_operation_run_history.py`
- `migrations/versions/a7c9d2e4f6b1_add_summary_performance_indexes.py`
- `migrations/versions/b3d8e2a9c4f7_add_ml_label_label_source_index.py`
- `migrations/versions/c4f1a8d9e2b6_add_log_sources.py`
- `migrations/versions/c8d9e0f1a2b3_add_account_email_verification.py`
- `migrations/versions/d4e5f6a7b8c9_add_assistant_feedback.py`
- `migrations/versions/d5a6b7c8e9f0_fix_log_source_name_index.py`
- `migrations/versions/e7b2c3d4f5a6_add_log_source_parser_profile.py`
- `migrations/versions/f1a2b3c4d5e6_add_ml_label_provenance.py`

### Safe Operations And Diagnostics

- `atdr/scripts/backup_database.py`
- `atdr/scripts/restore_database.py`
- `atdr/scripts/validate_persistence_profile.py`
- `atdr/scripts/backup_postgres.py`
- `atdr/scripts/run_backup_restore_drill.py`
- `atdr/scripts/run_postgres_lab_validation.py`
- `atdr/scripts/config_doctor.py`
- `atdr/scripts/check_dev_environment.py`

### Tests And CI

- `atdr/tests/test_v389_persistence.py`
- `atdr/tests/test_api.py`
- `atdr/tests/test_dev_onboarding.py`
- `atdr/tests/test_hardening_and_ingestion.py`
- `.github/workflows/ci.yml`

### Configuration And Documentation

- `.env.example`
- `.env.lab.example`
- `.env.production.example`
- `.gitignore`
- `README.md`
- `docs/V3_89_SHARED_LAB_PERSISTENCE_AND_BACKUP_RESTORE.md`
- `docs/V3_89_CHANGESET_MANIFEST.md`
- `docs/changes/T1_T20_V3_89_SHARED_LAB_PERSISTENCE.md`
- `docs/QUICKSTART_FOR_TEAM.md`
- `docs/LAB_RUNBOOK.md`
- `docs/CURRENT_SYSTEM_STATE_LOCK.md`
- `docs/ATDR_PRODUCTIZATION_ROADMAP.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## Explicit Exclusions

Do not stage or commit the following, even when generated while validating v3.89:

- `.env` and private environment files;
- `atdr.db`, `*.sqlite`, `*.sqlite3`, backup artifacts, manifests, and `.tmp/` output;
- real or private logs, processed logs, and `atdr/data/processed/*` except tracked `.gitkeep` files;
- model artifacts and generated model reports;
- `ml_baseline_reviews/`, `demo_exports/`, generated CSV/JSON/HTML/PDF reports;
- API keys, IAM client secrets, passwords, access tokens, and provider credentials;
- the external supervisor-template directory outside this repository.

## Exact Staging Commands

Review the worktree first:

```powershell
git status --short --untracked-files=all
git diff --check
```

Stage only the v3.89 source-controlled files:

```powershell
git add -- .env.example .env.lab.example .env.production.example .gitignore README.md `
  .github/workflows/ci.yml `
  atdr/app/core/config.py atdr/app/db/engine.py atdr/app/db/database.py atdr/app/db/models.py `
  atdr/app/services/persistence_service.py `
  atdr/scripts/backup_database.py atdr/scripts/restore_database.py atdr/scripts/validate_persistence_profile.py `
  atdr/scripts/backup_postgres.py atdr/scripts/check_dev_environment.py atdr/scripts/config_doctor.py `
  atdr/scripts/database_portability_audit.py atdr/scripts/run_backup_restore_drill.py `
  atdr/scripts/run_postgres_lab_validation.py `
  atdr/tests/test_v389_persistence.py atdr/tests/test_api.py atdr/tests/test_dev_onboarding.py `
  atdr/tests/test_hardening_and_ingestion.py `
  migrations/env.py migrations/versions `
  docs/V3_89_SHARED_LAB_PERSISTENCE_AND_BACKUP_RESTORE.md docs/V3_89_CHANGESET_MANIFEST.md `
  docs/changes/T1_T20_V3_89_SHARED_LAB_PERSISTENCE.md `
  docs/AI-DOCS-INDEX.md docs/ATDR_PRODUCTIZATION_ROADMAP.md docs/ATDR_REQUIREMENT_TRACEABILITY.md `
  docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md docs/CURRENT_SYSTEM_STATE_LOCK.md docs/LAB_RUNBOOK.md `
  docs/QUICKSTART_FOR_TEAM.md docs/prd/PRD-ATDR.md docs/tasks/tasklist-progress.md docs/tasks/tasklist-progress.html
```

Then verify the staged diff contains no ignored/private output:

```powershell
git diff --cached --check
git status --short --ignored
git diff --cached --name-only
```

Do not commit or push until the v3.89 verification result and the staged file list have been reviewed. After push, inspect the `postgres-persistence` GitHub Actions job before treating PostgreSQL runtime validation as complete.

## Rollback

v3.89 does not add a schema migration or modify the current database. If a code rollback is needed, revert the v3.89 commit. Generated backups remain ignored or external and must be handled separately by the operator.
