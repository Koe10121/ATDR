# v3.97 Closure And v3.98 Changeset Manifest

## Status

This is the exact source-controlled allowlist for the current v3.97 closure and v3.98 independent holdout worktree. It is a review boundary, not permission to stage, commit, push, migrate the configured database, activate a model, or enable response automation.

## v3.97 Allowlist

The v3.97 work that existed at the start of this closure is limited to these 19 paths:

```text
atdr/app/core/log_fingerprint.py
atdr/app/db/models.py
atdr/app/services/log_service.py
atdr/app/services/metrics_service.py
atdr/app/services/resumable_ingestion_service.py
atdr/scripts/validate_large_ingestion.py
atdr/tests/test_v397_large_ingestion.py
docs/AI-DOCS-INDEX.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/LAB_RUNBOOK.md
docs/V3_97_LARGE_FILE_INGESTION_RELIABILITY.md
docs/changes/T1_T20_V3_97_LARGE_FILE_INGESTION_RELIABILITY.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/ExecutiveOverview.tsx
frontend/tests/smoke.spec.ts
migrations/versions/b4c5d6e7f8a9_add_raw_log_content_fingerprint.py
```

The shared governance files in this list also receive v3.98 traceability updates; they remain one staged path each.

## v3.98 Additional Allowlist

```text
atdr/app/detection/v398_independent_holdout_validation.py
atdr/scripts/run_v398_independent_holdout_validation.py
atdr/tests/test_v398_independent_holdout_validation.py
docs/ATDR_PRODUCTIZATION_ROADMAP.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/V3_98_CHANGESET_MANIFEST.md
docs/V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md
docs/changes/T1_T20_V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md
```

The union of both lists is the complete 27-path allowlist. Do not use `git add .`, `git add -A`, or a broad directory add.

## Explicitly Excluded

Never stage or commit:

```text
.env
atdr.db
*.db
*.sqlite
*.sqlite3
backups/
.tmp/
ml_baseline_reviews/
demo_exports/
atdr/data/processed/ (except its existing .gitkeep)
frontend/dist/
frontend/playwright-report/
frontend/test-results/
active or candidate model artifacts
real/private logs
generated validation reports
```

Current ignored evidence includes the timestamped v3.97 SQLite backup, its manifest, the disposable migrated database copy, v3.97 validator output, and `ml_baseline_reviews/v3_98_*` reports. They are local evidence only.

## Repo-Hygiene Finding

No tracked ATDR runtime database, private `.env`, real log, generated review/export report, or active ATDR model artifact was found. Four pre-existing `.bin` face-model assets remain tracked under `NewSystem/frontend-vue/public/models/`. `NewSystem/` is reference-only and these files are not used by ATDR runtime, but they are model binaries in the strict repository-wide sense. They were intentionally left untouched because they are outside this allowlist and removing template assets requires a separate approved cleanup decision.

## Migration And Backup Boundary

- Configured database revision: `a3b4c5d6e7f8`.
- Disposable copy revision after validation: `b4c5d6e7f8a9 (head)`.
- Timestamped ignored backup: `backups/v397-closure/atdr-sqlite-20260714T011954Z-ac36e08c.sqlite3` with a separate manifest.
- The configured database was not reset, deleted, migrated, or used by the v3.97/v3.98 validators.
- Applying `alembic upgrade head` to the configured database still requires explicit user approval.

## Review Commands

```powershell
git status --short --untracked-files=all
git diff --check
git diff --stat
git diff -- <path>
```

If the user later approves a commit, stage only the literal paths in this manifest and review `git diff --cached --name-status` before committing. Push and force-push remain separately controlled; force-push is not authorized.
