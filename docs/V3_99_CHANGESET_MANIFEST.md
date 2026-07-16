# v3.97-v3.99 Changeset Manifest

## Status

This is the exact source-controlled allowlist for the preserved v3.97 closure, v3.98 holdout validation, and v3.99 synthetic multi-source frozen revalidation worktree. It is a review boundary, not permission to stage, commit, push, migrate the configured database, activate a model, or enable response automation.

## Exact 33-Path Allowlist

```text
atdr/app/core/log_fingerprint.py
atdr/app/db/models.py
atdr/app/detection/v398_independent_holdout_validation.py
atdr/app/detection/v399_multisource_frozen_revalidation.py
atdr/app/services/log_service.py
atdr/app/services/metrics_service.py
atdr/app/services/resumable_ingestion_service.py
atdr/scripts/run_v398_independent_holdout_validation.py
atdr/scripts/run_v399_multisource_frozen_revalidation.py
atdr/scripts/validate_large_ingestion.py
atdr/tests/test_v397_large_ingestion.py
atdr/tests/test_v398_independent_holdout_validation.py
atdr/tests/test_v399_multisource_frozen_revalidation.py
docs/AI-DOCS-INDEX.md
docs/ATDR_PRODUCTIZATION_ROADMAP.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/V3_97_LARGE_FILE_INGESTION_RELIABILITY.md
docs/V3_98_CHANGESET_MANIFEST.md
docs/V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md
docs/V3_99_CHANGESET_MANIFEST.md
docs/V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE_AND_FROZEN_REVALIDATION.md
docs/changes/T1_T20_V3_97_LARGE_FILE_INGESTION_RELIABILITY.md
docs/changes/T1_T20_V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md
docs/changes/T1_T20_V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/ExecutiveOverview.tsx
frontend/tests/smoke.spec.ts
migrations/versions/b4c5d6e7f8a9_add_raw_log_content_fingerprint.py
```

Do not use `git add .`, `git add -A`, or broad directory staging.

## v3.99 New Paths

```text
atdr/app/detection/v399_multisource_frozen_revalidation.py
atdr/scripts/run_v399_multisource_frozen_revalidation.py
atdr/tests/test_v399_multisource_frozen_revalidation.py
docs/V3_99_CHANGESET_MANIFEST.md
docs/V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE_AND_FROZEN_REVALIDATION.md
docs/changes/T1_T20_V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE.md
```

Shared docs already present in the v3.98 allowlist receive v3.99 traceability updates and remain one path each.

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

Ignored v3.99 evidence includes three source CSVs, their manifest, the latest JSON, and timestamped validation/leakage Markdown reports. They are local evidence only.

## Hygiene Exception

Four pre-existing `.bin` face-model assets remain tracked under reference-only `NewSystem/frontend-vue/public/models/`. They are not used by ATDR runtime and were not modified. Removing reference-template assets requires a separate approved cleanup decision.

## Database And Activation Boundary

- Configured database remains at `a3b4c5d6e7f8` and was not evaluated or migrated.
- The ignored disposable copy is at `b4c5d6e7f8a9 (head)`.
- v3.99 read from the disposable copy and generated external features in ephemeral in-memory SQLite tables.
- Before/after database counts and active artifact metadata were identical.
- No label, model run, detection run, response action, or active artifact was created.

## Review Commands

```powershell
git status --short --untracked-files=all
git diff --check
git diff --stat
git diff -- <path>
```

Staging, commit, push, configured-database migration, model activation, and any response integration still require explicit approval.
