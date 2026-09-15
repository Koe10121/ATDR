# v3.97-v4.0 Changeset Manifest

## Status

This is the exact source-controlled review boundary for the preserved v3.97-v3.99 worktree plus v4.0 provider-blinded external validation. It is not permission to stage, commit, push, migrate the configured database, activate a model, or enable response automation.

## Exact 39-Path Allowlist

```text
atdr/app/core/log_fingerprint.py
atdr/app/db/models.py
atdr/app/detection/v398_independent_holdout_validation.py
atdr/app/detection/v399_multisource_frozen_revalidation.py
atdr/app/detection/v400_provider_blinded_external_validation.py
atdr/app/services/log_service.py
atdr/app/services/metrics_service.py
atdr/app/services/resumable_ingestion_service.py
atdr/scripts/run_v398_independent_holdout_validation.py
atdr/scripts/run_v399_multisource_frozen_revalidation.py
atdr/scripts/run_v400_provider_blinded_external_validation.py
atdr/scripts/validate_large_ingestion.py
atdr/tests/test_v397_large_ingestion.py
atdr/tests/test_v398_independent_holdout_validation.py
atdr/tests/test_v399_multisource_frozen_revalidation.py
atdr/tests/test_v400_provider_blinded_external_validation.py
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
docs/V4_0_CHANGESET_MANIFEST.md
docs/V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE_AND_FROZEN_VALIDATION.md
docs/changes/T1_T20_V3_97_LARGE_FILE_INGESTION_RELIABILITY.md
docs/changes/T1_T20_V3_98_INDEPENDENT_DETECTION_ML_HOLDOUT_VALIDATION.md
docs/changes/T1_T20_V3_99_INDEPENDENT_MULTI_SOURCE_EVIDENCE.md
docs/changes/T1_T20_V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/ExecutiveOverview.tsx
frontend/tests/smoke.spec.ts
migrations/versions/b4c5d6e7f8a9_add_raw_log_content_fingerprint.py
```

Do not use broad staging commands such as `git add .` or `git add -A`.

## v4.0 New Paths

```text
atdr/app/detection/v400_provider_blinded_external_validation.py
atdr/scripts/run_v400_provider_blinded_external_validation.py
atdr/tests/test_v400_provider_blinded_external_validation.py
docs/V4_0_CHANGESET_MANIFEST.md
docs/V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE_AND_FROZEN_VALIDATION.md
docs/changes/T1_T20_V4_0_PROVIDER_BLINDED_EXTERNAL_EVIDENCE.md
```

## Explicitly Excluded

Never stage or commit:

```text
.env
atdr.db
*.db
*.sqlite
*.sqlite3
.tmp/
backups/
ml_baseline_reviews/
demo_exports/
atdr/data/processed/ (except its existing .gitkeep)
frontend/dist/
frontend/playwright-report/
frontend/test-results/
provider benchmark files
feature-only samples
revealed provider labels
prediction artifacts
external evidence manifests
generated validation reports
active or candidate model artifacts
real/private logs
```

## Database And Activation Boundary

- Configured `atdr.db` was not evaluated, reset, deleted, or migrated.
- v4.0 ran against ignored disposable SQLite at Alembic head.
- External rows contributed `0/0/0` to fit/calibration/threshold selection.
- No label, model run, detection run, response action, or active artifact was created.

## Hygiene Exception

Four pre-existing `.bin` face-model assets remain tracked under reference-only `NewSystem/frontend-vue/public/models/`. They were not modified and are not ATDR runtime artifacts. Their removal requires a separate approved cleanup.

## Review Commands

```powershell
git status --short --untracked-files=all
git diff --check
git diff --stat
git diff -- <path>
```

Staging, commit, push, configured-database migration, model activation, and any response integration require separate explicit approval.
