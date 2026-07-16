# v4.1 Changeset Manifest

## Status

This is the source-controlled review boundary for v4.1 Schema-Aware SOC Queue Model Redesign. It inherits the exact 39-path v3.97-v4.0 boundary in `docs/V4_0_CHANGESET_MANIFEST.md` and adds the exact v4.1 paths below. It is not authority to stage, commit, push, migrate the configured database, activate a model, or enable response automation.

## v4.1 Exact Path Additions

```text
atdr/app/detection/schema_contracts.py
atdr/app/detection/v401_schema_aware_soc_queue.py
atdr/scripts/run_v401_schema_aware_soc_queue.py
atdr/tests/test_v401_schema_aware_soc_queue.py
docs/V4_1_CHANGESET_MANIFEST.md
docs/V4_1_SCHEMA_AWARE_SOC_QUEUE_MODEL_REDESIGN.md
docs/AI-DOCS-INDEX.md
docs/ATDR_PRODUCTIZATION_ROADMAP.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/changes/T1_T20_V4_1_SCHEMA_AWARE_SOC_QUEUE_MODEL_REDESIGN.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

The cumulative review boundary is the inherited 39 paths plus these 16 additions, for 55 paths. Do not use broad staging commands such as `git add .` or `git add -A`.

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
provider development files
generated samples, manifests, predictions, labels, and reports
active or candidate model artifacts
real/private logs
```

## Evidence and State Boundary

- v4.0 evidence is locked by name and SHA-256 and is prohibited from v4.1 development roles.
- v4.1 reports run against a disposable migrated SQLite database, not configured `atdr.db`.
- Official provider development rows are non-human and non-importable.
- The future UNSW benchmark is reserved but not downloaded, inspected, or used.
- No labels, model runs, detection runs, response actions, or active artifacts are created.

## Review Commands

```powershell
git status --short --untracked-files=all
git diff --check
git diff --stat
git diff -- <path>
```

Staging, commit, push, configured-database migration, model activation, benchmark release, and any response integration require separate explicit approval.
