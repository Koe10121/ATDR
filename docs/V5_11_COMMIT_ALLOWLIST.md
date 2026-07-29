# v5.11 Exact Commit Allowlist

Date: 2026-07-28

This file records the exact v5.11 source-controlled path set. It does not
authorize staging, committing, or pushing. Separate explicit owner approval
is required.

Exact allowlist, 26 paths:

```text
.env.example
.env.lab.example
atdr/app/core/config.py
atdr/app/routers/ml.py
atdr/app/services/job_dispatcher.py
atdr/app/services/job_service.py
atdr/app/services/v511_shadow_monitoring_service.py
atdr/app/services/v59_shadow_observation_service.py
atdr/scripts/run_v511_shadow_monitoring.py
atdr/tests/test_api.py
atdr/tests/test_v511_shadow_monitoring.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/V5_11_COMMIT_ALLOWLIST.md
docs/V5_11_OPERATIONAL_DRIFT_AND_SHADOW_MONITORING.md
docs/changes/T1_T20_V5_11_OPERATIONAL_DRIFT_AND_SHADOW_MONITORING.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Do not stage:

- `.env` or any private environment profile;
- databases or backups;
- raw/private logs or processed evidence;
- model artifacts;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- generated reports outside the tracked documentation paths;
- local test output, build output, caches, or runtime logs; or
- any cumulative v4.9-v5.10 path not independently approved.

Before any future approved commit:

```powershell
git status --short --untracked-files=all
git diff --check
git diff --cached --name-only
```

The staged path set must exactly match this allowlist and no force-push is
permitted.
