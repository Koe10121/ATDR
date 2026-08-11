# v5.32 Exact Commit Allowlist

## Purpose

This file defines the exact tracked review boundary for v5.32 Analyst
Workflow, Dashboard, and Assistant Product Acceptance Lock.

It does not authorize staging, committing, pushing, or force operations. Those
actions require a separate explicit user approval.

## Exact Paths (17)

```text
atdr/app/services/dashboard_service.py
atdr/tests/test_frontend_scaffold.py
atdr/tests/test_v47_overview_performance.py
atdr/tests/test_v532_analyst_workflow_product_acceptance.py
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/DASHBOARD_PRODUCTION_PATH.md
docs/LAB_RUNBOOK.md
docs/V5_32_ANALYST_WORKFLOW_PRODUCT_ACCEPTANCE.md
docs/V5_32_COMMIT_ALLOWLIST.md
docs/changes/T1_T20_V5_32_ANALYST_WORKFLOW_PRODUCT_ACCEPTANCE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/ExecutiveOverview.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

## Explicit Exclusions

Do not stage or track:

- `.env` or any private environment/profile file;
- databases, backups, logs, uploaded evidence, or processed data;
- model artifacts, labels, reviews, prediction locks, fingerprints, or private
  evidence manifests;
- `ml_baseline_reviews/`, `demo_exports/`, generated reports, build/test
  output, or temporary databases;
- private PAN-OS paths, raw rows, IP addresses, source identities, reviewer
  identities, provider credentials, or secrets; or
- any path not listed above.

## Review Commands

```powershell
git status --short --untracked-files=all
git diff --check
git diff --name-only
git ls-files --others --exclude-standard
git diff --cached --name-only
```

Expected staging state is empty. Before any later approved Git operation,
compare the normalized changed-path set exactly with these 17 paths and stop
on any mismatch.
