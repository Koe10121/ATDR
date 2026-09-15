# v5.30 Exact Commit Allowlist

## Purpose

This file defines the exact cumulative tracked review boundary for the pending
v5.29.1 frontend security closure and v5.30 supervised evidence closure. The
two phases share governance and taskboard files, so reviewing the complete
current boundary is safer than implying that those shared edits can be split
mechanically.

This document does not authorize staging, committing, pushing, or force
operations. Those actions require a separate explicit user approval.

## Exact Paths (20)

```text
atdr/app/detection/v530_supervised_evidence_closure.py
atdr/scripts/run_v530_supervised_evidence_closure.py
atdr/tests/test_v530_supervised_evidence_closure.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/V5_29_1_COMMIT_ALLOWLIST.md
docs/V5_29_1_FRONTEND_SECURITY_CLOSURE.md
docs/V5_30_COMMIT_ALLOWLIST.md
docs/V5_30_SUPERVISED_EVIDENCE_CLOSURE.md
docs/changes/T1_T20_V5_29_1_FRONTEND_SECURITY_CLOSURE.md
docs/changes/T1_T20_V5_30_SUPERVISED_EVIDENCE_CLOSURE.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/package-lock.json
frontend/package.json
frontend/src/components/ProtectedRoute.tsx
frontend/src/pages/LoginPage.tsx
frontend/tests/smoke.spec.ts
```

## Explicit Exclusions

Do not stage or track:

- `.env` or any private environment/profile file;
- databases, backups, logs, uploaded evidence, or processed data;
- model artifacts, label/review files, prediction locks, or fingerprints;
- `ml_baseline_reviews/`, `demo_exports/`, generated reports, or test output;
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

Expected staging state during this phase is empty. Before any later approved
Git operation, compare the normalized changed-path set exactly with the 20
paths above and stop on any mismatch.
