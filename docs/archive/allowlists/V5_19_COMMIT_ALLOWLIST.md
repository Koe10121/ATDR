# v5.19 Exact Commit Allowlist

Date: 2026-08-01

## Purpose

This file defines the exact tracked review boundary for v5.19 Independent
Labeled Detection/ML Evidence and Blind Validation. It does not authorize a
commit or push.

## Exact Paths

```text
atdr/app/detection/v519_independent_labeled_validation.py
atdr/scripts/run_v519_independent_labeled_validation.py
atdr/tests/test_v519_independent_labeled_validation.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/V5_19_COMMIT_ALLOWLIST.md
docs/V5_19_INDEPENDENT_LABELED_BLIND_VALIDATION.md
docs/changes/T1_T20_V5_19_INDEPENDENT_LABELED_BLIND_VALIDATION.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

Exact path count: `16`.

## Explicit Exclusions

Do not stage:

- external CTU-13 files or manifests;
- frozen predictions, revealed labels, evidence checksums, or generated reports;
- private PAN-OS files or any local path to them;
- `.env` files, credentials, tokens, or secrets;
- databases, backups, journals, or temporary PostgreSQL files;
- model artifacts;
- `ml_baseline_reviews/`, `demo_exports/`, processed evidence, or `.tmp/`; or
- unrelated local work.

## Boundary Checks

Before any separately approved Git operation:

1. compare the changed-path set exactly with these 16 paths;
2. run `git diff --check`;
3. verify ignored/private evidence remains untracked;
4. scan tracked v5.19 content for paths, raw rows, IPs, hashes, database URLs,
   credentials, and secrets; and
5. stage nothing until the owner gives separate exact-path approval.

No commit or push is authorized by this document.
