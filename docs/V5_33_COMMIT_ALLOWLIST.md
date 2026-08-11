# v5.33 Exact Commit Allowlist

## Purpose

This file defines the exact tracked review boundary for v5.33 Independent
Detection Evidence and Assistant Human Acceptance.

It does not authorize staging, committing, pushing, or force operations. Those
actions require separate explicit user approval.

## Exact Paths (15)

```text
atdr/app/detection/v528_blind_review_helper.py
atdr/app/services/v533_independent_acceptance_service.py
atdr/scripts/run_v533_independent_detection_assistant_acceptance.py
atdr/tests/test_v533_independent_acceptance.py
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/LAB_RUNBOOK.md
docs/V5_33_COMMIT_ALLOWLIST.md
docs/V5_33_INDEPENDENT_DETECTION_AND_ASSISTANT_ACCEPTANCE.md
docs/changes/T1_T20_V5_33_INDEPENDENT_DETECTION_AND_ASSISTANT_ACCEPTANCE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

## Explicit Exclusions

Do not stage or track:

- `.env` or any private environment/profile file;
- databases, backups, logs, uploaded evidence, or processed data;
- model artifacts, labels, reviews, prediction locks, fingerprints, private
  evidence manifests, or human acceptance worksheets;
- `ml_baseline_reviews/`, `demo_exports/`, generated reports, build/test
  output, or temporary databases;
- private PAN-OS paths, raw rows, IP addresses, source identities, reviewer
  identities, provider credentials, API keys, or secrets; or
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
compare the normalized changed-path set exactly with these 15 paths and stop
on any mismatch.
