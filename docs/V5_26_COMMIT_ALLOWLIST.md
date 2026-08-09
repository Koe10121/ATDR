# v5.26 Exact Commit Allowlist

## Scope

This is the exact 15-path review boundary for v5.26. It contains implementation,
tests, and tracked governance only. It does not authorize staging, committing,
or pushing; those actions require separate explicit approval naming this
allowlist.

## Paths

```text
atdr/app/detection/v526_native_blind_qualification.py
atdr/scripts/run_v526_native_blind_qualification.py
atdr/tests/test_v526_native_blind_qualification.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/changes/T1_T20_V5_26_NATIVE_BLIND_DETECTION_QUALIFICATION.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/LAB_RUNBOOK.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
docs/V5_26_COMMIT_ALLOWLIST.md
docs/V5_26_NATIVE_BLIND_DETECTION_QUALIFICATION.md
```

## Exclusions

Private `.env` files, databases, raw/private logs, IP-bearing evidence, labels,
review packs, prediction locks, fingerprints, model artifacts,
`ml_baseline_reviews/`, `demo_exports/`, processed evidence, generated reports,
caches, and build output are outside this boundary and must remain ignored.
