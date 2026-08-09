# v5.27 Exact Commit Allowlist

## Status

This is the cumulative tracked review boundary for the uncommitted v5.26 and
v5.27 work. It contains exactly 24 paths. It is not permission to stage,
commit, or push.

## Allowed Paths

```text
atdr/app/detection/v526_native_blind_qualification.py
atdr/app/detection/v527_blind_review_evaluation.py
atdr/app/services/v527_gemini_real_alert_quality_service.py
atdr/scripts/run_v526_native_blind_qualification.py
atdr/scripts/run_v527_blind_review_evaluation.py
atdr/scripts/run_v527_gemini_real_alert_quality.py
atdr/tests/test_v526_native_blind_qualification.py
atdr/tests/test_v527_blind_review_and_gemini_quality.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/LAB_RUNBOOK.md
docs/V5_26_COMMIT_ALLOWLIST.md
docs/V5_26_NATIVE_BLIND_DETECTION_QUALIFICATION.md
docs/V5_27_BLIND_REVIEW_AND_GEMINI_REAL_ALERT_QUALITY.md
docs/V5_27_COMMIT_ALLOWLIST.md
docs/changes/T1_T20_V5_26_NATIVE_BLIND_DETECTION_QUALIFICATION.md
docs/changes/T1_T20_V5_27_BLIND_REVIEW_AND_GEMINI_REAL_ALERT_QUALITY.md
docs/detection/V5_27_BLIND_REVIEWER_GUIDE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

## Excluded

Do not stage or commit:

- `.env` or any provider/IAM secret;
- databases, logs, processed evidence, or private source files;
- blind review CSVs, prediction locks, review tokens, reviewer identities,
  private integrity seals, fingerprints, or generated metrics reports;
- `ml_baseline_reviews/` or `demo_exports/`;
- model artifacts; or
- anything outside the exact list above.

## Approval Gate

Before any future commit, compare the complete changed-path set to this list,
confirm staging is empty, run `git diff --check`, verify ignored/private files,
and obtain separate explicit exact-path approval. Never force-push.
