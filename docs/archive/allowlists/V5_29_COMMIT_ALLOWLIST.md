# v5.29 Exact Commit Allowlist

## Status

This is the cumulative tracked review boundary for the uncommitted v5.26,
v5.27, v5.28, and v5.29 work. It contains exactly 52 paths. It is not
permission to stage, commit, or push.

## Allowed Paths

```text
.env.example
.env.lab.example
atdr/app/core/config.py
atdr/app/detection/v526_native_blind_qualification.py
atdr/app/detection/v527_blind_review_evaluation.py
atdr/app/detection/v528_blind_review_helper.py
atdr/app/detection/v528_supervised_readiness.py
atdr/app/schemas/assistant.py
atdr/app/services/assistant_llm.py
atdr/app/services/assistant_response_contracts.py
atdr/app/services/assistant_service.py
atdr/app/services/v524_investigation_gemini_quality_service.py
atdr/app/services/v527_gemini_real_alert_quality_service.py
atdr/scripts/evaluate_assistant_qa.py
atdr/scripts/run_v526_native_blind_qualification.py
atdr/scripts/run_v527_blind_review_evaluation.py
atdr/scripts/run_v527_gemini_real_alert_quality.py
atdr/scripts/run_v528_blind_review_helper.py
atdr/scripts/run_v528_supervised_readiness_audit.py
atdr/tests/test_assistant.py
atdr/tests/test_v526_native_blind_qualification.py
atdr/tests/test_v527_blind_review_and_gemini_quality.py
atdr/tests/test_v528_review_readiness_and_gemini.py
atdr/tests/test_v529_assistant_concision.py
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
docs/V5_28_COMMIT_ALLOWLIST.md
docs/V5_28_REVIEW_READINESS_AND_GEMINI_PRODUCTIZATION.md
docs/V5_29_COMMIT_ALLOWLIST.md
docs/V5_29_SOC_ASSISTANT_INTENT_AWARE_CONCISION.md
docs/changes/T1_T20_V5_26_NATIVE_BLIND_DETECTION_QUALIFICATION.md
docs/changes/T1_T20_V5_27_BLIND_REVIEW_AND_GEMINI_REAL_ALERT_QUALITY.md
docs/changes/T1_T20_V5_28_REVIEW_READINESS_AND_GEMINI_PRODUCTIZATION.md
docs/changes/T1_T20_V5_29_SOC_ASSISTANT_INTENT_AWARE_CONCISION.md
docs/detection/V5_27_BLIND_REVIEWER_GUIDE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/components/AssistantAnswerContent.tsx
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/assistantSession.ts
frontend/src/pages/AssistantPage.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

## Excluded

Do not stage or commit:

- `.env` or any provider/IAM secret;
- databases, logs, processed evidence, or private source files;
- blind packs or review working copies, prediction locks, review tokens,
  reviewer identities, private integrity seals, fingerprints, or generated
  metrics/readiness reports;
- prompts, provider answers, raw Assistant context, IP addresses, or telemetry
  containing content;
- `ml_baseline_reviews/` or `demo_exports/`;
- model artifacts; or
- anything outside the exact list above.

## Approval Gate

Before any future commit, compare the complete changed-path set to this list,
confirm staging is empty, run `git diff --check`, verify ignored/private files,
and obtain separate explicit exact-path approval. Never force-push.
