# v5.62 Commit Allowlist

This allowlist contains the complete tracked v5.62 implementation boundary.
It excludes private evidence, protected reviews, generated reports, database
files, model artifacts, provider payloads, secrets, and all ignored runtime
state. Staging, committing, or pushing requires separate explicit approval.

Expected path count: **23**

```text
atdr/app/detection/v562_supervised_qualification_campaign.py
atdr/app/routers/evidence_review.py
atdr/app/schemas/evidence_review.py
atdr/app/services/v562_supervised_qualification_review_service.py
atdr/scripts/run_v562_supervised_qualification_campaign.py
atdr/tests/test_v562_supervised_qualification_campaign.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/V5_62_COMMIT_ALLOWLIST.md
docs/V5_62_SUPERVISED_QUALIFICATION_CAMPAIGN.md
docs/changes/T1_T20_V5_62_SUPERVISED_QUALIFICATION_CAMPAIGN.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/components/SupervisedQualificationReviewPanel.tsx
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/EvidenceReviewPage.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

## Publication Safety

- Confirm the changed-path union exactly matches these 23 paths.
- Confirm `git diff --check` passes.
- Confirm the staging area contains only these paths.
- Rerun the repository surface audit and security acceptance scan.
- Confirm supervised ML remains `unqualified` and no active artifact exists.
- Confirm rules remain alert-authoritative and response remains
  `simulation_only`.
- Do not force-push.
