# v5.63 Commit Allowlist

This cumulative allowlist covers the unpublished v5.62 and v5.63 source,
tests, frontend, and governance baseline. It contains exactly 32 tracked paths.
No path is authorized for staging, commit, or push without separate explicit
approval.

```text
atdr/app/detection/v562_supervised_qualification_campaign.py
atdr/app/detection/v563_fresh_evidence_expansion.py
atdr/app/routers/evidence_review.py
atdr/app/schemas/evidence_review.py
atdr/app/services/v562_supervised_qualification_review_service.py
atdr/app/services/v563_supervised_expansion_review_service.py
atdr/scripts/run_v562_supervised_qualification_campaign.py
atdr/scripts/run_v563_fresh_evidence_expansion.py
atdr/tests/test_v562_supervised_qualification_campaign.py
atdr/tests/test_v563_fresh_evidence_expansion.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/V5_62_COMMIT_ALLOWLIST.md
docs/V5_62_SUPERVISED_QUALIFICATION_CAMPAIGN.md
docs/V5_63_COMMIT_ALLOWLIST.md
docs/V5_63_FRESH_COMPARABLE_EVIDENCE_EXPANSION.md
docs/changes/T1_T20_V5_62_SUPERVISED_QUALIFICATION_CAMPAIGN.md
docs/changes/T1_T20_V5_63_FRESH_COMPARABLE_EVIDENCE_EXPANSION.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/components/SupervisedEvidenceExpansionPanel.tsx
frontend/src/components/SupervisedQualificationReviewPanel.tsx
frontend/src/hooks/useApiQueries.ts
frontend/src/lib/api.ts
frontend/src/pages/EvidenceReviewPage.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Excluded private and generated material includes `.env` files, databases, raw
logs, protected review state, labels, predictions, fingerprints, model
artifacts, `ml_baseline_reviews/`, `demo_exports/`, processed evidence, provider
payloads, credentials, and secrets.
