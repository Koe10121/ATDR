# v5.63.1 Commit Allowlist

This allowlist covers only the controlled-lab detection and advisor
demonstration reliability lock. It contains exactly 27 tracked paths. No path
is authorized for staging, commit, or push without separate explicit approval.

```text
README.md
atdr/app/detection/v5631_advisor_demo_reliability.py
atdr/app/schemas/ml.py
atdr/app/services/ml_service.py
atdr/app/services/tuning_service.py
atdr/app/services/v561_anomaly_bootstrap_service.py
atdr/scripts/run_v5631_advisor_demo_acceptance.py
atdr/scripts/run_v5631_anomaly_reliability.py
atdr/tests/test_v5631_advisor_demo_reliability.py
docs/ADVISOR_DEMO_RUNBOOK.md
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/PRESENTATION_BRIEF.md
docs/V5_63_1_ADVISOR_DEMO_RELIABILITY_LOCK.md
docs/V5_63_1_COMMIT_ALLOWLIST.md
docs/changes/T1_T20_V5_63_1_ADVISOR_DEMO_RELIABILITY_LOCK.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/DetectionTuning.tsx
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

Excluded private and generated material includes `.env` files, databases, raw
logs, protected reviews, labels, predictions, fingerprints, model artifacts,
`ml_baseline_reviews/`, `demo_exports/`, processed evidence, generated reports,
provider payloads, credentials, and secrets.

The allowlist does not authorize model activation, artifact installation,
automatic response, real firewall blocking, commit, or push.
