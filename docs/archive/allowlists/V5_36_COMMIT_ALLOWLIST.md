# v5.36 Exact Commit Allowlist

This file does not authorize a commit or push. A repository owner must provide
separate explicit approval before staging these exact paths:

1. `atdr/app/services/v536_independent_evidence_activation_service.py`
2. `atdr/scripts/run_v536_independent_evidence_activation_decision.py`
3. `atdr/tests/test_v536_independent_evidence_activation.py`
4. `docs/V5_36_INDEPENDENT_EVIDENCE_ACTIVATION_DECISION.md`
5. `docs/changes/T1_T20_V5_36_INDEPENDENT_EVIDENCE_ACTIVATION_DECISION.md`
6. `docs/V5_36_COMMIT_ALLOWLIST.md`
7. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
8. `docs/AI_TRAINING_RUNBOOK.md`
9. `docs/LAB_RUNBOOK.md`
10. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
11. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
12. `docs/prd/PRD-ATDR.md`
13. `docs/tasks/tasklist-progress.md`
14. `docs/tasks/tasklist-progress.html`

Explicitly excluded: `.env` files, databases, private logs, human review
worksheets, labels, model artifacts, `ml_baseline_reviews/`, `demo_exports/`,
processed evidence, generated reports, provider payloads, API keys, and every
path not listed above.
