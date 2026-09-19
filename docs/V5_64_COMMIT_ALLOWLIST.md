# v5.64 Commit Allowlist

This allowlist covers only the window-aware advisory anomaly redesign. It does
not authorize staging, commit, or push without separate explicit approval.

```text
README.md
atdr/app/detection/v564_window_aware_anomaly.py
atdr/scripts/run_v564_window_aware_anomaly_redesign.py
atdr/tests/test_v564_window_aware_anomaly.py
docs/ADVISOR_DEMO_RUNBOOK.md
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/V5_64_COMMIT_ALLOWLIST.md
docs/V5_64_WINDOW_AWARE_ADVISORY_ANOMALY_REDESIGN.md
docs/changes/T1_T20_V5_64_WINDOW_AWARE_ADVISORY_ANOMALY_REDESIGN.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

The allowlist contains exactly 17 tracked paths. It excludes private source
data, `.env` files, databases, labels, reviews, predictions, fingerprints,
model artifacts, generated reports, `ml_baseline_reviews/`, `demo_exports/`,
processed evidence, provider payloads, credentials, and secrets.

Rules must remain alert-authoritative, anomaly/hybrid output advisory,
supervised ML unqualified, and response `simulation_only`.
