# v5.61 Exact Commit Allowlist

Status: prepared only. No commit or push is authorized by this document.

If publication is separately approved, the changed-path set must match these
31 repository-relative paths exactly:

```text
.gitignore
atdr/app/main.py
atdr/app/schemas/ml.py
atdr/app/services/ml_service.py
atdr/app/services/v560_clean_machine_acceptance_service.py
atdr/app/services/v561_anomaly_bootstrap_service.py
atdr/scripts/run_v560_clean_machine_acceptance.py
atdr/scripts/run_v561_governed_anomaly_bootstrap.py
atdr/tests/test_api.py
atdr/tests/test_v560_clean_machine_acceptance.py
atdr/tests/test_v561_anomaly_bootstrap.py
docs/AI-DOCS-INDEX.md
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/OPERATIONS_RUNBOOK.md
docs/QUICKSTART_FOR_TEAM.md
docs/V5_61_COMMIT_ALLOWLIST.md
docs/V5_61_GOVERNED_ANOMALY_BOOTSTRAP.md
docs/changes/T1_T20_V5_61_GOVERNED_ANOMALY_BOOTSTRAP.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
frontend/src/pages/MLGovernance.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
scripts/bootstrap_advisory_anomaly.cmd
scripts/bootstrap_advisory_anomaly.ps1
scripts/start_system.ps1
```

Before any separately approved commit:

- require the unstaged/staged changed-path union to equal this set;
- require `git diff --check` to pass;
- require the staging area to be empty before explicit publication approval;
- rerun repository surface and candidate secret scans after final rendering;
- exclude private `.env` files, databases, logs, labels, reviews, model
  artifacts, provider payloads, generated reports, `ml_baseline_reviews/`,
  `demo_exports/`, processed evidence, credentials, and secrets;
- confirm rules remain alert-authoritative, supervised ML remains
  `unqualified`, anomaly/hybrid remain advisory, and response remains
  `simulation_only`; and
- never force-push.

After a separately approved, CI-green publication, rerun the v5.60
clean-machine acceptance with `--exercise-anomaly-bootstrap` so the genuine
remote clone executes all 32 stages.
