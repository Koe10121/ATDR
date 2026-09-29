# v5.60 Exact Commit Allowlist

Status: prepared only. No commit or push is authorized by this document.

If publication is separately approved, the changed-path set must match these
18 repository-relative paths exactly:

```text
README.md
atdr/app/services/v560_clean_machine_acceptance_service.py
atdr/scripts/run_v560_clean_machine_acceptance.py
atdr/tests/test_v560_clean_machine_acceptance.py
docs/AI-DOCS-INDEX.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/ENVIRONMENT_GUIDE.md
docs/OPERATIONS_RUNBOOK.md
docs/QUICKSTART_FOR_TEAM.md
docs/V5_60_CLEAN_MACHINE_RELEASE_CANDIDATE_ACCEPTANCE.md
docs/V5_60_COMMIT_ALLOWLIST.md
docs/changes/T1_T20_V5_60_CLEAN_MACHINE_RELEASE_CANDIDATE_ACCEPTANCE.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

Before any separately approved commit:

- require the unstaged/staged changed-path union to equal this set;
- require `git diff --check` to pass;
- require the staging area to be empty before explicit publication approval;
- rerun repository surface and tracked-secret scans after final rendering;
- exclude private `.env` files, databases, logs, labels, reviews, model
  artifacts, provider payloads, generated reports, `ml_baseline_reviews/`,
  `demo_exports/`, processed evidence, credentials, and secrets;
- confirm rules remain alert-authoritative, supervised ML remains
  `unqualified`, and response remains `simulation_only`; and
- never force-push.
