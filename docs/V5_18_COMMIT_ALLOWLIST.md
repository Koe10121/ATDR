# v5.18 Exact Commit Allowlist

Date: 2026-07-30

## Purpose

This is the exact 27-path review boundary for v5.18 Approved-Host
PostgreSQL Scale Qualification and SLO Lock.

It does not authorize staging, committing, pushing, deleting data, migrating
the configured database, activating a model, or changing response authority.
Any Git publication requires separate explicit owner approval.

## Exact Paths

### Backend runtime, qualification, and tests (14)

```text
atdr/app/detection/explanations.py
atdr/app/routers/alerts.py
atdr/app/schemas/alerts.py
atdr/app/services/alert_service.py
atdr/app/services/case_service.py
atdr/app/services/detection_service.py
atdr/app/services/job_dispatcher.py
atdr/app/services/v514_large_file_runtime_service.py
atdr/app/services/v517_postgres_multiworker_service.py
atdr/app/services/v518_postgres_scale_service.py
atdr/scripts/run_v518_postgres_scale_qualification.py
atdr/tests/test_detection_grouping.py
atdr/tests/test_v517_postgres_multiworker_acceptance.py
atdr/tests/test_v518_postgres_scale_qualification.py
```

### Frontend contracts and regression coverage (3)

```text
frontend/src/pages/AlertsTriage.tsx
frontend/src/types/api.ts
frontend/tests/smoke.spec.ts
```

### Governance and operating documentation (10)

```text
README.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/V5_18_COMMIT_ALLOWLIST.md
docs/V5_18_POSTGRES_SCALE_QUALIFICATION.md
docs/changes/T1_T20_V5_18_POSTGRES_SCALE_QUALIFICATION.md
docs/prd/PRD-ATDR.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

## Explicit Exclusions

The boundary excludes:

- private or real log files and their paths;
- `.env` files, credentials, tokens, and secrets;
- SQLite/PostgreSQL databases, backups, and journal files;
- `ml_baseline_reviews/` and reviewed-label exports;
- `demo_exports/` and generated JSON/CSV/HTML/PDF reports;
- processed evidence and temporary/staged inputs;
- model artifacts and benchmark snapshots; and
- any unrelated local work.

## Boundary Checks

Before any separately approved Git operation:

1. compare the changed-path set exactly with the 27 paths above;
2. confirm `git diff --check` passes;
3. confirm protected/private files remain ignored and untracked;
4. confirm no private path, raw row, IP address, fingerprint, SQL parameter,
   private database URL, private credential, or secret is present in tracked
   v5.18 content; and
5. stage only these exact paths after separate explicit approval.

The measured qualification output and disposable PostgreSQL runtime remain
ignored host-local evidence and are not included in this boundary.
