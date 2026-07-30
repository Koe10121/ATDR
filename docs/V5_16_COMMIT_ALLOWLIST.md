# v5.16 Exact Commit Allowlist

Date: 2026-07-30

## Purpose

This is the exact 21-path review boundary for v5.16 Full-Scale Memory And
Query Stabilization.

It does not authorize staging, committing, pushing, deleting data, migrating
the configured database, activating a model, or changing response authority.
Any Git publication requires separate explicit owner approval.

## Exact Paths

### Backend runtime and tests (11)

```text
atdr/app/detection/rules.py
atdr/app/services/alert_service.py
atdr/app/services/case_service.py
atdr/app/services/detection_service.py
atdr/app/services/source_service.py
atdr/app/services/v514_large_file_runtime_service.py
atdr/app/services/v515_runtime_soak_service.py
atdr/app/services/v516_memory_query_service.py
atdr/scripts/run_v516_memory_query_stabilization.py
atdr/tests/test_detection_grouping.py
atdr/tests/test_v516_memory_query_stabilization.py
```

### Governance and operating documentation (10)

```text
README.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/CURRENT_SYSTEM_STATE_LOCK.md
docs/LAB_RUNBOOK.md
docs/V5_16_COMMIT_ALLOWLIST.md
docs/V5_16_FULL_SCALE_MEMORY_QUERY_STABILIZATION.md
docs/changes/T1_T20_V5_16_FULL_SCALE_MEMORY_QUERY_STABILIZATION.md
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

1. compare the changed-path set exactly with the 21 paths above;
2. confirm `git diff --check` passes;
3. confirm protected/private files remain ignored and untracked;
4. confirm no private path, raw row, IP address, fingerprint, SQL parameter,
   or secret is present in tracked v5.16 content; and
5. stage only these exact paths after separate explicit approval.
