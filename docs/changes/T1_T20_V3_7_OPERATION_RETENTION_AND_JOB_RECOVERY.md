# T1-T20 Change Document: v3.7 Operation Retention And Job Recovery

## T1. Change Title

v3.7 Operation Retention, Stale Job Recovery, and Maintenance Hardening.

## T2. Requirement

Add safe, explicit maintenance tooling for operation jobs so ATDR can identify stale long-running operations and clean old terminal job records without deleting raw evidence or changing normal runtime behavior.

## T3. Source Evidence

| Evidence | Source |
| --- | --- |
| Existing operation job model | `atdr/app/db/models.py` |
| Existing job service and router | `atdr/app/services/job_service.py`, `atdr/app/routers/jobs.py` |
| Existing run history | `atdr/app/services/operation_run_service.py`, `atdr/app/routers/ingestion.py`, `atdr/app/routers/detection.py` |
| Existing replay job integration | `atdr/scripts/replay_logs.py` |
| Existing Operations Health UI | `frontend/src/pages/ExecutiveOverview.tsx` |
| Existing v3.6 documentation | `docs/V3_6_BACKGROUND_JOB_HARDENING.md` |

## T4. Current Behavior

ATDR records synchronous operation jobs for imports, replay, detection, ML actions, and exports. Before v3.7, it did not provide stale job detection, retention policy visibility, or an explicit maintenance command.

## T5. Impacted Areas / Agents

Backend/API, Release/Ops, Frontend Dashboard, QA/UAT, Documentation, and Governance.

## T6. Scope

In scope:

- Config placeholders for stale-job and retention policy.
- Stale active job detection.
- Job summary API.
- Dry-run-first maintenance script.
- Compact dashboard visibility.
- Tests and docs.

Out of scope:

- True async worker queues.
- Automatic startup cleanup.
- Raw log, alert, label, audit, or evidence cleanup.
- Detection, ML, or response logic changes.

## T7. Functional Requirements

- List stale active jobs based on a configurable threshold.
- Mark stale active jobs only when explicitly requested.
- Preview terminal job cleanup candidates by age.
- Delete only terminal `operation_jobs` records when explicitly requested.
- Expose non-secret job summary health.
- Keep all evidence-bearing tables protected.

## T8. Acceptance Criteria

- Dry-run does not mutate the database.
- Stale jobs are visible in API/UI.
- Stale jobs are only marked with explicit execution.
- Cleanup deletes only old terminal operation jobs.
- Raw logs and audit logs remain unchanged.
- Verification passes.

## T9. API Contract

Added:

```text
GET /api/jobs/summary
```

Response includes status counts, active count, failed count, stale count, stale job IDs, latest failed job, latest successful job, and retention policy values. It does not expose secrets.

## T10. Data Model / Migration

No schema migration was required. Existing `operation_jobs` timestamps and statuses support stale-job detection and cleanup.

## T11. Backend Plan / Changes

- Added retention config fields to `atdr/app/core/config.py`.
- Added stale detection, cleanup candidate listing, stale marking, terminal cleanup, and summary helpers to `atdr/app/services/job_service.py`.
- Added `OperationJobSummaryRead`.
- Added `/api/jobs/summary`.
- Added `atdr/scripts/maintenance_jobs.py`.

## T12. Frontend Plan / Changes

- Added `OperationJobSummary` type.
- Added `api.jobsSummary()` and `useJobsSummary()`.
- Added active/stale/latest failed job cards to Overview Operations Health.

## T13. Security / Response / AI Safety

- No response behavior changed.
- No automatic response was added.
- No real firewall blocking was added.
- No ML model activation or promotion was added.
- Maintenance does not touch raw evidence, alerts, labels, response actions, or audit logs.

## T14. Test Plan

- Operation job API summary test.
- Dry-run maintenance non-mutation test.
- Explicit stale marking test.
- Explicit terminal job cleanup test.
- Evidence protection assertions for raw logs and audit logs.

## T15. Implementation Summary

v3.7 provides operator-controlled job maintenance and dashboard health visibility using existing `operation_jobs` state. It keeps normal local workflow unchanged and does not add automatic data deletion.

## T16. Tests Run / Evidence

Verification evidence should be recorded in `docs/tasks/tasklist-progress.md` after final gate execution.

## T17. PRD / Docs Updated

Updated or added:

- `docs/V3_7_OPERATION_RETENTION_AND_JOB_RECOVERY.md`
- `docs/LAB_RUNBOOK.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

## T18. Risks / Blockers / Assumptions / Decisions

- Decision: no automatic cleanup on startup.
- Decision: cleanup applies only to terminal operation job history.
- Risk: true async queues are still future work.
- Risk: shared-lab scale should eventually validate PostgreSQL.

## T19. Release / Rollback

Rollback:

- Remove the job summary endpoint and maintenance script changes.
- Remove frontend job-summary cards.
- Keep existing `operation_jobs` table from v3.6 unless rolling back v3.6 too.

No destructive data migration is introduced by v3.7.

## T20. Final Handoff

ATDR now has safe operation-job maintenance groundwork. Operators can preview stale jobs and retention cleanup candidates, then explicitly mark stale jobs or delete old terminal job records. Raw evidence and audit history remain protected.
