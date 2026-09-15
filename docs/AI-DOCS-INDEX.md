# ATDR Documentation Index

Use this page to find current ATDR instructions. Documents under
`docs/archive/` preserve implementation history and are not active operating
guidance. Documents under `docs/reference/` are university/template references
and do not define ATDR's runtime stack.

## Start And Operate

| Document | Purpose |
| --- | --- |
| `README.md` | Product boundary, architecture, setup, startup, and current status |
| `docs/QUICKSTART_FOR_TEAM.md` | Fresh-machine shell-first installation |
| `docs/OPERATIONS_RUNBOOK.md` | Daily operations, recovery, backup, and shared-host guidance |
| `docs/LAB_RUNBOOK.md` | Import, syslog, detection, Assistant, and local validation workflow |
| `docs/RELEASE_CHECKLIST.md` | Local release and safety verification |
| `docs/ENVIRONMENT_GUIDE.md` | Configuration profiles and validation |
| `docs/DEPLOYMENT_GUIDE.md` | Local, teammate, and shared PostgreSQL deployment boundaries |
| `docs/EXTERNAL_ACCEPTANCE.md` | Evidence required from university, provider, hardware, and host owners |

## Product And Governance

| Document | Purpose |
| --- | --- |
| `docs/CURRENT_SYSTEM_STATE_LOCK.md` | Current product truth and readiness boundary |
| `docs/CURRENT_AI_ML_PRODUCT_STATUS.md` | Current detection, model, and Assistant authority |
| `docs/V5_60_CLEAN_MACHINE_RELEASE_CANDIDATE_ACCEPTANCE.md` | Current clean-clone setup, lifecycle, workflow, and safety evidence |
| `docs/prd/PRD-ATDR.md` | Current product requirements |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Requirement-to-source/test mapping |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | Active university workflow and safety checklist |
| `docs/ATDR_AI_WORKFLOW.md` | Engineering, evidence, and AI governance process |
| `docs/tasks/tasklist-progress.md` | Current task, verification, blockers, and next action |

## Detection And AI

| Document | Purpose |
| --- | --- |
| `docs/DETECTION_RULE_CATALOG.md` | Active deterministic rule intent, evidence, and analyst guidance |
| `docs/AI_TRAINING_RUNBOOK.md` | Label integrity, supervised qualification, anomaly, and Assistant governance |
| `docs/detection/` | Active field, evidence, schema, and frozen-protocol contracts |
| `docs/security/ATDR_DETECTION_RULE_STANDARD.md` | Rule quality and safety standard |
| `docs/security/ATDR_DETECTION_LABELING_POLICY.md` | Label provenance and decision policy |

## Security, IAM, And Deployment

| Location | Purpose |
| --- | --- |
| `docs/security/` | IAM, RBAC, external provider, and security contracts |
| `deploy/` | Versioned shared-host, proxy, worker, monitoring, and recovery assets |
| `.env.shell.example` | Normal shell-first profile without secrets |
| `.env.example` | Explicit local-recovery/development profile |
| `.env.lab.example` | Optional PostgreSQL lab profile |
| `.env.production.example` | Fail-closed shared-host reference |

## Presentation And History

- `docs/PRESENTATION_BRIEF.md` is the single current demonstration summary.
- `docs/archive/README.md` explains the preserved history.
- `docs/archive/V5_59_ARCHIVE_MANIFEST.md` records the archive mapping.
- Four root-level v3 citation files are small compatibility pointers retained
  for stable Assistant response contracts; their full records remain archived.
- `docs/reference/NewSystem/REFERENCE_SCOPE.md` defines the selected sanitized
  NewSystem reference boundary.

## Change Rules

Non-trivial work updates the active taskboard and a T1-T20 record. Product or
behavior changes also update the PRD, traceability, compliance, and current
state locks as applicable. Do not edit archived records to match newer
behavior, and do not commit or push without separate explicit approval.

The complete pre-v5.59 index is retained at
`docs/archive/indexes/AI-DOCS-INDEX_THROUGH_V5_58.md`.
