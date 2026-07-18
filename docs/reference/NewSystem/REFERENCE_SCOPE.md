# NewSystem Reference Scope

Date: 2026-07-18

This directory preserves selected university-template evidence after the unused
in-repository NewSystem runtime copy was removed. It is reference material, not
ATDR runtime source and not the approved MFU companion-shell distribution.

## Authority Boundary

- Active ATDR runtime truth is under `atdr/`, `frontend/`, `migrations/`,
  `scripts/`, `config/`, `deploy/`, and `.github/workflows/`.
- Active ATDR process truth is `docs/ATDR_AI_WORKFLOW.md`,
  `docs/prd/PRD-ATDR.md`, `docs/tasks/tasklist-progress.md`, and the ATDR
  T1-T20 records.
- The versioned MFU companion shell is a separately distributed, checksum-locked
  package described by `docs/V4_6_VERSIONED_MFU_SHELL_DISTRIBUTION.md`.
- Files below may explain template concepts, but they do not make Node, Vue,
  MongoDB, or NewSystem part of ATDR.

## Preserved Material

- Template overview and environment guidance: `README.md`, `TEMPLATE.md`, and
  `ENVIRONMENTS.md`.
- Non-secret template manifests: `.iam-template.json` and
  `template.manifest.json`.
- IAM and security guidance: `backend-node/docs/IAM_PRD.md`,
  `IAM_RECOMMENDATIONS.md`, `IAM_SYSTEM_OVERVIEW.md`, and
  `OWASP_TOP10_REPORT.md`.
- Original workflow examples: `workflow/AI-WORKFLOW.md`,
  `workflow/PRD-NewSystem.md`, `workflow/T1-T20-change-document.md`, the
  `workflow/agents/` examples, and the historical workflow change record.

## Sanitization And Use

Two legacy high-entropy identifiers in archived IAM/security prose were
replaced with `<redacted-from-reference>`. No environment file, credential,
database, log, model artifact, generated report, or dependency tree was copied
into this archive.

Use these files only to understand university workflow, IAM, permission, audit,
and documentation patterns. New ATDR work must cite current ATDR source and
active ATDR documents.
