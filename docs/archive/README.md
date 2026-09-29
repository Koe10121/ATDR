# ATDR Documentation Archive

This directory preserves superseded ATDR implementation and university-process
evidence. Archived files are immutable historical records, not current
operating instructions.

Use `docs/AI-DOCS-INDEX.md` for active guidance.

## Layout

| Directory | Contents |
| --- | --- |
| `allowlists/` | Historical approval-gated commit boundaries |
| `changes/` | Historical T1-T20 implementation records |
| `phases/` | Versioned phase status, plans, manifests, and reports |
| `presentations/` | Superseded demo, defense, and weekly presentation material |
| `legacy/` | Superseded planning, bootstrap, template-comparison, and duplicate guidance |
| `governance/` | Full pre-v5.59 PRD, workflow, traceability, and compliance ledgers |
| `runbooks/` | Full pre-v5.59 lab, AI, release, and related operating histories |
| `indexes/` | Full pre-v5.59 documentation index |
| `tasks/` | Full pre-v5.59 taskboard and workflow guide |

## Rules

- Do not use an archived command until an active runbook confirms it.
- Do not edit archived claims to match newer behavior.
- Do not interpret an archived model result as current activation authority.
- Use Git history and the original archived allowlist together for release
  authorization context.
- `docs/reference/` is separate: it contains sanitized university/template
  reference material rather than ATDR implementation history.

The archive operation moved records within Git and did not delete their
contents. See `docs/archive/V5_59_ARCHIVE_MANIFEST.md` for the mapping.

## 29 September 2026 move

After the improvement phase, the v5.59-v5.64 round records moved from `docs/`
into `phases/`, their commit allowlists into `allowlists/`, the two
`SYSTEM_DEEP_ANALYSIS` audit plans into `legacy/`, and the former
`CURRENT_SYSTEM_STATE_LOCK.md` and `CURRENT_AI_ML_PRODUCT_STATUS.md` (last
current on 19 September 2026) into `phases/`. Their contents are unchanged.
Current figures are in `docs/EVIDENCE_SUMMARY.md`.
