# v5.59 Archive Manifest

Date: 2026-09-14

## Classification Result

| Class | Count | Destination |
| --- | ---: | --- |
| Historical commit allowlists | 70 | `docs/archive/allowlists/` |
| Historical version phases | 207 | `docs/archive/phases/` |
| Historical T1-T20 records | 163 | `docs/archive/changes/` |
| Presentation artifacts | 29 | `docs/archive/presentations/` |
| Superseded planning/guidance | 18 | `docs/archive/legacy/` |
| Governance snapshots | 4 | `docs/archive/governance/` |
| Runbook snapshots | 3 | `docs/archive/runbooks/` |
| Index snapshot | 1 | `docs/archive/indexes/` |
| Taskboard/workflow snapshots | 2 | `docs/archive/tasks/` |
| **Total moved** | **497** | Preserved in Git |

## Deterministic Mapping

- `docs/*_COMMIT_ALLOWLIST.md` moved to `docs/archive/allowlists/` with the same
  basename.
- The two historical v3.94/v3.95 text-form release path lists moved to
  `docs/archive/allowlists/` with the same basename.
- Superseded root `docs/V*.md` and `docs/v*.md` moved to
  `docs/archive/phases/` with the same basename.
- `docs/changes/*.md` moved to `docs/archive/changes/` with the same basename.
- Superseded presentation files moved to `docs/archive/presentations/` with the
  same basename.
- Superseded unversioned plans and duplicate startup guidance moved to
  `docs/archive/legacy/` with the same basename.

The large PRD, traceability, compliance, AI workflow, AI index, lab runbook, AI
runbook, release checklist, taskboard, and taskboard guide use explicit
`*_THROUGH_V5_58` snapshot names. Concise current documents now occupy their
stable canonical paths.

## Removal Decision

No source module, wrapper, migration, test, or historical record was deleted.
The generated taskboard HTML was regenerated from the compact active Markdown
instead of archiving a duplicate rendered copy. All baseline ATDR Python CLIs
were retained because static/dynamic references or executable compatibility
entry points still justify them.
