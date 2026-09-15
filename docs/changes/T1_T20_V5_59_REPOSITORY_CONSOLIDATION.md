# T1-T20: v5.59 Repository Consolidation

## T1 Change Title

- Title: Repository Consolidation and Final Documentation Lock
- Date: 2026-09-14
- Owner / acting agent: Codex under project-owner direction
- Related version or sprint: v5.59

## T2 Requirement

- User request: reduce accumulated documentation, historical scripts, and
  generated surface without losing audit history or runtime compatibility.
- Business / lab goal: leave one professional current documentation surface.
- Success outcome: dependency-led classification, intact archive, concise
  canonical docs, zero broken links/commands/imports, full verification.
- Explicit non-goals: no runtime, data, model, IAM, Assistant, API, schema,
  startup, alert-authority, or response change.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Product truth | `README.md`, `docs/CURRENT_SYSTEM_STATE_LOCK.md` | v5.58 controlled local release candidate |
| AI/ML truth | `docs/CURRENT_AI_ML_PRODUCT_STATUS.md` | rules authoritative; supervised unqualified |
| Runtime | `atdr/app/`, `frontend/src/` | no behavior changes required |
| History | root `docs/V*.md`, `docs/changes/` | hundreds of superseded active-surface records |
| Operator docs | quickstart and runbooks | duplicated historical commands and status narratives |
| Verification | tests, CI, scripts, migrations | compatibility callers must remain intact |

## T4 Current Behavior

- Backend, frontend, database, AI/ML, IAM, and response behavior are unchanged.
- The repository previously exposed historical phase documents beside current
  operator guidance, making current truth harder to identify.
- All protected evidence and consumed evaluation state remain untouched.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | inventory and archive coordination |
| Product/requirements | yes | concise PRD and truth lock |
| Data model/database | no | no schema or data access change |
| Backend/API | audit tooling only | read-only repository utilities |
| Frontend/dashboard | no runtime change | generated taskboard HTML only |
| AI/ML governance | docs only | authority and evidence boundaries retained |
| Security/response | docs/tests only | invariants retained |
| QA/UAT | yes | complete non-regression matrix |
| Release/ops | yes | canonical runbooks and exact allowlist |

## T6 Scope

### In Scope

- Markdown and Python dependency/reference graphs.
- Archive, canonical docs, taskboard, safe cache preview, tests, and verification.

### Out Of Scope

- Runtime feature changes, data mutation, model activation, automatic response,
  real blocking, or production-readiness claims.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-559-01 | Classify every documentation/script candidate | Must | v5.59 plan |
| FR-559-02 | Preserve historical records unchanged | Must | v5.59 plan |
| FR-559-03 | Maintain a concise canonical documentation set | Must | user goal |
| FR-559-04 | Detect broken links, imports, and commands | Must | acceptance gates |
| FR-559-05 | Preserve compatibility interfaces | Must | runtime safety |
| FR-559-06 | Offer tightly scoped dry-run cache cleanup | Should | repository hygiene |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-01 | Clean synchronized v5.58 starting point | Git branch/status/revision |
| AC-02 | All archived blobs unchanged | Git object hash comparison |
| AC-03 | Zero active link/command/import failures | repository surface CLI |
| AC-04 | No unsupported script deletion | machine-readable classifications |
| AC-05 | Full product regression remains green | complete matrix |
| AC-06 | Safety states unchanged | v5.58 runtime and release checks |

## T9 API Contract

- New endpoints: none.
- Changed endpoints: none.
- Auth/RBAC and backward compatibility: unchanged.

## T10 Data Model / Migration

- Schema, Alembic, indexes, and existing data: unchanged.
- No migration is needed because v5.59 affects repository organization and
  read-only developer tooling only.

## T11 Backend Plan / Changes

- Add read-only repository graph/audit service and CLI.
- Add allowlisted dry-run-first cache cleanup service and CLI.
- Add focused tests; no router, schema, job registry, or audit-event change.

## T12 Frontend Plan / Changes

- No React route, component, API, state, or interaction behavior changed.
- Regenerate the required static taskboard HTML from compact Markdown.

## T13 Security / Response / AI Safety

- Response remains simulation: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Supervised decision support: unqualified and fail closed.
- Labels/protected evidence: not accessed or modified.
- Repository utilities expose no secret values or private evidence.
- Security reviewer decision: pass; the repository scan found zero
  tracked-secret findings and runtime safety states are unchanged.

## T14 Test Plan

Run taskboard, focused utility, Ruff, compileall, full backend, Alembic,
frontend lint/build/Playwright, detection, Assistant, security, performance,
release, repository graph, archive-integrity, diff, and hygiene checks.

## T15 Implementation Summary

| Area | Change Summary |
| --- | --- |
| Archive | historical docs moved into named immutable categories |
| Canonical docs | current runbooks, PRD, governance, taskboard, index, and presentation brief |
| Audit | Markdown, command, AST/import, entry-point, and surface inventory |
| Cleanup | confirmation-gated allowlisted disposable cache utility |
| Runtime | unchanged |

## T16 Tests Run / Evidence

The complete local matrix passed: Ruff, compileall, 1,084 backend tests with one
skip, Alembic, frontend lint/build, 42 Playwright tests with one live skip, a
disposable source scenario, 288/288 layered runs, 30/30 Assistant QA cases,
security acceptance, replay dry-run, performance smoke, repository graph, and
release gate. Archive integrity is 497/497 exact blobs. No authoritative
Assistant, model, alert, response, label, or protected-evidence side effect was
introduced.

## T17 PRD / Docs Updated

PRD, workflow, lab/AI/release runbooks, state locks, traceability, compliance,
index, taskboard, archive manifest, README, and presentation brief are updated.

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Archived instructions can be stale; the archive banner points operators to
  the active index.

### Blockers

- External acceptance tracks remain owner-backed and outside v5.59.

### Assumptions

- Git history and byte-identical archive copies satisfy historical audit needs.

### Decisions

- Retain every script with a compatibility role; delete no runtime module.
- Replace generated taskboard HTML instead of archiving duplicate output.

## T19 Release / Rollback

- Release impact: documentation organization and developer audit tools only.
- Local workflow: startup commands unchanged.
- Rollback: revert the future v5.59 commit; no data rollback is required.
- Publication requires a separately approved exact path allowlist.

## T20 Final Handoff

- Status: complete locally; publication remains separately approval-gated.
- Behavior changed: no.
- Remaining risks: owner-backed external acceptance only.
- Exact next action: review the v5.59 exact allowlist and request separate
  staging/commit/push approval if publication is desired.
