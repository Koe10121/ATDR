# T1-T20: v5.62 Supervised ML Qualification Campaign

## T1 Change Title

- Title: Supervised ML Qualification Campaign and Fresh Evidence Lock
- Date: 2026-09-16
- Owner / acting agent: Codex under project-owner direction
- Related version or sprint: v5.62

## T2 Requirement

Prepare fresh prediction-blind evidence, protected review, safe aggregate
status, and development-only repair preflight without reusing the consumed
v5.49b evaluation or granting supervised authority.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| Consumed boundary | Immutable v5.49b result, review packs, and at-most-once claim |
| Runtime authority | v5.58 governed hybrid runtime and v5.61 anomaly contract |
| Fresh source | Private PAN-OS input supplied only through guarded CLI |
| Model contracts | Eight v5.48 strategies, 40-feature schema, and fixed v5.30 gates |
| UI and API | Evidence Review page, authenticated router, protected owner service |

## T4 Current Behavior

Supervised runtime is `unqualified`, v5.49b selected no candidate, and its
evaluation cannot be reused. No fresh immutable qualification campaign or
current protected review workspace existed before v5.62.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Evidence | private consumed-exclusion manifest and fresh chronological pack |
| Backend | campaign, guarded CLI, protected review service, schemas, API |
| Frontend | supervised qualification review tab and fail-closed gate status |
| ML | development-only preflight; no fit, evaluation, freeze, or activation |
| Database | read-only aggregate checks; no authoritative writes |
| Governance | current status, runbook, traceability, compliance, taskboard |

## T6 Scope

In scope: immutable exclusion, disposable private inspection, predeclared
roles, protected review, aggregate status, fixed-gate reporting, development
repair readiness, tests, and governance. Out of scope: completing human
review, training, evaluation, candidate selection, activation, promotion, and
response authority.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-562-01 | Reject all consumed v5.49b overlap | Must |
| FR-562-02 | Assign chronological roles before labels | Must |
| FR-562-03 | Keep duplicate families within one role | Must |
| FR-562-04 | Provide owner-isolated prediction-blind review | Must |
| FR-562-05 | Seal future evaluation labels from development code | Must |
| FR-562-06 | Preserve every fixed qualification gate | Must |
| FR-562-07 | Refuse training while support is insufficient | Must |
| FR-562-08 | Expose safe aggregate status only | Must |

## T8 Acceptance Criteria

The campaign parses in disposable storage, rejects overlap, locks roles and
protocol, creates a protected review pack, keeps all sensitive material
private, exposes honest pass/fail/blocked gates, supports genuine review, and
produces zero label, model, detection, alert, suppression, or response writes.

## T9 API Contract

Add authenticated aggregate campaign status and protected review status,
start, list, item, save, and close endpoints under
`/api/evidence-review/supervised-qualification`. Responses return no raw logs,
addresses, identities, fingerprints, reviewer identities, predictions, model
scores, suggestions, private paths, or secrets.

## T10 Data Model / Migration

No schema or migration change. Protected campaign state is private ignored
evidence; authoritative application labels are not created.

## T11 Backend Plan / Changes

Add the v5.62 campaign module, CLI, review service, API schemas/routes,
development-only loader, and repair preflight. Bind state to the immutable
protocol and reject edits after closure.

## T12 Frontend Plan / Changes

Add a Supervised Qualification workspace with campaign custody, source/time
gates, review progress, filters, approved evidence, validated human decisions,
immutable closure, and explicit unqualified/rules-authoritative wording.

## T13 Security / Response / AI Safety

- Use private paths only through CLI arguments.
- Keep raw logs, addresses, identities, fingerprints, and reviews ignored.
- Never auto-label, train early, evaluate future labels, or activate a model.
- Keep rules authoritative and response `simulation_only`.
- Keep automatic response and real firewall blocking disabled.

## T14 Test Plan

Cover overlap rejection, duplicate and temporal locks, unchanged gates,
authentication, owner isolation, redaction, revision conflicts, automated
reviewer rejection, immutable closure, development/evaluation separation,
second-source failure, no artifact changes, and zero authoritative writes.

## T15 Implementation Summary

The guarded campaign processed 773,551 records with zero parser failures,
identified 298,963 fresh eligible rows, rejected 228 overlapping event rows,
contained 52,881 near duplicates, found 19 chronological windows and one real
source, and sealed 300 review rows across 150/60/45/45 roles.

## T16 Tests Run / Evidence

Focused backend tests pass `6/6`. Full backend tests pass `1108 passed, 1
skipped`; React lint/build pass; Playwright passes `44 passed, 1 skipped`;
Alembic reports no drift; controlled source and layered detection pass (`10/10`
parsed and `288/288` mode runs); Assistant QA passes 30 quality cases and its
follow-up sequence; hybrid safety, replay dry-run, repository/security audits,
performance smoke, release gate, taskboard checks, and diff hygiene pass. The
cold Overview path has one non-failing `1.1947s` warning; its cached path is
`0.0150s`.

## T17 PRD / Docs Updated

v5.62 status, current AI/ML and system locks, training runbook, traceability,
compliance checklist, documentation index, taskboard, HTML board, and exact
23-path allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Only one physical source exists. Current review is `0/300`, and 300 rows alone
cannot satisfy the fixed 1,000-row comparable-evidence gate. The campaign is a
development foundation, not qualification evidence by itself.

## T19 Release / Rollback

Runtime behavior and startup commands do not change. Remove only the ignored
v5.62 generated workspace to abandon an unstarted campaign; never overwrite a
started or closed review. No database rollback is required.

## T20 Final Handoff

Complete all 300 genuine human decisions, acquire additional fresh comparable
rows and a second source, then run a separately governed development-repair
phase. No commit or push is authorized by this record.
