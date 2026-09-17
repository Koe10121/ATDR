# T1-T20: v5.63 Fresh Comparable Evidence Expansion

## T1 Change Title

- Title: Fresh Comparable Evidence Expansion and Second-Source Intake Readiness
- Date: 2026-09-17
- Owner / acting agent: Codex under project-owner direction
- Related version or sprint: v5.63

## T2 Requirement

Expand the prediction-blind supervised campaign to the fixed 1,000-row
capacity while preserving v5.62 custody, keeping evaluation evidence sealed,
and refusing every model operation.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| Original boundary | immutable v5.62 protocol, sealed/working packs, roles, and fixed gates |
| Consumed boundary | immutable v5.49b exclusion lineage retained by v5.62 |
| Private source | PAN-OS input supplied only through guarded CLI |
| Runtime authority | v5.58 rules-authoritative hybrid contract and v5.61 anomaly contract |
| UI/API | authenticated Evidence Review workspace and owner-isolated batch service |

## T4 Current Behavior

v5.62 provides 300 prediction-blind rows but cannot meet the fixed 1,000-row
comparable-evidence gate. One real physical source exists. Supervised runtime
is unqualified and no candidate is active.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Evidence | append-only 700-row supplemental pack and private custody records |
| Backend | campaign module, guarded CLI, review service, schemas, API |
| Frontend | seven-batch protected review and aggregate qualification status |
| ML | no fit/evaluation; fixed development and qualification contracts only |
| Database | read-only aggregate guards; zero authoritative writes |
| Governance | status, runbook, traceability, compliance, taskboard, allowlist |

## T6 Scope

In scope: append-only preservation, fresh selection, duplicate isolation,
development-only roles, protected batches, second-source preflight, aggregate
gates, tests, docs, and verification. Out of scope: automatic labels,
training, evaluation, candidate freeze, activation, promotion, and response
authority.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-563-01 | Preserve all 300 original rows and roles exactly | Must |
| FR-563-02 | Select at least 700 non-overlapping unique families | Must |
| FR-563-03 | Select development-safe chronological roles only | Must |
| FR-563-04 | Provide owner-isolated resumable 100-row batches | Must |
| FR-563-05 | Make each closed batch immutable | Must |
| FR-563-06 | Reject same-device second-source evidence | Must |
| FR-563-07 | Keep evaluation labels inaccessible | Must |
| FR-563-08 | Preserve fixed gates and zero authoritative writes | Must |

## T8 Acceptance Criteria

The system must produce exactly 700 supplemental rows, reach 1,000 selected
capacity, select zero original overlaps and zero future-evaluation rows,
expose only aggregates, support protected batch review, fail closed for a
non-independent source, and create no label/model/detection/alert/response
writes.

## T9 API Contract

Authenticated endpoints under
`/api/evidence-review/supervised-qualification/expansion` expose aggregate
status and batch status/start/list/item/save/close operations. Responses hide
raw logs, addresses, identities, fingerprints, tokens, reviewer identities,
predictions, scores, suggestions, paths, digests, and secrets.

## T10 Data Model / Migration

No application schema or migration change. Protected state is private ignored
evidence. Each batch stores private ownership, revision, and closure metadata.

## T11 Backend Plan / Changes

Add append-only protocol validation, deterministic supplemental selection,
private custody, safe second-source preflight, guarded CLI, per-batch review
service, API schemas/routes, and development loader that refuses early access.

## T12 Frontend Plan / Changes

Add a compact expansion panel to Supervised Qualification showing 300+700
capacity, source/time gates, seven batches, protected evidence, validated
human decisions, closure, and explicit unqualified/no-training wording.

## T13 Security / Response / AI Safety

- Use private paths only as CLI arguments.
- Keep every generated pack and custody value ignored.
- Never expose predictions or generate human labels automatically.
- Never add a candidate source during preflight.
- Keep rules authoritative and response `simulation_only`.

## T14 Test Plan

Cover original-pack byte preservation, overlap and duplicate rejection,
future-role exclusion, unchanged gates, auth, owner isolation, stale revisions,
automated-reviewer rejection, immutable batch closure, early label-access
refusal, source independence, redaction, artifact stability, and zero writes.

## T15 Implementation Summary

Disposable processing parsed 773,551 rows with zero failures and selected 700
unique development-safe rows from 220,547 eligible families. The final roles
are 411 development-fit, 165 calibration, and 124 threshold-selection across
seven 100-row batches and seven coverage groups. Original overlap and added
future-evaluation rows are both zero.

## T16 Tests Run / Evidence

Focused backend tests pass `6/6`; full backend tests pass `1114 passed, 1
skipped`, including a second successful run inside the release gate. React
lint/build pass and Playwright passes `45 passed, 1 skipped`. Alembic reports
no drift; the controlled source scenario parses `10/10`; layered detection
passes `288/288`; Assistant QA passes 30 quality cases and the follow-up
sequence; hybrid safety, replay dry-run, repository/security audits,
performance smoke, release gate, and taskboard checks pass. Performance smoke
has no warnings (`0.8425s` cold Overview, `0.0105s` cached Overview), and the
tracked-source security scan finds zero findings across 1,441 text paths.

## T17 PRD / Docs Updated

v5.63 status, current AI/ML and system locks, training runbook, PRD,
traceability, compliance checklist, docs index, taskboard, HTML board, and an
exact cumulative commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The evidence capacity is 1,000 but reviewed support is `0/1,000`; capacity is
not qualification. Only one real physical source exists. A second device and
genuine independent review remain external blockers.

## T19 Release / Rollback

Runtime startup, alert authority, and response behavior do not change. Remove
only an unstarted ignored v5.63 workspace to abandon it; never overwrite a
started or closed review. No database rollback is required.

## T20 Final Handoff

Complete the 300 original decisions and seven supplemental batches, then
preflight a second real source. v5.64 Reviewed Development Evidence Lock and
Candidate Repair may run development-only fitting and freeze at most one
diagnostic candidate only after every input gate passes. Three substantial
supervised phases then remain: v5.64 development repair/freeze, v5.65 one-shot
blind validation, and v5.66 shadow-runtime qualification/activation decision.
No commit or push is authorized by this record.
