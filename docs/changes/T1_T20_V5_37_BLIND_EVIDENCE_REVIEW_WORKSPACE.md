# T1-T20: v5.37 Blind Evidence Review Workspace

## T1 Change Title

v5.37 Blind Evidence Review and Assistant Acceptance Workspace.

## T2 Requirement

Allow authenticated genuine reviewers to complete the sealed detection and
Assistant human acceptance contracts through the React dashboard without
manually editing CSV files, weakening blindness, or causing authoritative
system changes.

## T3 Source Evidence

v5.26 prediction lock, v5.27 strict reviewer validator and guide, v5.28 review
helper, v5.33 protected Assistant acceptance service, v5.36 activation
coordinator, current FastAPI JWT/RBAC/audit implementation, React routing/API
patterns, and existing backend/Playwright test contracts.

## T4 Current Behavior

Before v5.37, reviewers had to edit or use a terminal helper against ignored
worksheets. Detection review was 0/40 and Assistant acceptance was 0/8. The
contracts were safe but not available as a normal analyst workflow.

## T5 Impacted Areas / Agents

Backend/API, frontend/dashboard, detection evidence custody, Assistant
acceptance, IAM/RBAC, audit, QA, documentation, and release governance.

## T6 Scope

Authenticated aggregate status, private session ownership, safe item views,
human decision forms, atomic save/resume, completion recording, auditing,
tests, runbooks, traceability, taskboard, and exact commit allowlist.

Training, label import, model artifact writes, activation, tuning, Gemini calls
during review, automatic response, and real blocking are out of scope.

## T7 Functional Requirements

- Reuse existing ignored v5.28/v5.33 files and validators.
- Expose only approved sanitized structured evidence.
- Keep predictions, scores, tokens, fingerprints, paths, IPs, raw logs, and
  hidden labels server-side.
- Require analyst/admin authentication, genuine human identity, compatible
  decisions, confidence/scores, rationale where required, and confirmation.
- Preserve owner isolation, revisions, immutable decisions, atomic writes, and
  fail-closed integrity.
- Audit lifecycle events without sensitive evidence.
- Return and test zero authoritative mutations.

## T8 Acceptance Criteria

An analyst can start, save, navigate, and resume both workspaces; a second
user sees aggregate progress only; malformed or changed packs fail closed;
saved decisions cannot be overwritten; all forbidden fields remain absent;
the page is responsive; and no label, model, detection, alert, provider, or
response side effect occurs.

## T9 API Contract

Authenticated routes under `/api/evidence-review` provide aggregate status,
workspace start, item read/save, and completion for `detection` and
`assistant`. Save and complete requests require an expected revision and
literal human confirmation. Responses explicitly report zero authoritative
mutations and no import, activation, or response action.

## T10 Data Model / Migration

No schema or migration change. Review content and workspace state remain in
ignored private files. Audit events use the existing `audit_logs` table.

## T11 Backend Plan / Changes

Add Pydantic request/response contracts, one evidence-review service that
adapts the existing validators, and an authenticated router with bounded audit
events. Convert contract errors into non-sensitive fail-closed responses.

## T12 Frontend Plan / Changes

Add `/evidence-review`, AI Governance navigation, typed API/query hooks, two
tabs, progress metrics, approved evidence presentation, explicit human forms,
save/resume navigation, completion controls, and clear owner/unavailable
states. Keep layouts responsive and avoid raw JSON.

## T13 Security / Response / AI Safety

No frozen prediction, model/rule score, expected label, token, fingerprint,
path, IP, raw log, secret, or hidden truth crosses the API boundary. Gemini is
not called. Decisions are not imported. Models are not changed. Rules remain
alert-authoritative. Response automation and real firewall blocking remain
disabled.

## T14 Test Plan

Test authentication, analyst/admin access, owner isolation, save/resume,
explicit confirmation, automated reviewer rejection, immutable decisions,
integrity mismatch, audit lifecycle, safe projections, zero authority count
deltas, frontend tabs/forms/empty states, and multi-viewport overflow.

## T15 Implementation Summary

Added the schemas, service, router, route registration, eight focused backend
tests, typed React API/query integration, a professional Evidence Review page,
navigation, and Playwright workflow/viewport coverage. No database migration
or runtime authority change was introduced.

## T16 Tests Run / Evidence

Targeted backend tests pass `8/8`. Ruff and compileall pass. The authoritative
release run passes `910` backend tests with `1` intentional skip; Alembic
reports no drift. React lint/build pass; Playwright passes `33` tests with `1`
live-source skip. Controlled detection passes `24/24`, layered validation
passes `288/288`, Assistant QA passes `20/20`, replay remains dry-run only,
performance reports no warnings, and the release gate returns `ok: true`.

## T17 PRD / Docs Updated

v5.37 status, this T1-T20 record, AI and lab runbooks, PRD, requirement
traceability, university compliance checklist, taskboard/HTML, and exact
commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

The private packs exist only on qualified reviewer machines and are ignored by
Git. One owner per workspace is intentionally conservative. File-backed state
is suitable for the current controlled review boundary, not distributed
multi-reviewer production operation. Genuine review, second-device evidence,
institutional provider approval, and preproduction acceptance remain external.

## T19 Release / Rollback

No commit or push is authorized here. Release requires separate approval of
the exact allowlist. Rollback removes the new router/service/schema, React
page/integration, tests, and docs; no data migration or model rollback exists.
Private completed decisions must never be deleted during source rollback.

## T20 Final Handoff

Open `/evidence-review` as a genuine analyst, complete the two workflows, and
rerun the existing v5.36 read-only decision only after all decisions validate.
An all-green evaluation would still require a separate explicit model
activation review. Response authority remains unchanged.
