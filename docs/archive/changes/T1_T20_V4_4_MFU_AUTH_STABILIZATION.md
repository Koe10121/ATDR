# T1-T20: v4.4 MFU Authentication And Shell Integration Stabilization

## T1 Change Title

- Title: v4.4 MFU Authentication And Shell Integration Stabilization
- Date: 2026-07-15
- Owner: ATDR team / Codex
- Version: v4.4

## T2 Requirement

Make the approved MFU shell a reliable, fail-closed normal entry into ATDR, remove an unapproved legacy Google client fallback, preserve explicit local recovery, and state exact external provider requirements.

## T3 Source Evidence

| Source | Finding |
| --- | --- |
| `scripts/setup_team.ps1`, `scripts/start_system.ps1`, `scripts/check_system.ps1` | Portable four-service lifecycle existed but Google frontend/backend agreement was not a blocking preflight. |
| Approved shell `frontend-vue/src/main.js` | Empty `VUE_APP_CLIENTID` fell back to a hardcoded Google client. |
| Approved shell `backend-node/server/Project/accounts/service/account.js` | Empty `GOOGLE_CLIENT_ID` also fell back to the same legacy audience. |
| Approved shell private environment | Both environment-specific client-ID fields were unconfigured; values were not printed. |
| `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` | One-time code, exact origin, server exchange, HttpOnly cookie, analyst default, explicit admin-group mapping, and audit already existed. |
| Google browser result | `400 invalid_request` / account policy denial occurred before ATDR handoff. |

## T4 Current Behavior

The shell is the normal entry and ATDR rejects direct local login outside explicit recovery. Google configuration now fails closed. Handoff failures are specific but non-secret. No detection, ML, response, or database behavior changed.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Backend / API | Safe handoff error codes and audits |
| Frontend / Dashboard | Actionable login messages and corrected admin wording |
| Security / IAM | Matching private client requirement and legacy-fallback removal |
| Release / Ops | Setup/start/check provider preflight |
| QA | OAuth configuration, handoff, recovery, and secret-hiding tests |

## T6 Scope

In scope: MFU shell Google configuration, one-time handoff UX/security, portable startup, tests, and docs. Out of scope: direct ATDR OAuth, provider credential creation, database reset, detection/ML changes, automatic response, and real firewall blocking.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| V44-01 | Require matching private frontend/backend Google client IDs | Must |
| V44-02 | Remove legacy source fallbacks | Must |
| V44-03 | Keep local recovery explicit | Must |
| V44-04 | Reject unsafe handoffs and show safe actionable errors | Must |
| V44-05 | Preserve analyst default and explicit admin-group mapping | Must |
| V44-06 | Never display credentials or provider payloads | Must |

## T8 Acceptance Criteria

- Doctor reports missing, mismatched, legacy, or ready state without values.
- Setup/start refuse incomplete Google configuration.
- Approved source contains no fallback client ID.
- Expired/replayed, wrong-origin, disallowed-domain, disabled, and conflicting identities are rejected.
- Local recovery works only when selected explicitly.
- A real approved MFU login reaches `/overview` before provider acceptance is claimed.

## T9 API Contract

Existing endpoints remain. `POST /api/auth/mfu-iam/handoff/consume` still redirects, but `handoff_error` now uses a fixed safe code. No token, code, email, or provider response is added to redirects.

## T10 Data Model / Migration

No schema or migration change. Existing users and data are preserved.

## T11 Backend Plan / Changes

Add safe template configuration inspection/hardening, typed handoff failure codes, secret-free audit reasons, and startup checks.

## T12 Frontend Plan / Changes

Map safe handoff codes to concise operator messages. Correct Admin wording so local login is described as explicit recovery only.

## T13 Security / Response / AI Safety

- HttpOnly one-time handoff retained.
- No browser token handoff restored.
- Secrets and client values are not returned.
- New school identities default to analyst.
- Automatic response and real blocking remain disabled.
- ML behavior and activation state are unchanged.

## T14 Test Plan

Run focused IAM/config tests, shell Node handoff tests, full backend tests, Alembic check, React lint/build, Playwright, lifecycle preflight, and release gate.

## T15 Implementation Summary

| File | Summary |
| --- | --- |
| `atdr/app/services/template_shell_auth.py` | Secret-free configuration status |
| `atdr/scripts/template_auth_doctor.py` | Teammate-safe doctor |
| `atdr/scripts/harden_template_google_auth.py` | Idempotent fallback removal with ignored backup |
| `atdr/app/services/template_bridge_contract.py`, `atdr/scripts/validate_template_shell_runtime.py` | Accurate composed-route contract evidence and state-aware operator guidance |
| `scripts/*.ps1` | Fail-closed setup/start/check lifecycle |
| `atdr/app/services/mfu_iam_service.py`, `atdr/app/routers/auth.py` | Safe handoff failure classification |
| `frontend/src/pages/LoginPage.tsx`, `frontend/src/pages/UserAdmin.tsx` | Actionable UX and accurate recovery wording |
| `atdr/tests/test_v44_mfu_auth_stabilization.py` | v4.4 regression coverage |

## T16 Tests Run / Evidence

- Task-board render/check: passed.
- Ruff and compileall: passed.
- Focused v4.4/MFU/handoff tests: `19 passed`.
- Bridge/runtime contract tests after the composed-route repair: `10 passed`.
- Full backend: `584 passed, 1 skipped`; the skip is hardware-dependent.
- Alembic: no drift at `b4c5d6e7f8a9`.
- React lint/build: passed; Playwright `24 passed, 1 skipped`.
- External Vue production build: passed; Node handoff tests `3 passed`.
- Replay dry-run: two safe rows parsed, zero writes.
- Performance smoke: `ok: true`; cached Overview `0.0093s`; cold large-SQLite warnings retained.
- Release gate: `ok: true`, no failed required checks, repeated backend `584 passed, 1 skipped`.
- Provider preflight: expected fail-closed result `frontend_client_not_configured`; no value exposed.

## T17 PRD / Docs Updated

v4.4 status, quickstart, IAM validation, PRD/traceability/compliance, task board, README, and this change record are updated.

## T18 Risks / Blockers / Assumptions / Decisions

- External blocker: an authorized MFU/Google administrator must approve and deliver the OAuth Web client ID and account policy.
- Any administrator credential previously disclosed outside the approved secret channel must be revoked and rotated before shared deployment.
- Real login cannot be proven with placeholder or legacy credentials.
- Decision: fail closed instead of silently using a fallback.
- Decision: no direct ATDR Google flow; the approved shell continues to own login and 2FA.

## T19 Release / Rollback

Run setup after private configuration, then start/check. Stop launcher processes for rollback. Source backups are ignored under `.atdr_runtime`; no database rollback is needed.

## T20 Final Handoff

Status: locally implemented and fully verified; provider acceptance remains externally blocked. The next operator action is to rotate any administrator credential exposed outside the approved channel, obtain the approved OAuth Web client, configure both ignored shell fields identically, run the doctor, then execute one real MFU login acceptance test through React `/overview`.
