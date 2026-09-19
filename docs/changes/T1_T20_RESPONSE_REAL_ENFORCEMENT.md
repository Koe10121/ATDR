# T1-T20: Real Host-Scoped Response Enforcement (Windows Firewall)

## T1 Change Title

- Title: Real, opt-in, host-scoped IP block/timeout enforcement via Windows
  Firewall
- Date: 2026-09-19
- Owner / acting agent: Claude (Sonnet 5) under project-owner direction
- Related phase: none assigned; a version number and commit boundary are for
  the project owner to assign alongside the v5.64 and rule-engine-fix work
  already sitting in this working tree.

## T2 Requirement

The project owner asked for the dashboard's block/unblock workflow — until
now fully simulated — to be able to genuinely block or time out an IP,
explicitly choosing real host-level enforcement (Windows Firewall on the
machine running the ATDR backend) over a real network-firewall connector or a
purely-polished simulation, after being shown exactly what already existed.

## T3 Source Evidence

Direct reading of `atdr/app/services/response_service.py`,
`atdr/app/routers/response.py`, `atdr/app/schemas/response.py`,
`atdr/app/db/models.py` (`BlockedIP`, `ResponseAction`),
`frontend/src/pages/ResponseCenter.tsx`, `atdr/app/core/config.py`
(`response_simulation`, `response_provider`, and their existing
`validate_runtime_settings` gates, which already anticipated a pluggable
provider), and `atdr/tests/test_response_safety.py`.

## T4 Current Behavior (before this change)

Block/unblock already had a complete, well-designed simulated workflow:
admin-only, justification required, protected-range denial (RFC1918/
loopback/link-local), evidence-linked, fully audited. `RESPONSE_PROVIDER`
already existed as a config string with a "pending_connector" fallback for
any non-"simulation" value, but no connector was ever implemented — the
fallback was a no-op recording intent only. No timeout/expiry field existed.

## T5 Impacted Areas / Agents

`atdr/app/services/response_service.py` (rewritten enforcement dispatch),
new `atdr/app/services/windows_firewall_connector.py`,
`atdr/app/db/models.py` (`BlockedIP.enforcement`, `BlockedIP.expires_at`,
`ResponseAction.enforcement`), new migration
`c3d4e5f6a7b8_add_response_enforcement_and_expiry`, `atdr/app/core/config.py`
(`RESPONSE_MAX_BLOCK_MINUTES`, `windows_firewall` provider validation),
`atdr/app/schemas/response.py`, `atdr/app/routers/response.py`,
`atdr/app/main.py` (`/health` `response_mode`), `frontend/src/pages/ResponseCenter.tsx`,
`frontend/src/types/api.ts`, `frontend/src/lib/api.ts`,
`frontend/src/hooks/useApiQueries.ts`, `frontend/src/components/Badge.tsx`.

## T6 Scope

In scope: a single real connector (host-level Windows Firewall, IP-based),
opt-in via two existing config keys plus one new one, timeout/expiry for both
simulated and real blocks, dashboard UX reflecting real vs. simulated state
accurately. Out of scope (explicitly, not attempted): any real network/
perimeter firewall connector, any device/MAC/NAC-level quarantine, any
change to the default configuration of any shipped profile, any change to
detection/alert authority.

## T7 Functional Requirements

- Real enforcement is off by default in every shipped profile
  (`RESPONSE_SIMULATION=true`, `RESPONSE_PROVIDER=simulation` unchanged in
  every `.env*.example`).
- Enabling it requires an explicit two-key change
  (`RESPONSE_SIMULATION=false`, `RESPONSE_PROVIDER=windows_firewall`) and is
  refused by startup validation when `ENVIRONMENT=production` or the backend
  is not running on Windows.
- A block/unblock command is built from an explicit argument list, never a
  shell string, so a target IP can never inject additional commands.
- A block is only ever recorded as `active`/`enforced` in the dashboard when
  the real firewall rule genuinely applied; a failed enforcement (e.g.
  missing Administrator privileges) is surfaced as `enforcement_failed` and
  the IP is not marked blocked.
- An unblock that fails to remove a real rule never marks the row inactive —
  the dashboard must never claim an IP is unblocked while it is still
  genuinely blocked.
- The ATDR backend host's own address(es) are always protected from being
  blocked, in addition to the existing RFC1918/loopback/link-local
  protection.
- A block may include a timeout (`duration_minutes`, capped by
  `RESPONSE_MAX_BLOCK_MINUTES`, default 1440); expired blocks are swept
  (and, for real enforcement, their firewall rule removed) lazily on every
  list/block/unblock call.
- Every action (denied, simulated, enforced, enforcement-failed,
  auto-expired) is audited with an explicit `enforcement` provenance field.

## T8 Acceptance Criteria

Existing simulated-mode tests and behavior are unchanged (`enforcement:
"simulated"` on every default-config action). New tests cover: injection-safe
command construction, elevation-required failure handling, idempotent
add/remove, non-Windows refusal, active-only-on-success semantics for both
block and unblock, self-host protection, duration capping, and expiry sweep
with connector removal. Full backend suite, frontend lint/build/Playwright,
ruff, compileall, and Alembic all pass after the change.

## T9 API Contract

`POST /api/response/block-ip` gains an optional `duration_minutes` field
(minutes, must be positive; capped server-side). `BlockedIPRead` gains
`enforcement` (string) and `expires_at` (nullable datetime).
`ResponseActionRead` gains `enforcement` (string). `GET /health` gains
`checks.response_mode.real_enforcement_possible` (bool) alongside the
existing `status`/`provider` fields; `status` now distinguishes
`simulation` / `windows_firewall_enforcement` /
`misconfigured_unsupported_platform` / `pending_connector` instead of the
previous binary `simulation`/`pending_connector`.

## T10 Data Model / Migration

Additive migration `c3d4e5f6a7b8_add_response_enforcement_and_expiry`: adds
`response_actions.enforcement` (string, server default `"simulated"`) and
`blocked_ips.enforcement` (string, server default `"simulated"`),
`blocked_ips.expires_at` (nullable datetime). No drops, no backfill logic
beyond the server default, fully reversible via the migration's `downgrade`.
Applied to the configured local database; `alembic check` reports no drift
afterward.

## T11 Backend Plan / Changes

New `windows_firewall_connector.py`: `apply_block`/`remove_block` via
`netsh advfirewall firewall add|delete rule`, one rule per direction
(`in`/`out`) named `ATDR-Block-{direction}-{ip}`, idempotent (clears any
stale rule first), 15-second subprocess timeout, elevation-failure detection
with a specific operator-facing message, non-Windows guard.
`response_service.py`: three-way enforcement dispatch (simulated / real /
pending-connector-for-any-other-provider-name, preserving prior behavior for
that third case), lazy expiry sweep, self-host address discovery
(stdlib-only: `socket.gethostbyname_ex` plus a no-packet UDP "connect" probe,
cached per process), duration capping.

## T12 Frontend Plan / Changes

`ResponseCenter.tsx`: headline/subhead and the block confirmation dialog now
read live `response_mode` instead of hardcoded "stays simulated" copy; a
timeout selector (until-manually-removed / 15m / 1h / 4h / 24h); a
"Real Block" vs "Simulated" badge and a live countdown per active block row;
button label switches to "Apply real block" when real enforcement is
configured. No change to any other page.

## T13 Security / Response / AI Safety

Detection/alert authority is untouched — this feature only affects the
already-existing, already-admin-gated response/containment path, not
detection. The connector cannot be reached except through the existing
admin-only, justification-required, evidence-checked, audited `block_ip`/
`unblock_ip` service functions. No shell-string command construction exists
anywhere in the connector. Real enforcement remains impossible to enable
accidentally (two explicit config keys, both defaulted off in every shipped
profile, both re-validated at startup).

## T14 Test Plan

`atdr/tests/test_windows_firewall_response.py` (new, 10 tests, all mock
`subprocess.run`/the connector — no test ever invokes a real `netsh`
process): command construction, elevation failure + rollback, idempotent
delete-of-nonexistent-rule, non-Windows refusal, active-only-on-success for
block and unblock, self-host protection, duration capping, expiry sweep.
`atdr/tests/test_response_safety.py` and `atdr/tests/test_api.py` updated/
extended for the new `enforcement` field and duration/health-endpoint
coverage. Full backend suite and Playwright re-run in full afterward.

## T15 Implementation Summary

A new ~120-line connector module, a rewritten (not just extended)
`response_service.py` enforcement dispatch, one additive migration, and
proportional frontend/schema/doc updates. No change to any shipped profile's
default configuration.

## T16 Tests Run / Evidence

`atdr/tests/test_windows_firewall_response.py`: `10 passed`.
`atdr/tests/test_response_safety.py`, `atdr/tests/test_api.py`,
`atdr/tests/test_iam_rbac.py`: `50 passed` (existing suite, updated for the
new `enforcement` field). Full backend suite, frontend lint/build/Playwright,
ruff, compileall, and Alembic check results are recorded in
`docs/tasks/tasklist-progress.md` after the full matrix completes.

## T17 PRD / Docs Updated

`README.md` (new "Response And Containment" section plus corrected safety
language), `docs/CURRENT_SYSTEM_STATE_LOCK.md`, `docs/prd/PRD-ATDR.md`,
`docs/ATDR_REQUIREMENT_TRACEABILITY.md`,
`docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`, `docs/OPERATIONS_RUNBOOK.md`,
`docs/LAB_RUNBOOK.md`, `docs/RELEASE_CHECKLIST.md`, `docs/ATDR_AI_WORKFLOW.md`,
`docs/ADVISOR_DEMO_RUNBOOK.md`, `docs/PRESENTATION_BRIEF.md`,
`docs/ENVIRONMENT_GUIDE.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md`,
`.env.example`, `.env.lab.example`, `.env.production.example` — every active
(non-archived) document that previously stated real firewall blocking is
unconditionally disabled now states the accurate, narrower claim: simulation
by default in every profile, real enforcement is an explicit local/lab-only
host-scoped opt-in, no real network-firewall connector exists, and
shared/production profiles remain simulation-only regardless of
configuration. Archived documents were not touched.

## T18 Risks / Blockers / Assumptions / Decisions

The connector requires the ATDR backend process to run with Administrator
privileges to create firewall rules; without it, `apply_block` fails cleanly
and the IP is not marked blocked (verified by test). Self-host protection is
best-effort stdlib discovery and could miss an unusual network
configuration; RFC1918/loopback/link-local protection already covers the
overwhelmingly common case as a second layer. "Device" control in the
original request is implemented as IP-based blocking only — true MAC/NAC-
level device quarantine was explicitly out of scope pending real switch/NAC
infrastructure details from the project owner.

## T19 Release / Rollback

Fully reversible: revert the migration (`alembic downgrade -1` from this
revision), revert the changed backend/frontend files, and no shipped
profile's default configuration changed, so no operator action is required
to return to pre-change behavior. No commit or push is authorized by this
record alone.

## T20 Final Handoff

Awaiting project-owner review and a separately approved commit/push decision,
together with the v5.64 window-aware anomaly work and the rule-engine
zone-classification fix already sitting in this working tree. If real
enforcement is to be demonstrated live, do so deliberately per
`docs/ADVISOR_DEMO_RUNBOOK.md`'s updated guidance, not as part of the default
walkthrough.
