# T1-T20: v5.60 Clean-Machine Release Candidate Acceptance

## T1 Change Title

- Title: Clean-Machine End-to-End Release Candidate Acceptance
- Date: 2026-09-15
- Owner / acting agent: Codex under project-owner direction
- Related version or sprint: v5.60

## T2 Requirement

- Prove the published repository can be cloned, configured, started, checked,
  stopped, restarted, recovered, and used through a safe analyst workflow on a
  teammate-style Windows environment.
- Do not use authoritative private state or relax security to make the test
  pass.
- Fix reproducibility defects found and leave a reusable acceptance harness.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| Published baseline | v5.59 commit `d020f1a973f005c192eba3256357f76618542cab` |
| Lifecycle | `scripts/setup_team.ps1`, `start_system.ps1`, `check_system.ps1`, `stop_system.ps1` |
| Shell distribution | `config/mfu-shell-contract.json`, shell package service |
| Analyst workflow | controlled e2e and v5.57 workflow services |
| Authority | v5.58 runtime contract and v5.49b no-candidate decision |
| Safety | repository audit/security scan and ignore policy |

## T4 Current Behavior

- Normal entry is the versioned MFU shell followed by one-time handoff.
- Local ATDR persistence is SQLite; shell persistence is separate MongoDB.
- Rules are authoritative, supervised scoring is unqualified, and response is
  simulation only.
- Earlier teammate rehearsal used `git archive HEAD`, not a genuine remote
  clone, and did not cover the entire safe analyst workflow.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Setup/lifecycle | acceptance coverage only; normal commands unchanged |
| Backend | new read-only/disposable acceptance service and CLI |
| Frontend | no runtime change |
| Database | disposable SQLite only; no schema change |
| IAM | packaged contract and fail-closed checks; no real provider call |
| Detection/ML | controlled workflow and authority inspection; no activation |
| Assistant | deterministic fallback/citation workflow; no provider key |
| Documentation | current operator and governance truth updated |

## T6 Scope

In scope: remote clone, pristine hygiene, first setup, versioned shell,
provider failure, synthetic wiring, idempotence, lifecycle, health, handoff,
recovery, controlled workflow, diagnostics, cleanup, tests, and documentation.

Out of scope: real MFU sign-in, real Gemini call, physical hardware forwarding,
supervised activation, shared-host deployment, automatic response, or blocking.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-560-01 | Clone genuine `origin/main` into Windows temporary storage | Must |
| FR-560-02 | Exclude private/generated state and developer paths | Must |
| FR-560-03 | Prove first setup and repeated setup | Must |
| FR-560-04 | Prove four-service lifecycle and diagnostics | Must |
| FR-560-05 | Validate shell handoff without bypassing auth | Must |
| FR-560-06 | Execute safe ingestion-to-Assistant workflow | Must |
| FR-560-07 | Leave no process/database/temp state | Must |

## T8 Acceptance Criteria

All 27 named harness stages pass; public output contains no usernames, private
paths, IP addresses, credentials, provider payloads, or secrets; no response
action/model activation occurs; and cleanup is constrained to the verified
temporary workspace and uniquely named synthetic shell database.

## T9 API Contract

No endpoint, request, response, authentication, or RBAC contract changed.

## T10 Data Model / Migration

No migration. Alembic runs repeatedly only against the disposable clone's
SQLite database.

## T11 Backend Plan / Changes

Add the v5.60 acceptance service, confirmation-gated CLI, redacted stage report,
provider-missing check, synthetic wiring, process/database snapshots, and safe
cleanup boundaries.

## T12 Frontend Plan / Changes

No React or MFU shell source change. The running frontends and printed entry URL
are health checked in the disposable clone.

## T13 Security / Response / AI Safety

- No authoritative private file is read or copied.
- Synthetic profile values are random, non-network, temporary, and never
  returned.
- Real provider acceptance remains `not_validated`.
- Rules remain alert-authoritative; supervised ML remains `unqualified`.
- Assistant uses deterministic fallback and creates no authoritative rows.
- Response remains `simulation_only`; no response action or block is created.

## T14 Test Plan

Focused tests cover preflight, pristine-clone rejection, synthetic-profile
boundaries, cleanup containment, packaged one-time handoff security, Assistant
fallback, and report redaction. Complete verification covers backend, frontend,
detection, Assistant, database, security, performance, release, and hygiene.

## T15 Implementation Summary

The harness defaults to preflight and executes only after exact confirmation.
It uses a real remote clone, validates all four dependency trees, exercises
lifecycle/recovery/workflow contracts, and removes only verified disposable
state. Normal startup commands remain unchanged.

## T16 Tests Run / Evidence

- Focused v5.60 tests: `7/7` pass; related portability/workflow selection:
  `40/40` pass.
- Genuine remote-clone acceptance: `27/27` pass.
- Controlled workflow: 10 ingested/normalized, one rule alert, three cited
  Assistant turns, zero response actions, zero model activation.
- Full backend suite: 1,091 passed and one live/external case skipped; release
  gate repeated the same suite successfully.
- Frontend: lint/build pass; Playwright 42 passed and one live-hardware case
  skipped.
- Detection: controlled port-scan scenario passed and layered validation passed
  288/288 mode runs across 24 scenarios.
- Assistant QA: 30/30 cases plus one follow-up sequence passed with a 100%
  citation pass rate.
- Alembic, repository audit, security acceptance, replay dry-run, performance
  smoke, deployment operations, and release gate passed. Performance recorded a
  cold Overview observation of 1.0477 seconds against the 1.0-second advisory
  budget; its cached path was 0.014 seconds.

## T17 PRD / Docs Updated

README, quickstart, environment guide, operations runbook, current state,
current AI/ML status, PRD, traceability, compliance, index, taskboard, v5.60
status, and this change record.

## T18 Risks / Blockers / Assumptions / Decisions

- The approved shell archive remains a separately distributed dependency.
- Synthetic provider wiring is not a real MFU login claim.
- A clean clone has no ignored IsolationForest artifact; rules still operate,
  while anomaly/hybrid status honestly reports unavailable/abstained.
- External owner acceptance remains pending.

## T19 Release / Rollback

The acceptance harness is additive and does not change normal runtime. Rollback
is a source revert only; no authoritative data rollback exists. Publication is
separately approval-gated.

## T20 Final Handoff

- Local status: clean-machine acceptance passed `27/27`.
- Runtime behavior changed: no.
- Reproducibility defects fixed: packaged fixture assumption and Windows
  long-path cleanup.
- Next recommended phase: v5.61 governed advisory anomaly bootstrap and final
  capability closure, followed by owner-backed external acceptances.
