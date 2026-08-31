# T1-T20: v5.49 Fixed Development Revalidation And Candidate Decision

## T1 Change Title

v5.49 Fixed Development Revalidation and Supervised Candidate Decision.

## T2 Requirement

Execute the immutable v5.48 development protocol exactly once after proven
human-review closure, report all eight strategies, and make a conservative
diagnostic candidate decision without changing model or alert authority.

## T3 Source Evidence

The sealed v5.47 pack, locked v5.48 protocol, protected working copy and state,
configured audit log, v5.42 fixed gates, v5.45 strategy implementation, and
current database/artifact authority state.

## T4 Current Behavior

The fixed protocol is valid and measured source truth is review `120/120`,
invalid `0`, formally closed, with support `92/9/0`. The suspicious and
malicious support gates fail, so evaluation remains correctly blocked at count
`0` with no claim or result.

## T5 Impacted Areas / Agents

Orchestrator, Detection/ML, Evidence Governance, Security/Privacy, QA,
Release/Ops, and documentation. A genuine human reviewer remains required.

## T6 Scope

Atomic execution claim, aggregate result integrity validation, eight-strategy
reporting, conservative diagnostic decision, tests, governance, full
verification, and hygiene. Label creation, protocol tuning, active artifacts,
alert authority, and response are out of scope.

## T7 Functional Requirements

- Prove protocol, pack, state, class support, closure, and custody first.
- Claim the one permitted run atomically before evaluation-label access.
- Preserve the exact locked protocol and report all eight outcomes.
- Fail closed on missing, duplicate, changed-gate, or authority-mutating data.
- Qualify at most one inactive diagnostic candidate.
- Preserve `shadow_observation` and deterministic-rule authority.

## T8 Acceptance Criteria

The private review is valid and closed; exactly one evaluation claim and result
exist; all eight strategies and requested metrics are reported; no forbidden
write occurs; governance and the complete verification matrix pass.

Current state satisfies completion and closure but not the fixed class-support
criteria. The evaluation therefore remains unconsumed.

## T9 API Contract

No new API is required. The read-only CLI is:

```text
python -m atdr.scripts.run_v549_fixed_revalidation_decision
```

Existing protected v5.48 API routes remain unchanged.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. The claim and measured result remain private,
ignored evidence files.

## T11 Backend Plan / Changes

Add an atomic execution claim to the v5.48 runner and a v5.49 aggregate result
validator/decision CLI. Do not alter the frozen modeling protocol.

## T12 Frontend Plan / Changes

No frontend behavior change is required for the candidate decision. Genuine
review continues through the existing protected Manual Anchors workspace.

## T13 Security / Response / AI Safety

No row label, prediction, raw log, IP, identity, path, fingerprint, secret, or
reviewer identity is returned. No model activation/promotion, alert mutation,
automatic response, or firewall action is permitted.

## T14 Test Plan

Cover all-eight reporting, fixed-gate projection, leader consistency, missing
or changed strategies, authority-state mutation, private-field redaction,
blocked pre-review status, and atomic execution claiming.

## T15 Implementation Summary

The post-result decision layer, CLI, atomic one-run claim, and focused tests are
implemented. Evaluation remains pending a separately relocked protocol after
honest supplemental support, not changes to the closed v5.48 decisions.

## T16 Tests Run / Evidence

Focused v5.48/v5.49 tests pass `19/19`; the release gate passes with `1016
passed, 1 skipped`; Ruff, compileall, Alembic no-drift, React lint/build,
Playwright `36 passed, 1 skipped`, taskboard checks, controlled source
validation, layered detection `288/288`, Assistant QA `20/20`, replay dry-run,
performance smoke, diff check, and exact 64-path allowlist checks pass. The
performance run produced one narrow cold-Overview warning (`1.0705s` versus
the `1.0s` local target), while the cached path was `0.0141s`. Real review
status is `120/120`, closed, support `92/9/0`, claim-free, result-free, and
execution count `0`.

## T17 PRD / Docs Updated

This in-progress status, PRD, traceability, compliance, AI runbook, current
AI/ML status, and taskboard are updated. Final metrics and exact allowlist must
be recorded after the one-time run.

## T18 Risks / Blockers / Assumptions / Decisions

The genuine closed review lacks sufficient suspicious and malicious support.
Changing those decisions to satisfy a gate would violate label provenance.
v5.49a therefore acquires separate prediction-blind evidence. One-source
development evidence cannot prove generalization even after a successful run.

## T19 Release / Rollback

No commit or push is authorized. Removing the v5.49 reader/tests/docs and the
unconsumed atomic-claim code restores v5.48 behavior; configured data requires
no rollback.

## T20 Final Handoff

Complete and close the separate v5.49a Supplemental Threat Anchors review. If
combined support passes honestly, relock a new versioned protocol in v5.49b
before any fixed run. Never execute the original support-invalid protocol.
