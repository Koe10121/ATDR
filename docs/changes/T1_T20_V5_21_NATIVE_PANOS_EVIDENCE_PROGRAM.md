# T1-T20: v5.21 Native PAN-OS Evidence Program

## T1 Change Title

v5.21 Native PAN-OS Evidence Program.

## T2 Requirement

Build leakage-safe native PAN-OS development and blind-evaluation roles from a
private file without importing it into the configured database, inventing
human labels, exposing private evidence, or changing model/response authority.

## T3 Source Evidence

- private PAN-OS evidence supplied only through a CLI argument;
- v5.4/v5.6 chronological and disposable-index machinery;
- v5.20 native schema contract;
- official PAN-OS syslog, TRAFFIC, THREAT, and application documentation; and
- existing privacy, parser, lifecycle, and repository-hygiene tests.

## T4 Current Behavior

Earlier phases could aggregate or weakly label private PAN-OS evidence, but
they did not produce a dedicated native role lock with a suggestion-free blind
verification pack and explicit official-field semantics.

## T5 Impacted Areas/Agents

Detection evidence, parser semantics, AI/ML governance, privacy/security, QA,
documentation, and orchestration.

## T6 Scope

Add a disposable evidence service/CLI, chronological role lock, duplicate
containment, weak development pack, suggestion-free blind pack, safe aggregate
reporting, tests, governance records, and cumulative allowlist. No API, UI,
database schema, startup command, detector threshold, or model artifact change.

## T7 Functional Requirements

- Require explicit disposable-storage acknowledgement.
- Parse the private source in bounded chunks.
- Assign roles before any assisted decision.
- Prevent exact and near-duplicate families crossing roles.
- Keep blind evidence suggestion-free and unopened.
- Exclude raw rows, addresses, paths, reusable fingerprints, and secrets from
  public output.
- Never access the configured database during the corrected v5.21 run.

## T8 Acceptance Criteria

The complete stream must parse, all four roles must contain evidence, duplicate
cross-role counts must be zero, packs must preserve label integrity, the
configured database marker must remain unchanged, no authoritative side effect
may occur, and the full repository verification matrix must pass.

## T9 API Contract

No API change. The CLI is:

```powershell
python -m atdr.scripts.run_v521_native_panos_evidence `
  --sample-path <private-path> --use-temp-db --pretty
```

It returns aggregate JSON only.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. Derived evidence uses temporary
SQLite and ignored local files only.

## T11 Backend Plan / Changes

Add the evidence module and CLI; reuse the bounded parser/index; record private
role locks; generate separate development/blind packs; expose only safe
aggregates; and remove disposable storage on completion.

## T12 Frontend Plan / Changes

No frontend change. v5.21 prepares evidence for later governed model work.

## T13 Security / Response / AI Safety

No raw evidence, addresses, private paths, fingerprints, secrets, human-label
claims, model artifact, alert, detection run, response action, activation,
promotion, automatic response, or real blocking.

## T14 Test Plan

Test official-source contract, disposable acknowledgement, chronological role
presence, duplicate containment, explicit in-memory overlap target, pack
separation, suggestion suppression, no import readiness, redacted failures,
zero authoritative side effects, and output privacy.

## T15 Implementation Summary

v5.21 processed 773,551 native rows into four chronological roles with zero
parser failures and zero duplicate-family leakage. It produced a 120-row weak
development pack and a 40-row suggestion-free blind pack.

The first full run revealed an inherited `None`-means-configured-database
behavior in the v5.6 helper. It read fingerprints without writing data. v5.21
now passes `sqlite:///:memory:` explicitly, has a regression guard, and the
corrected run reported no configured-database access or quarantine.

## T16 Tests Run / Evidence

Focused v5.21 tests pass `5/5`; the corrected complete-file run passes with
773,551 parser successes, 22 chronological windows, zero cross-role leakage,
zero quarantine, zero label/model/response writes, and an unchanged configured
database marker. Full backend/release runs each passed `800 passed, 1 skipped`;
Alembic, React lint/build, Playwright `27 passed, 1 skipped`, controlled
`24/24`, layered `288/288`, Assistant `20/20`, replay, performance, taskboard,
and release gate all passed.

## T17 PRD / Docs Updated

v5.21 status, PAN-OS field contract, this T1-T20 record, PRD, traceability,
compliance, current state, AI/ML status, runbooks, docs index, taskboard, and
cumulative exact allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

One native device and one private collection do not prove source
generalization. Weak suggestions do not prove accuracy. Human/advisor-verified
native labels are required. The blind role must stay sealed until v5.22 freezes
its candidate and evaluation contract.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes the v5.21 module, CLI, tests,
and docs. No database rollback is required. Ignored local packs/reports may be
removed manually only with owner approval.

## T20 Final Handoff

Proceed to v5.22 using only `development_fit`, `calibration`, and `threshold`
roles. Keep `untouched_future_validation` sealed. Select at most one diagnostic
shadow candidate and preserve rules as alert authority.
