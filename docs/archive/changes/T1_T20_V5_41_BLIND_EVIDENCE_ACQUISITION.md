# T1-T20: v5.41 Governed Blind Evidence Acquisition

## T1 Change Title

v5.41 Governed Blind Evidence Acquisition and Review Readiness.

## T2 Requirement

Implement the complete privacy-safe workflow for collecting, sealing,
reviewing, and later evaluating genuinely new multi-source evidence without
performing more model tuning or reusing consumed evidence.

## T3 Source Evidence

The consumed v5.39 evidence state and sealed review pack, v5.40 development
boundary and no-candidate result, disposable PAN-OS parser/index services,
existing evidence-review contracts, configured database and artifact counters,
AI Governance UI, AI training runbook, PRD, and requirement traceability.

## T4 Current Behavior

v5.40 rejected every supervised candidate and identified single-source,
short-window evidence as the main blocker. A future protocol existed only as
documentation; there was no dedicated collection CLI, custody manifest,
prediction-blind pack generator, separate prediction seal, or dashboard
readiness surface.

## T5 Impacted Areas / Agents

Detection/ML, evidence governance, backend/API, frontend/AI Governance,
security/privacy, QA, Release/Ops, documentation, future device operators, and
future genuine human reviewers.

## T6 Scope

Protected-boundary revalidation, disposable collection, source attestation,
cutoff and overlap enforcement, duplicate containment, safe manifest and
custody digests, separate prediction sealing, prediction-blind review pack,
aggregate API/UI status, tests, rehearsal, governance, and exact allowlist.

Model tuning/training/freezing/activation/promotion, label creation, configured
database writes, rule changes, response automation, real blocking, schema
migrations, and frozen evaluation metrics are out of scope.

## T7 Functional Requirements

- Revalidate v5.39 and v5.40 boundaries before every collection.
- Accept private files only with explicit disposable-storage acknowledgement.
- Reject evidence at or before the development cutoff.
- Reject configured, prior, exact, near, source, or custody overlap.
- Require genuine human physical-source attestation for qualification.
- Require two sources, three windows, and 240 isolated rows before review.
- Store candidate predictions separately from reviewer-visible evidence.
- Reject prediction, score, suggestion, fingerprint, raw-log, and IP columns.
- Detect protected evidence or custody-file tampering.
- Keep all operational authority unchanged.

## T8 Acceptance Criteria

The full private file parses in disposable storage; the run is classified
rehearsal-only; overlap is reported only as aggregate counts; no configured
state changes; custody and duplicate tests pass; API/UI status is aggregate;
review remains closed without the required sources/windows/candidate; and the
lifecycle remains conservative.

## T9 API Contract

Add authenticated read-only endpoint:

```text
GET /api/evidence-review/blind-evidence/status
```

It returns aggregate readiness and fixed safety state only. It never returns
source identities, windows, paths, raw logs, IPs, fingerprints, predictions,
reviewer identities, or secrets.

## T10 Data Model / Migration

No SQLAlchemy model or Alembic migration. All custody state, candidate rows,
prediction seals, review packs, and reports stay ignored under
`ml_baseline_reviews/`.

## T11 Backend Plan / Changes

Add the v5.41 service and CLI; reuse established boundary, parser, disposable
index, behavior aggregation, and database/artifact safety helpers; add
digest-bound manifest/candidate/seal/review custody; expose only a typed public
projection.

## T12 Frontend Plan / Changes

Add a compact AI Governance panel with aggregate status, sources, windows,
candidate rows, human review, lifecycle, and fixed safeguards. Add no
collection, prediction, review, activation, or response controls.

## T13 Security / Response / AI Safety

Private data stays outside Git and outside API output. Predictions remain
hidden from reviewers. AI/rule/Codex decisions cannot become human labels.
No label/model/detection/alert/response write occurs. Rules remain
alert-authoritative; ML remains advisory; automation and real blocking remain
disabled.

## T14 Test Plan

Test strict cutoff, genuine attestation, source/window gate, within-collection
near-duplicate containment, separate prediction sealing, prediction-blind CSV,
custody tamper detection, rehearsal classification, authentication, aggregate
API safety, no authoritative mutation, and responsive dashboard rendering.

## T15 Implementation Summary

Implemented the fail-closed v5.41 acquisition service, CLI, manifest/private
custody state, candidate isolation, separate prediction-seal workflow,
prediction-blind review generator, aggregate API/schema/types/query hook, AI
Governance panel, and focused backend/Playwright coverage.

## T16 Tests Run / Evidence

The private rehearsal parsed 773,551 rows with zero parser failures in about
171 seconds. It identified 120,000 configured-database overlap rows, 1,273
v5.40 exact overlaps, and 1,619 v5.40 near overlaps, then correctly remained
rehearsal-only. Focused custody/API tests pass, backend tests pass `946 passed,
1 skipped`, Playwright passes `35 passed, 1 skipped`, controlled detection and
layered validation pass (`288/288` layered), Assistant QA passes `20/20`,
performance has no warnings, Alembic has no drift, and the release gate returns
`ok: true`. The initial readiness-panel overflow found by Playwright was fixed
with a content-aware responsive breakpoint. The complete matrix is recorded in
the taskboard and v5.41 status document.

## T17 PRD / Docs Updated

v5.41 status, this T1-T20 record, AI training runbook, current AI/ML status,
PRD, requirement traceability, university compliance checklist, taskboard
Markdown/HTML, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

No new independently attested device or window was available. The existing
file overlaps configured/development evidence and cannot qualify. v5.40 froze
no candidate, so a prediction seal and review pack cannot yet open. Genuine
human review and adequate class support remain external requirements.

## T19 Release / Rollback

No commit or push is authorized. Release requires separate approval of the
exact allowlist. Rollback removes the v5.41 service, CLI, API/UI projection,
tests, and documentation; there is no database, label, model, alert, or
response rollback.

## T20 Final Handoff

Use the CLI for aggregate preflight or rehearsal now. Register only genuinely
future evidence from independently verified devices with private human
attestations. Do not open review until collection and prediction-seal gates
pass. Do not calculate frozen metrics or change model authority during v5.41.
