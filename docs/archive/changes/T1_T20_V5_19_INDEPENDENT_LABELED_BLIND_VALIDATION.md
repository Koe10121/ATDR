# T1-T20: v5.19 Independent Labeled Detection/ML Evidence And Blind Validation

## T1 Change Title

v5.19 Independent Labeled Detection/ML Evidence and Blind Validation.

## T2 Requirement

Acquire authoritative evidence that has not influenced ATDR development, freeze
the evaluation contract before labels are read, perform one final label reveal,
and preserve a conservative lifecycle when fixed transfer gates fail.

## T3 Source Evidence

- v5.3-v5.7 evidence locks and frozen candidate artifacts;
- v5.8-v5.13 shadow/parser governance;
- official CTU-13 publisher pages and scenario files;
- official UNB/CIC and UNSW dataset pages considered during selection;
- current feature, rule, model, database, and safety source; and
- ignored private manifest, prediction, label, and diagnostic records.

## T4 Current Behavior

ATDR had a frozen calibrated PAN-OS candidate but no fresh independently labeled
native evidence. Existing private PAN-OS traffic is reused, unlabeled development
evidence. Earlier external evidence was already opened and could not be reused as
fresh blind ground truth.

## T5 Impacted Areas/Agents

Detection, supervised ML governance, evidence custody, privacy, QA, release,
documentation, and orchestration.

## T6 Scope

Add a private immutable evidence manifest, label-sealed sampling/adapter,
prediction freeze, one-time reveal, conservative binary evaluator, safe CLI,
tests, reports, governance updates, and exact commit boundary. No runtime API,
database schema, dashboard, or authority change is in scope.

## T7 Functional Requirements

- Use only primary/authoritative dataset sources.
- Reject reused or unverifiable evidence.
- Keep private evidence and fingerprints outside Git.
- Freeze candidate, adapter, taxonomy, duplicates, metrics, and gates first.
- Never read labels during sampling, features, or prediction.
- Reveal labels once and fail closed on repeat execution.
- Quarantine ambiguous provider labels.
- Return aggregate redacted output only.
- Preserve configured database, model artifacts, and response safety.

## T8 Acceptance Criteria

The protocol is complete when provenance is documented, the contract and
predictions are frozen before label access, the one-shot outcome is preserved,
adapter errors cannot be hidden, repeat execution fails closed, all side-effect
deltas are zero, tests pass, and readiness follows fixed gates rather than a
desired result.

## T9 API Contract

No HTTP API changes. The new CLI supports `--dataset-path`, `--manifest-path`,
`--preflight-only`, `--execute`, `--confirm`, `--rows-per-scenario`,
`--output-dir`, `--recover-label-adapter`, and `--pretty`. Execute and recovery
are mutually exclusive; execution requires explicit confirmation.

## T10 Data Model / Migration

No database model or Alembic migration. Provider labels remain external and are
not imported into `ml_labels`.

## T11 Backend Plan / Changes

- Add v5.19 evaluator and CLI.
- Verify v5.7 locks and the frozen v5.6 artifact.
- Create/verify ignored immutable evidence identity.
- Sample in two passes without label access.
- map defensible flow fields to the fixed feature contract without invention.
- Freeze private predictions, reveal provider labels once, and evaluate.
- Preserve the initial adapter failure and allow one explicitly post-blind
  serialization diagnostic.
- Lock completed preflight/recovery state against misleading reruns.

## T12 Frontend Plan / Changes

No frontend behavior changes. AI Governance continues to report the supervised
lifecycle as shadow-only through existing sources.

## T13 Security / Response / AI Safety

No private path, checksum, row, IP, database URL, or secret is returned. The
configured DB, labels, runs, alerts, responses, and active artifacts are not
modified. Rules remain alert-authoritative. Automatic response and real firewall
blocking remain disabled.

## T14 Test Plan

- Label-sealed sample equality after label-only changes.
- Binary taxonomy and ambiguity quarantine.
- Wrapped provider-label handling.
- Prediction-before-label and one-time reveal.
- Repeat adapter recovery refusal.
- Conservative metrics and partial-rule status.
- Explicit execute confirmation.
- Full repository verification and hygiene matrix.

## T15 Implementation Summary

CTU-13 scenarios 5, 7, 11, and 12 were acquired from official sources and
recorded privately. Preflight scanned 676,631 flows and selected 20,000 rows
without label access. The first reveal exposed a `flow=` serialization mismatch
and remains the authoritative failed blind record. A one-time normalization-only
diagnostic evaluated the unchanged predictions: F1 `0.6504`, FPR `0.9978`, ECE
`0.4244`, and queue rate `0.9989`. The binary transfer gate failed.

## T16 Tests Run / Evidence

Taskboard render/check, Ruff, compileall, focused v5.19 tests (`7 passed`), full
backend/release tests (`789 passed, 1 skipped`), Alembic no-drift, React
lint/build, Playwright (`26 passed, 1 skipped`), controlled detection (`23/23`),
layered detection (`288/288`), Assistant QA (`20/20`), replay dry-run,
warning-free performance smoke, release gate (`ok: true` with no failed
required checks), diff, privacy, exact 16-path allowlist, ignored-evidence,
staging, and tracked-hygiene checks pass. The configured database remained at
Alembic head and no v5.19 safety side effect was observed.

## T17 PRD / Docs Updated

v5.19 status, this T1-T20 record, PRD, state lock, AI/ML product status,
training runbook, traceability, compliance, lab runbook, docs index, taskboard,
rendered HTML, and exact commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

CTU-13 is old, botnet-focused bidirectional NetFlow and not native PAN-OS. Only
10 of 40 candidate fields map directly, 13 are defensibly derived, and 17 are
unavailable. The initial blind adapter failed; recovery metrics are diagnostic,
not fresh blind evidence. Native independently labeled PAN-OS data, a second
real device, and provider/deployment/security acceptance remain external.

## T19 Release / Rollback

No commit or push is authorized. Rollback removes the v5.19 evaluator, CLI,
tests, and tracked docs. Ignored evidence may be deleted separately only with
owner approval; no configured database rollback is required.

## T20 Final Handoff

Keep lifecycle `shadow_observation`, rules alert-authoritative, and all response
automation disabled. Lock v5.19 as failed cross-schema transfer evidence. The
recommended next phase is v5.20 schema-aware abstention and protocol repair,
without tuning on v5.19 final labels.
