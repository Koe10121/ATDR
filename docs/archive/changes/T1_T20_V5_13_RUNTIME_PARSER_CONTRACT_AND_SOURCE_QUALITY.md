# T1-T20: v5.13 Runtime Parser Contract And Source Quality Operations

## T1 Change Title

v5.13 Runtime Parser Contract Adoption and Source Quality Operations.

## T2 Requirement

Apply v5.12 parser-quality semantics consistently to every future ingestion
path, distinguish structural failures from legitimate unresolved
applications in source operations, and preserve historical evidence without
automatic reparse.

## T3 Source Evidence

- `atdr/app/parsers/paloalto_contract.py`
- `atdr/app/parsers/paloalto_parser.py`
- `atdr/app/services/runtime_parser_quality_service.py`
- file/direct/syslog/resumable ingestion services and replay CLI
- source service/router/schemas
- Overview and AI Governance source-quality views
- v5.11 aggregate lock and v5.12 comparison service
- runtime/backend/API/frontend regression tests

## T4 Current Behavior

Before v5.13, future parsing stored v5.12 metadata per normalized row, but
source counters and runtime import/replay/syslog/job summaries still used the
older parsed/failed totals. Raw fallback and unresolved applications could
therefore be difficult to distinguish operationally.

## T5 Impacted Areas/Agents

- Parser/backend: shared aggregate and ingestion-path adoption.
- Database: one additive source JSON aggregate.
- Operations: source health, run summaries, privacy-safe alerts.
- Frontend: Overview, Source Detail, Operations Health, AI Governance.
- Security/privacy: redacted examples and read-only historical preview.
- QA/docs: path coverage, zero mutation, frozen equivalence, governance.

## T6 Scope

Included:

- future file, direct replay, UDP syslog, durable import, and scenario paths;
- runtime aggregate baseline/latest-window semantics;
- source quality/status and operational alerts;
- read-only historical contract-impact preview;
- additive migration, API/UI, tests, docs, and exact allowlist.

Excluded:

- automatic historical reparse or backfill;
- raw-evidence deletion or alteration;
- label creation/overwrite;
- detection-rule/threshold changes;
- ML training, activation, or promotion;
- automatic response or real blocking; and
- commit/push.

## T7 Functional Requirements

1. Preserve one raw row for every accepted nonblank input row.
2. Record parser-quality aggregates on sources and operation results.
3. Separate parser error, structural warning, layout compatibility,
   application resolution, generic syslog, and raw fallback.
4. Compare latest runtime windows to a fixed supported source baseline.
5. Keep unresolved applications informational unless another structural
   problem exists.
6. Keep historical evidence represented as legacy without reparsing it.
7. Expose only redacted, aggregate operational information.
8. Preserve detection, ML, labels, response, and authority state.

## T8 Acceptance Criteria

- Every named ingestion path records the v5.13 aggregate.
- Raw fallback is not counted or displayed as an actual parser error.
- Actual malformed rows remain visible with redacted evidence references.
- Unknown/incomplete application values alone leave source health healthy.
- Error-rate increase is measured against a prior baseline.
- Historical preview is authenticated, read-only, redacted, and zero-write.
- Frozen v5.11 and controlled detection fingerprints still match.
- Full backend/frontend/release verification passes.

## T9 API Contract

Existing import, job, source, and run payloads gain parser-quality aggregates.

New authenticated read-only route:

```text
GET /api/sources/{source_id}/reparse-impact-preview
```

It returns aggregate stored-metadata coverage only and performs no reparse.

## T10 Data Model / Migration

Migration `e7f8a9b0c1d2` adds
`log_sources.parser_quality_json JSON NOT NULL DEFAULT '{}'`.

The migration contains no destructive operation, reparse, historical update,
or evidence deletion. Existing rows start with an empty aggregate and are
classified as legacy at read time.

## T11 Backend Plan / Changes

- Add a shared runtime aggregate service.
- Integrate it with all future ingestion paths.
- Persist resumable aggregates at transactional chunk boundaries.
- Add baseline-aware source alerts and quality summaries.
- Exclude expected raw fallback from actual parser-error examples.
- Add a zero-write historical metadata preview.

## T12 Frontend Plan / Changes

- Extend API types and client for source contract/quality/preview data.
- Show concise contract and quality states in source cards.
- Separate stored fallback/failure totals from runtime structural errors.
- Add source operational alerts and read-only historical coverage.
- Add aggregate parser-contract status to AI Governance.

## T13 Security / Response / AI Safety

- Raw rows never appear in parser operational alerts or preview output.
- Parser-error examples expose only row IDs and a redacted availability note.
- Private paths, IPs, source identities, labels, secrets, and model artifacts
  are excluded from validation outputs.
- Rules remain authoritative; ML remains advisory.
- No assistant, response, detection, label, or model action is triggered by
  source quality.

## T14 Test Plan

- All five runtime ingestion paths.
- Every profile and classification category.
- Initial high versus increased parser-error rates.
- Unresolved-application source-health behavior.
- Raw-fallback/error separation and evidence preservation.
- Historical preview privacy and zero mutation.
- API authorization and frontend rendering/overflow.
- Frozen detection equivalence and complete release matrix.

## T15 Implementation Summary

v5.13 makes the versioned parser contract operational for future evidence
without rewriting history. Source operations now report the meaning of
quality conditions instead of collapsing them into one failure count.

## T16 Tests Run / Evidence

Measured evidence includes:

- focused path and source semantics suites: passed;
- frozen v5.11 lock and 96/96 controlled projection: matched;
- configured authoritative entity deltas: zero during comparison;
- migration and Alembic check: passed;
- full backend: `741 passed, 1 skipped`;
- React lint/build and Playwright `26 passed, 1 skipped`;
- complete scenarios `24/24`, layered validation `288/288`, assistant QA
  `20/20`;
- private disposable preflight parsed 120,000 rows without protected output
  or persistent storage;
- warning-free performance smoke and official release gate: passed; and
- exact allowlist, diff, staging, privacy, and tracked-hygiene checks: passed.

## T17 PRD / Docs Updated

- v5.13 status
- this T1-T20 record
- PRD
- requirement traceability
- university compliance checklist
- AI training runbook
- current AI/ML status
- AI docs index
- taskboard Markdown/HTML
- exact commit allowlist

## T18 Risks / Blockers / Assumptions / Decisions

- Historical rows remain virtual `legacy_contract` records by design.
- First file-import baseline may represent the first supported batch rather
  than exactly 20 rows; subsequent windows remain comparable to that fixed
  baseline.
- Generic/raw profiles remain operationally classifiable but lack governed
  accuracy/drift baselines.
- Real SYSTEM evidence and independent labeled devices remain unavailable.

## T19 Release / Rollback

Rollback removes the API/UI/service integration and drops only the additive
source aggregate column. Raw and normalized evidence remains untouched.
Rollback is not authorized or needed. No commit or push is authorized by this
record.

## T20 Final Handoff

Use v5.13 source quality for future ingestion and keep historical evidence
unchanged. Treat unresolved applications as session context, investigate
structural errors/layout changes separately, keep rules authoritative, and
retain the supervised lifecycle in `shadow_observation`.
