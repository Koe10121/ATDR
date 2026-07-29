# T1-T20: v5.12 Parser-Profile-Aware Data Quality And Baseline Repair

## T1 Change Title

v5.12 Parser-Profile-Aware Data Quality and Operational Baseline Repair.

## T2 Requirement

Repair misleading parser/OOD warnings by separating parsing failures from
legitimate PAN-OS unresolved application states, versioning the parser
contract, and selecting governed parser-profile/source-type operational
baselines without tuning or activating supervised ML.

## T3 Source Evidence

- `atdr/app/parsers/paloalto_parser.py`
- `atdr/app/parsers/paloalto_contract.py`
- `atdr/app/services/v58_shadow_scoring_service.py`
- `atdr/app/services/v59_shadow_observation_service.py`
- `atdr/app/services/v511_shadow_monitoring_service.py`
- `atdr/app/services/v512_parser_baseline_service.py`
- `atdr/app/routers/ml.py`
- `frontend/src/pages/MLGovernance.tsx`
- v5.8-v5.12 backend/API/frontend tests
- eight aggregate v5.10/v5.11 observations
- bounded aggregate inspection of the private PAN-OS file
- official PAN-OS TRAFFIC, THREAT, and SYSTEM field documentation

## T4 Current Behavior

Before v5.12, unresolved/absent application values could be reported as parser
warnings, SYSTEM fields could inherit traffic mappings, parser compatibility
was implicit, and all shadow sources used an implicit global parser baseline.

## T5 Impacted Areas/Agents

- Backend/parser: contract, mappings, fallback, diagnostics.
- AI/ML governance: profile baselines and drift interpretation.
- Security/privacy: aggregate-only private inspection and opaque scopes.
- Frontend: concise collapsed AI Governance provenance.
- QA: parsing, no-mutation, privacy, controlled equivalence.
- Docs/release: status, runbook, traceability, compliance, taskboard, allowlist.

## T6 Scope

Included:

- TRAFFIC, THREAT, and SYSTEM schema contracts;
- application-resolution and compatibility diagnostics;
- SYSTEM mapping repair;
- generic/raw fallback preservation;
- governed profile/source-type baseline selection;
- read-only v5.11/v5.12 comparison;
- private bounded aggregate CLI;
- authenticated API and AI Governance panel;
- tests and governance records.

Excluded:

- configured-database reparse or migration;
- label creation/update;
- supervised model tuning, selection, activation, or promotion;
- alert/rule/threshold authority changes;
- automatic response or real blocking;
- private evidence persistence; and
- commit/push.

## T7 Functional Requirements

1. Preserve raw evidence and normal import behavior.
2. Distinguish parse error, structural warning, unresolved application,
   absent/not-applicable field, unsupported profile, and raw fallback.
3. Clear traffic-only fields from SYSTEM normalization.
4. Derive baselines from governed development-fit aggregates only.
5. Require minimum support and fail conservatively for incompatible profiles.
6. Never use labels, accuracy, or device identity for baseline selection.
7. Return aggregate-only private diagnostics.
8. Preserve queue/disagreement telemetry and controlled alert behavior.
9. Keep lifecycle and response safety unchanged.

## T8 Acceptance Criteria

- Complete private file parses 773,551/773,551 rows without error.
- Known private layouts are 115-field TRAFFIC and 121-field THREAT.
- Structural warning rate is zero; unresolved applications remain visible.
- SYSTEM synthetic/official-contract tests pass and traffic fields are clear.
- Generic syslog and raw fallback preserve evidence.
- Sparse/incompatible profiles return `Insufficient Evidence`.
- v5.11 diagnostic fingerprint and controlled projection match.
- Controlled comparison passes 96/96 with zero FP/FN.
- All authoritative database deltas are zero.
- API/UI expose no identity, raw data, labels, accuracy, paths, or secrets.

## T9 API Contract

Authenticated analyst/admin read-only route:

```text
GET /api/ml/supervised/shadow-operations/parser-quality
```

It returns aggregate parser contract, baseline provenance, opaque scope,
quality, compatibility, resolution, and safety data.

## T10 Data Model / Migration

No schema migration is required. No configured row is reparsed or rewritten.
New parser metadata is stored only on future normal imports. Existing rows
remain valid legacy evidence.

## T11 Backend Plan / Changes

- Add a versioned Palo Alto parser contract.
- Repair SYSTEM mapping and classify layout compatibility.
- Separate unresolved application data quality from parser warnings.
- Add baseline catalog/selection/evaluation and comparison services.
- Integrate profile-aware drift into future shadow telemetry.
- Add an aggregate-only private audit and safe CLI.
- Add the authenticated read-only API.

## T12 Frontend Plan / Changes

- Add API types, client, and query hook.
- Add a collapsed, overflow-safe Parser Profile Baseline panel.
- Show contract/baseline/quality/drift data only.
- Expose no execution controls or private identifiers.

## T13 Security / Response / AI Safety

- Private file is a CLI argument only and is never returned.
- Raw rows, IPs, source identity, fingerprints, labels, paths, and secrets are
  excluded.
- Configured database and active artifacts remain unchanged.
- Rules remain authoritative; IsolationForest and supervised ML remain
  advisory.
- No activation, promotion, automatic response, or real blocking occurs.

## T14 Test Plan

- Known/compatible/extended/partial parser variants.
- TRAFFIC, THREAT, and SYSTEM mappings.
- Application-resolution semantics.
- Generic and raw fallback preservation.
- Exact/global/incompatible/sparse baseline behavior.
- Private redaction and bounded aggregation.
- Read-only diagnostics and API authentication.
- Controlled projection equivalence.
- AI Governance rendering and overflow.
- Full project verification and hygiene matrix.

## T15 Implementation Summary

v5.12 introduces contract-aware parsing and profile-aware operational
baselines. It repairs interpretation without rewriting historical rows or
changing detection/model/response authority.

## T16 Tests Run / Evidence

Final verification evidence is recorded in
`docs/V5_12_PARSER_PROFILE_BASELINE_REPAIR.md` and the taskboard verification
log. The implementation-level evidence includes:

- complete private aggregate audit: 773,551 rows, 100% parse success;
- 0 parser errors and 0 structural warnings;
- 7.1739% unresolved application data quality;
- exact v5.11 diagnostics lock match;
- exact 96-run controlled projection match;
- zero authoritative database deltas; and
- focused parser/service/API/frontend checks;
- full backend and release-gate suites: `732 passed, 1 skipped`;
- Alembic no-drift check;
- React lint/build and Playwright `26 passed, 1 skipped`;
- controlled scenarios `24/24`;
- layered validation `288/288` with zero controlled FP/FN;
- assistant QA `20/20` with zero state-changing side effects;
- bounded private preflight, replay dry-run, warning-free performance smoke,
  and official release gate; and
- diff, exact-allowlist, privacy, and tracked-hygiene checks.

## T17 PRD / Docs Updated

- v5.12 status
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

- No real SYSTEM records were present in the private file.
- Existing rows remain legacy-contract records unless a separately approved
  reparse is designed.
- Generic/raw profiles lack sufficient governed comparable baselines.
- Application distribution still produces legitimate OOD warnings.
- Independent labeled multi-device evidence remains unavailable.

## T19 Release / Rollback

No migration or configured-data rewrite exists. Rollback removes the new
contract/service/API/UI integration; existing evidence remains untouched.
No commit or push is authorized by this record.

## T20 Final Handoff

Use v5.12 to interpret parser quality and drift more honestly. Keep the
supervised lifecycle in `shadow_observation`, rules authoritative, response
automation disabled, and obtain independent device/label evidence before any
ML authority proposal.
