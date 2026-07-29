# v5.13 Runtime Parser Contract Adoption And Source Quality Operations

Date: 2026-07-28

## Decision

v5.13 applies the v5.12 parser-quality contract to future runtime ingestion.
It does not reparse historical evidence, change deterministic detection,
retrain or activate ML, create labels, enable automatic response, or enable
real firewall blocking.

Existing normalized rows remain historical evidence. They are represented as
`legacy_contract` in aggregate source views unless they already contain
versioned parser metadata.

## Runtime Coverage

| Ingestion path | Runtime contract behavior |
| --- | --- |
| File import | Aggregates every parsed row and records the result on the source, ingestion run, audit event, and import result. |
| Direct replay | Uses the selected source parser profile and records run/source aggregates without exposing a database URL or private path. |
| UDP syslog | Aggregates received datagrams per batch/run and preserves raw evidence for every nonblank message. |
| Durable background import | Persists parser-quality totals transactionally with every resumable chunk and restores them on resume. |
| Controlled scenarios | Inherits the normal file-import contract; generic and raw-fallback scenarios prove profile-specific behavior. |

The aggregate format is
`v5.13-runtime-parser-quality-v1`. Source aggregates retain a fixed first
supported baseline and the latest bounded ingestion window so operational
changes are not inferred from one cumulative percentage.

## Classification Semantics

| Category | Meaning | Source-health effect |
| --- | --- | --- |
| Parser error | Structural parsing failed. | Warning or error according to recent count/rate. |
| Structural warning | Parsing completed, but fields/layout differ from the supported contract. | Warning when material. |
| Compatible layout | Supported known or compatible layout. | Healthy when no other issue exists. |
| Extended layout | Supported layout with additional preserved fields. | Healthy when no other issue exists. |
| Partial layout | Supported type lacks required contract structure. | Warning. |
| Unsupported layout | Missing or unsupported type/wrapper. | Warning or error when parsing also fails. |
| Unresolved application | PAN-OS session application identification is incomplete or unknown. | Informational context only; never source failure by itself. |
| Absent application | A traffic/threat application field is absent. | Data-quality context, separate from unresolved. |
| Not applicable | The record type has no application field. | No failure. |
| Generic syslog | Evidence preserved with intentionally limited structured fields. | Limited/warning state, not a Palo Alto parse failure. |
| Raw fallback | Raw evidence preserved without structured parsing. | Warning/fallback state, excluded from actual parser-error counts. |

The older stored `parse_failure_count` remains for compatibility and can
include raw-fallback rows. Dashboard labels therefore call it
`Fallback / Failed Rows`; `Runtime Parser Errors` is the actual v5.13
structural-error count.

## Operational Alerts

Source aggregates can emit privacy-safe alerts:

- `parser_error_rate_high`: the latest window has a high initial error rate;
- `parser_error_rate_increase`: the latest window materially exceeds the
  fixed source baseline;
- `unsupported_layout`;
- `structural_schema_drift`;
- `prolonged_raw_fallback`;
- `generic_syslog_limited_profile`;
- `unresolved_application_context`; and
- `unresolved_application_shift`.

Unresolved-application alerts are informational. Overview Operations Health
links each aggregate alert to the authorized source drawer without placing
raw evidence, IP addresses, or private paths in the alert payload.

## Historical Evidence And Migration

Migration `e7f8a9b0c1d2` adds one non-null JSON aggregate to `log_sources`.
It performs no raw/normalized row update and no reparse. After migration:

- all 11 existing sources had a valid empty aggregate;
- zero existing source aggregates were populated from historical raw data;
- Alembic reported no schema drift; and
- historical rows remained unchanged.

Authenticated analyst/admin route:

```text
GET /api/sources/{source_id}/reparse-impact-preview
```

The preview reads stored normalized metadata only. It reports bounded
contract/profile coverage, performs no reparse, reads no raw evidence, and
returns no source identity, private path, IP address, label, or secret.

## Dashboard

- **Overview / Log Sources:** contract state and parser-quality state appear
  beside source status.
- **Operations Health:** current parser operational alerts are concise and
  source-linked.
- **Source Detail:** actual parser errors, structural warnings, layout
  classes, application-resolution classes, generic/raw fallback, legacy
  rows, and redacted parser-error examples are separate.
- **AI Governance:** aggregate runtime-contract, legacy/mixed-source, and
  parser-alert counts are visible without changing model authority.

## Frozen Non-Regression Evidence

The v5.11 diagnostics fingerprint still matches:

```text
4057448c2c0aa6aec27c01e64bd708e0e811d8aa3da49a8d3d5497eb13612490
```

The frozen one-variant controlled projection still matches:

```text
74a6f5ada3179585c6bfdf25663f0c64bc09b196066c3f38270442eca3bd2ce6
```

The comparison passed 96/96 controlled mode runs with zero controlled false
positives and false negatives. Authoritative raw, normalized, alert,
detection-run, label, model-run, and response-action deltas were all zero.

## Verification

Completed evidence:

- taskboard render/standard checks: passed;
- Ruff and exact source/migration compileall: passed;
- focused runtime path/classification/source tests: passed;
- full backend/release tests: `741 passed, 1 skipped`;
- additive migration and Alembic no-drift check: passed;
- React lint/build: passed;
- Playwright: `26 passed, 1 skipped`;
- complete controlled scenarios: `24/24`;
- layered validation: `288/288`, zero controlled FP/FN;
- assistant QA: `20/20`, zero side effects;
- v5.12 frozen lock and controlled comparison: matched, `96/96`;
- private disposable preflight: 120,000 rows, zero parser errors and
  structural warnings, no persistent storage or protected output;
- replay dry-run: two parsed, zero sent/imported;
- performance smoke: warning-free; Overview `0.1545s`, cached `0.0102s`,
  AI Governance `0.2710s`;
- official release gate: passed; and
- diff, exact allowlist, privacy, staging, and tracked-hygiene checks: passed.

The release check now excludes ignored runtime/test evidence under
`atdr/data/processed` from source compilation. A regression test locks this
boundary while `atdr` source and migrations remain fully compiled.

## Safety State

- deterministic rules remain alert-authoritative;
- IsolationForest and supervised ML remain advisory;
- supervised lifecycle remains `shadow_observation`;
- no model was activated or promoted;
- no label was created or overwritten;
- no automatic response was enabled;
- no real firewall blocking was enabled; and
- no historical evidence was reparsed or deleted.

## Remaining Evidence

1. Real SYSTEM-log evidence is still required to validate the official and
   synthetic SYSTEM contract against an actual device.
2. Generic syslog and raw fallback do not yet have governed comparable drift
   baselines.
3. Independent, legitimately labeled, multi-device and multi-period evidence
   remains required before supervised ML can advance.
4. Long-duration real-device syslog forwarding and parser-drift operation
   remain external validation work.

The exact source-controlled v5.13 path set is recorded in
`docs/V5_13_COMMIT_ALLOWLIST.md`. It authorizes no staging, commit, or push.
