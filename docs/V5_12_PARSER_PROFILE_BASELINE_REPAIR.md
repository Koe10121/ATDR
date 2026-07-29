# v5.12 Parser-Profile-Aware Data Quality And Operational Baseline Repair

Date: 2026-07-28

## Decision

v5.12 is a parser and operational-monitoring repair. It does not retrain,
select, activate, or promote a supervised model. The supervised lifecycle
remains `shadow_observation`, deterministic rules remain alert-authoritative,
IsolationForest remains advisory, response automation remains disabled, and
real firewall blocking remains disabled.

## Problems Found

1. The Palo Alto parser treated `unknown`, `incomplete`, an absent
   application field, and some related application states as one parser
   warning. An unresolved session application is useful data-quality evidence,
   but it is not proof that CSV parsing failed.
2. PAN-OS SYSTEM records used a different field layout but inherited
   traffic-column values from the shared mapping.
3. Parser compatibility was implicit. Existing records could not state
   whether their TRAFFIC, THREAT, or SYSTEM layout matched a known contract,
   was compatible/extended, was partial, or required fallback.
4. v5.11 shadow drift compared every source against one implicit global
   baseline. Parser profile and source type were not represented in baseline
   selection.
5. Existing normalized rows predate the v5.12 contract and correctly appear
   as `legacy_contract`; v5.12 does not reparse or mutate them automatically.

## Evidence-Backed Repairs

- Added the versioned `palo_alto_syslog_v5.12` contract for TRAFFIC, THREAT,
  and SYSTEM records.
- Kept application metadata anchored to the documented high-resolution
  timestamp rather than relying on unstable tail offsets.
- Added explicit compatibility states for known, compatible, extended,
  partial, missing-type, and unsupported layouts.
- Added explicit application-resolution states:
  `identified`, `unresolved`, `absent`, and `not_applicable`.
- Moved unresolved applications to parser notices/data-quality telemetry.
  Structural parser warnings and parse errors remain separate.
- Added SYSTEM-specific normalization and cleared traffic-only fields.
- Preserved generic syslog and raw fallback evidence with explicit profile,
  contract, status, and compatibility metadata.
- Added governed profile/source-type baseline selection with minimum support
  and conservative global fallback.
- Integrated the profile-aware quality result into new shadow telemetry while
  preserving old public quality aliases for compatibility.

Official contract references:

- [PAN-OS Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
- [PAN-OS Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields)
- [PAN-OS System Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/system-log-fields)

## Frozen v5.11 Baseline

The aggregate-only v5.11 diagnostics projection is locked at:

```text
4057448c2c0aa6aec27c01e64bd708e0e811d8aa3da49a8d3d5497eb13612490
```

The one-variant controlled layered projection is locked at:

```text
74a6f5ada3179585c6bfdf25663f0c64bc09b196066c3f38270442eca3bd2ce6
```

The lock includes no source identifiers, raw rows, IP addresses, labels,
private paths, or secrets.

## Complete Private Aggregate Audit

The private PAN-OS file was supplied only through the CLI argument. It was
read by bounded streaming and was not imported or persisted.

| Measure | Result |
| --- | ---: |
| Rows observed | 773,551 |
| TRAFFIC, 115 fields | 771,932 |
| THREAT, 121 fields | 1,619 |
| SYSTEM rows | 0 |
| Parse success | 100% |
| Parser error rate | 0% |
| Structural warning rate | 0% |
| Unresolved application rate | 7.1739% |
| Identified application rows | 717,397 |
| Incomplete session rows | 47,947 |
| Unidentified application rows | 6,302 |
| Insufficient-data rows | 1,245 |
| Absent/not-applicable application rows | 660 |

Before v5.12, 48,607 rows (6.2836%) were represented by the broad
`unknown or incomplete application` parser warning. After v5.12, structural
warning rate is 0%, while 55,494 rows (7.1739%) remain honestly visible as
unresolved application data quality. The higher unresolved count is expected:
it now includes PAN-OS unidentified and insufficient-data states instead of
hiding them or calling them parser failures.

No SYSTEM rows were present in this file. SYSTEM compatibility is therefore
supported by the official field contract and synthetic regression tests, not
claimed as private-device validation.

## Profile-Aware Baseline Behavior

The governed baseline catalog is derived only from the v5.6
`development_fit` aggregate:

- support: 352,312 rows;
- evidence role: governed development-fit aggregate;
- labels used for baseline selection: no;
- accuracy used: no;
- source identity used: no;
- locked-final evidence used: no.

Selection policy:

1. Use a parser-profile/source-type baseline only when the exact profile has
   at least 200 governed rows.
2. Use the governed global baseline for comparable Palo Alto profiles when an
   exact source-type baseline is unavailable.
3. Return `Insufficient Evidence` for incompatible profiles such as generic
   syslog or raw fallback instead of comparing unlike schemas.
4. Never create a per-device baseline that could normalize away real drift.

Current observation coverage:

- five windows use the supported `palo_alto/firewall` profile baseline;
- three `palo_alto/file_import` windows use conservative global fallback;
- seven legacy warning windows are reclassified into structural quality and
  unresolved-application signals.

## v5.11 Versus v5.12

The current effective operational state remains `OOD Warning`.

| Measure | v5.11 | v5.12 |
| --- | --- | --- |
| Effective state counts | Stable 1, Drift 2, OOD 3, insufficient 2 | Stable 1, Drift 2, OOD 3, insufficient 2 |
| Mean queue rate | 0.672734 | 0.672734; not recomputed |
| Mean disagreement rate | 0.278047 | 0.278047; not recomputed |
| Legacy warning windows separated | No | 7 |
| Baseline provenance | Implicit global | 5 exact profile, 3 global fallback |
| Accuracy calculated | No | No |

The unchanged OOD state is important. v5.12 removes misleading parser-quality
causes but does not hide genuine application-distribution, queue, or
disagreement shifts.

## Controlled Detection Equivalence

The one-variant layered comparison passed:

- 24 scenarios;
- 96 mode runs;
- 96 passed;
- 0 failed;
- 0 controlled false positives;
- 0 controlled false negatives; and
- exact match to the frozen aggregate projection.

No configured database row, model artifact, label, alert, detection run, or
response action was changed by the comparison.

## API And Dashboard

Authenticated analyst/admin endpoint:

```text
GET /api/ml/supervised/shadow-operations/parser-quality
```

AI Governance adds a collapsed Parser Profile Baseline panel showing:

- parser contract version;
- current aggregate state;
- exact-profile versus global-fallback counts;
- structural parser error/warning rates;
- unresolved application rate; and
- opaque source/time scopes.

The panel exposes no raw rows, source identity, IP addresses, labels,
accuracy, private paths, or secrets.

## Verification

Final closure results:

- taskboard render and supervisor-standard check: passed;
- Ruff and compileall: passed;
- backend tests: `732 passed, 1 skipped`;
- Alembic check: no new upgrade operations;
- React lint and production build: passed;
- Playwright: `26 passed, 1 skipped`;
- controlled detection scenarios: `24/24`;
- layered detection validation: `288/288`, zero controlled false positives
  and zero controlled false negatives;
- deterministic assistant QA: `20/20`, with zero response, detection, label,
  model, alert, log, or feedback side effects;
- private disposable preflight: 120,000/120,000 rows parsed, no structural
  warning, no private path/raw row/IP/source identity/secret returned;
- complete private aggregate audit: 773,551/773,551 rows parsed;
- replay dry-run: two safe rows parsed and zero rows written;
- performance smoke: no warnings, Overview `0.1595s`, cached Overview
  `0.0110s`, ML Governance `0.2847s`, alerts `0.0309s`, cases `0.0704s`;
- official release gate: `ok=true`, including an independent
  `732 passed, 1 skipped` backend run;
- `git diff --check`: passed; and
- protected tracked artifact count: zero.

One initial release-gate attempt encountered an ignored pytest fixture tree
left inside `atdr/data/processed` by a Windows path-length experiment. The
tree was moved to ignored `.tmp` storage, compileall passed, and the complete
release gate then passed. Runtime source and configured data were not changed.

## Safe Commands

Private aggregate preflight only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v512_parser_profile_baseline_repair `
  --sample-path "<PRIVATE_PANOS_PATH>" `
  --preflight-only `
  --limit 120000 `
  --pretty
```

Full read-only comparison with disposable controlled validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v512_parser_profile_baseline_repair `
  --sample-path "<PRIVATE_PANOS_PATH>" `
  --use-temp-db `
  --limit 120000 `
  --pretty
```

The command never returns the private path, raw rows, IP addresses, source
identifiers, or secrets.

## Remaining Evidence

- A real SYSTEM-log sample is still needed to validate the official/synthetic
  SYSTEM contract against an actual device.
- Generic syslog and raw fallback need their own governed profile baselines
  before comparable drift classification is possible.
- Independent multi-device, multi-period, legitimately human/provider-labeled
  evidence remains mandatory before supervised ML can move beyond
  `shadow_observation`.
- Existing legacy normalized rows are not reparsed automatically. A future
  explicit, backed-up, migration-safe reparse design would be a separate
  approved change.

The exact source-controlled v5.12 path set is recorded in
`docs/V5_12_COMMIT_ALLOWLIST.md`. It authorizes no staging, commit, or push.
