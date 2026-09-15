# v5.32 Analyst Workflow Product Acceptance Lock

## Status

v5.32 closes the final large in-repository analyst-product phase that does not
require new human labels, university-provider access, an approved deployment
host, or real firewall hardware. The supported outer-shell startup, React
workflow, evidence links, Assistant context, simulated response safety, and AI
Governance contracts are acceptance-tested together.

This is a controlled lab acceptance lock, not a production-readiness claim.
Rules remain alert-authoritative, IsolationForest and supervised ML remain
advisory, the supervised lifecycle remains `shadow_observation`, Gemini remains
read-only, and automatic response and real firewall blocking remain disabled.

## Audit Findings

- `start_system.cmd` and `check_system.cmd` bring up and diagnose the four
  expected services through the configured template-shell profile. The `.cmd`
  wrappers also avoid local PowerShell execution-policy failures.
- Existing Assistant contracts already replace explicit entity IDs, clear
  stale context for latest-critical requests, preserve safe session context
  across navigation, distinguish alert and log IDs, enforce concise response
  budgets, and expose trusted entity citations.
- Existing browser coverage already exercises source/log/case/alert links,
  simulated response denial and audit, dropdown clickability, long-output
  containment, and desktop/laptop/mobile overflow.
- The missing product surface was a concise operational view joining governed
  rule volume, source-linked alerts, analyst dispositions, grouped occurrence
  counts, deduplication, parser context, and recent run trends.
- `docs/DASHBOARD_PRODUCTION_PATH.md` was stale: it described Streamlit as the
  main dashboard and Node as unavailable. React is now documented as the
  primary analyst application.
- A Windows pytest temp/cache ACL failure was isolated to an ignored repo-local
  test directory. The identical focused suite then passed; no application
  defect was involved.

## Detection Operations View

Overview now derives one read-only `detection_operations` projection from
existing alert, evidence, source, run, audit, and parser-quality state:

- `primary_rule_alert_volume` counts unique alerts by their primary governed
  rule code;
- `source_alert_volume` counts distinct alerts linked to each registered
  source, so duplicate evidence rows do not inflate a source count;
- `analyst_dispositions` reports current alert workflow statuses;
- `deduplication` separates unique alerts, grouped occurrences, dedup updates,
  and occurrences per alert;
- parser context distinguishes structural failures from unresolved application
  values; and
- recent run rows show evaluated, created, deduplicated, and suppressed counts.

The panel always labels operational accuracy as `Insufficient Evidence` and
states that volume and disposition are workload measures, not accuracy. Quality
claims remain governed by independent labeled validation in AI Governance.

## Assistant Acceptance

The acceptance lock confirms:

- conversation and active entity context survive supported navigation;
- explicit alert/log/source/case IDs replace old context;
- latest-critical requests send `reset_context=true` and no stale entity IDs;
- follow-ups remain bound to the intended current entity;
- direct answers remain concise, with evidence/provider detail collapsed;
- citations resolve to alert, log, source, case/run/job, API, or documentation
  references where available;
- Gemini is labeled as used only when its guarded answer is accepted;
- deterministic fallback remains truthful when Gemini is disabled, rejected,
  or unavailable; and
- Assistant requests create no response, detection, label, model, user, or
  deletion side effects.

Raw-log context remains disabled by default, IP redaction remains enabled, and
API keys, prompts, raw evidence, and secrets are not returned.

## Measured Local Performance

The read-only v5.32 profile used the existing large SQLite database without
resetting or modifying it. At 145,232 raw/normalized records and 3,231 alerts:

- application-cache cold Overview: 0.296-0.385 seconds;
- application-cache warm Overview: 0.013-0.015 seconds;
- cold query count: 33, below the fixed ceiling of 36; and
- warm query count: 1.

A first uncached cold-disk full-summary measurement took 4.4228 seconds and
remains a large-SQLite warning. It does not affect the fast cached path, but it
must remain visible until shared-host/PostgreSQL operational evidence replaces
local SQLite measurements.

## Verification

- Ruff and compileall: passed.
- Focused backend acceptance: 58 Assistant/explanation/workflow tests plus 8
  v5.32/dashboard-performance tests passed.
- Full backend: `873 passed, 1 skipped`.
- Alembic: no schema drift.
- React lint/build: passed; npm audit reports zero moderate-or-higher findings.
- Playwright: `31 passed, 1 skipped`; the skipped case requires an external
  live-source sender.
- Controlled detection: `24/24` scenarios passed.
- Layered detection: `288/288` runs passed.
- Assistant QA: `20/20`, required-citation pass rate `1.0`, average/max answer
  length `74.5/200` words, and no operational mutations.
- Replay dry-run: parsed 2/2 safe sample rows and wrote zero records.
- Performance smoke: Overview `0.3602s`, cached Overview `0.0131s`, ML
  Governance `0.2944s`, alert list `0.0391s`, case summary `0.0632s`, with no
  warnings.
- Official release gate: `ok: true` with no failed required checks.

The first full pytest invocation used an excessively long repository-local
Windows temporary path and failed only when a launcher test copied a backup
file. That test passed alone under `C:\t`, and the complete suite passed under
`C:\t\v532-full`. This is recorded as a Windows path-length test-environment
condition, not an ATDR runtime defect.

## Manual Acceptance

1. Start the system:

   ```powershell
   .\scripts\start_system.cmd
   ```

2. Open the printed MFU shell login URL and complete the configured handoff.
3. On Overview, inspect Detection Operations and confirm `Insufficient
   Evidence` appears for accuracy.
4. Open a source, then an alert, related log, and case. Confirm all links retain
   the selected entity and `Why flagged?` shows exact governed evidence.
5. Open SOC Assistant from the alert. Ask why it was flagged, ask for related
   logs, then ask what to check next. Navigate away and back; context should
   remain on the same alert.
6. Ask for the latest critical alert; any previously pinned alert must clear.
7. Confirm provider details identify Gemini only after a Gemini answer is used,
   raw logs are not included, and no action controls appear.
8. In Response & Audit, verify actions remain simulated, require confirmation
   and justification, and protected targets fail closed with an audit record.

## Remaining External Gates

Three major externally dependent programs remain:

1. qualified prediction-blind native labels from another real source/time
   window followed by one frozen supervised evaluation;
2. qualified human Assistant usefulness/privacy acceptance plus approved
   Gemini quota, retention, cost, key-rotation, and managed-host monitoring;
3. MFU/provider and shared preproduction acceptance with multi-device live
   source transport, backup/recovery, security monitoring, and named owners.

Real response enforcement remains a separate optional safety program. No
in-repository prompt can replace these external evidence and ownership gates.
