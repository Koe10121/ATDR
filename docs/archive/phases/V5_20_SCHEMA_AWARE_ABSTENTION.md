# v5.20 Schema-Aware Abstention

Date: 2026-08-01

## Decision

v5.20 closes the unsafe inference behavior exposed by v5.19. Governed
supervised scoring now validates evidence against the native PAN-OS contract
before calling the model. Evidence from an incompatible, unknown, failed-parser,
or incomplete schema receives an explicit abstention and no supervised
probability.

Deterministic rules remain alert-authoritative. An abstention does not suppress
an alert, reduce severity, or stop rule evaluation. The supervised lifecycle
remains `shadow_observation`; no model was activated or promoted, and automatic
response and real firewall blocking remain disabled.

## Root Cause

The v5.19 CTU-13 transfer used bidirectional flow evidence against a model built
from PAN-OS-oriented features. Seventeen candidate fields were unavailable, yet
the prior runtime scorer measured missing values only after inference. Imputation
could therefore turn incompatible evidence into a confident queue decision.

This was a contract-ordering defect, not proof that CTU traffic was malicious.
The compatibility decision now runs before inference.

## Runtime Contract

The governed supervised model expects `palo_alto` evidence with these required
fields:

- timestamp;
- source and destination IP presence;
- destination port;
- protocol;
- action; and
- application.

Historical normalized rows without explicit `parser_profile` metadata retain
ATDR's established Palo Alto parser default, but they must still pass every
required-field check.

| Status | Model behavior | Rule behavior |
| --- | --- | --- |
| `compatible` | Score in shadow/decision-support mode | Authoritative |
| `incompatible_schema` | Abstain; no probability | Continues |
| `unknown_schema` | Abstain; no probability | Continues |
| `parser_error` | Abstain; no probability | Continues |
| `insufficient_evidence` | Abstain and list missing fields | Continues |

Compatibility output is aggregate or field-name-only. It contains no raw log,
IP address, source identity, local path, row fingerprint, or secret.

## User-Facing Evidence

- Alert explanations expose `abstained`, schema status, reason codes, and missing
  required field names.
- The Alerts drawer displays **Abstained** instead of a misleading zero
  threat-positive score.
- AI Governance displays a **Schema Gate: Fail closed** state and aggregate
  runtime abstention counts.
- Technical schema policy details remain collapsible.

## v5.19 Terminal Lock

The v5.20 validation command verifies the completed v5.19 state and result files,
records their fingerprints only in ignored local output, and does not open the
provider labels or frozen prediction rows. The local validation confirmed:

- evaluation completed;
- adapter recovery completed;
- predictions were frozen before labels;
- no post-reveal candidate change occurred;
- labels were not used for features, prediction, sampling, or tuning; and
- both terminal records remained unchanged.

Run the safe check with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v520_schema_aware_abstention --pretty
```

The command accesses no configured database and returns no private fingerprint.

## Safety And Side Effects

The implementation does not write labels, model runs, detection runs, alerts,
response actions, or active model artifacts. It does not change the database
schema. Rule detection, legacy local startup, import/replay, and response safety
remain unchanged.

## Verification

- focused v5.20/lifecycle/shadow/evidence/explanation tests: `25 passed`;
- supervised ML regression suite: `39 passed`;
- frontend lint and production build: passed;
- focused Playwright schema-governance and alert-abstention tests: `2 passed`;
- local v5.19 terminal-lock validation: passed;
- taskboard render/standard checks, Ruff, compileall, and Alembic no-drift:
  passed;
- full backend and release-gate backend runs: `795 passed, 1 skipped` each;
- React lint/build and Playwright: passed (`27 passed, 1 skipped`);
- controlled detection: `24/24` passed with 15 expected/actual alerts and
  zero response actions;
- layered detection: `288/288` passed with zero scenario false positives or
  false negatives;
- deterministic Assistant QA: `20/20` passed with required citation rate
  `1.0` and zero authoritative side effects;
- replay dry-run: two safe rows parsed and zero rows sent or written;
- 145,232-row read-only performance smoke: no warnings; Overview `0.7752s`
  cold and `0.0098s` cached, AI Governance `1.3386s`, alerts `0.0683s`, and
  cases `0.0319s`; and
- release gate: `ok=true`, with no failed required checks.

## Remaining Program

v5.20 completes phase 1 of the six-phase detection-centered closure program.
Five phases remain:

1. v5.21 native PAN-OS evidence program;
2. v5.22 supervised model rebuild;
3. v5.23 live-source acceptance;
4. v5.24 investigation and Gemini quality lock; and
5. v5.25 integrated acceptance.

The locally implementable engineering path is approximately four to eight weeks
of focused work. Final supervised accuracy claims still require trustworthy
human/advisor-verified native labels. Real-device acceptance requires a firewall
or a clearly identified second-laptop transport test, and MFU/provider deployment
claims remain dependent on external approval.

No commit or push is authorized by this phase.
