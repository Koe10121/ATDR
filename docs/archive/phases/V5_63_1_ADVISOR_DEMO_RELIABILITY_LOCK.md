# v5.63.1 Controlled-Lab Detection And Advisor Demonstration Reliability Lock

Date: 2026-09-17

## Decision

ATDR is ready for a controlled advisor demonstration of its complete analyst
workflow. The disposable acceptance command passes ingestion, parsing,
normalization, authoritative rule detection, advisory anomaly scoring, alert
explanation, recommendations, case handoff, SOC Assistant quality, Gemini
connectivity, simulated response, and audit history.

Runtime truth remains deliberately conservative:

- deterministic rules: `active_authoritative`;
- IsolationForest: `legacy_artifact_advisory_only`;
- supervised ML: `unqualified`;
- hybrid output: advisory only;
- response: `simulation_only`;
- automatic response and real firewall blocking: disabled.

No supervised model was activated or promoted. No anomaly candidate replaced
the existing ignored artifact.

## Anomaly-Rate Diagnosis

The previously reported `0.98` value was a percentage, not a 0.98 fraction.
It also used all stored logs as its denominator even though not every row had
been anomaly-scored. The database snapshot contained:

| Measure | Result |
| --- | ---: |
| Stored normalized logs | 145,232 |
| Rows with anomaly scores | 60,230 |
| Current anomaly flags | 1,421 |
| Old stored-row prevalence | 0.98% |
| Correct scored-row anomaly rate | 2.36% |
| Scoring coverage | 41.47% |
| Latest bounded scoring run | 30 / 1,000 (3.00%) |

The API and dashboard now distinguish:

1. anomaly rate among scored rows;
2. percentage of the database covered by scoring; and
3. anomaly prevalence across all stored rows.

This removes the denominator ambiguity without changing any predictions,
alerts, labels, model artifacts, or response behavior.

## Development-Only Anomaly Audit

The private PAN-OS source was supplied only as a CLI argument. Public output
contains no path, raw record, network address, identity, fingerprint, or
secret. A bounded 50,000-row inspection found:

| Measure | Result |
| --- | ---: |
| Parsed rows | 50,000 |
| Parse rate | 100% |
| Complete anomaly feature schema | 99.77% |
| Baseline-eligible rows | 30,832 |
| Duplicate rate | 0% |
| Evidence gates | pass |

Chronological fit, calibration, and holdout roles were created in memory.
Eight fixed IsolationForest variants compared the current raw feature set and
log/context feature engineering at 1%, 2%, 3%, and 5% queue targets.

The existing legacy artifact produced:

| Controlled measure | Result |
| --- | ---: |
| Benign row anomaly rate | 17.78% |
| Suspicious scenario capture | 57.14% |
| Malicious scenario capture | 50.00% |
| Private eligible holdout queue rate | 2.08% |

The private-trained variants reduced controlled benign noise to 0%, but none
preserved enough controlled suspicious or malicious capture. At 3% and 5%,
the strongest raw-feature variants reached only 14.29%-28.57% suspicious
scenario capture and 50% malicious scenario capture. Every candidate failed
the fixed threat-capture gates.

**Decision:** no candidate selected and no artifact installed. This is safer
than replacing a partially useful artifact with a quiet but blind one.
IsolationForest remains unusualness evidence, not a maliciousness classifier.

## SOC Assistant And Gemini

The deterministic Assistant QA fixture passed all 30 intent cases and its
context-preserving follow-up sequence:

- relevance, grounding, citation correctness, concision, intent
  differentiation, follow-up continuity, privacy, and zero authoritative side
  effects all passed;
- average answer length is 56.1 words, down from the historical 283.8-word
  baseline;
- all response-mode word budgets passed;
- no response actions, detection runs, model runs, labels, alerts, or logs were
  created by Assistant answers.

The bounded live provider probe passed with Gemini:

- provider, model, and key configured: true;
- structured response valid: true;
- external call executed: true;
- raw log context included: false;
- IP redaction enabled: true;
- secrets exposed: false;
- deterministic fallback remains available.

Gemini improves wording and synthesis. ATDR database/service context and
approved documentation remain the source of facts.

## Advisor Acceptance Command

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_advisor_demo_acceptance `
  --use-temp-db `
  --execute-provider-probe `
  --pretty
```

The command uses disposable in-memory storage and does not access or reset the
configured database. Current acceptance passes all 10 stages and 24/24
workflow checks.

To rerun the private, development-only anomaly comparison without installing
anything:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_anomaly_reliability `
  --sample-path "<private-log-file>" `
  --limit 50000 `
  --pretty
```

Candidate installation is unavailable unless every fixed gate passes and an
exact confirmation is supplied. Current candidates do not qualify.

## Advisor Demonstration Flow

1. Start ATDR through the MFU shell and open Overview.
2. Show received and normalized log counts plus source/parser health.
3. Open a rule-created alert and show why it was flagged, related logs,
   evidence strength, and recommended checks.
4. Ask the SOC Assistant why the alert was flagged and one scoped follow-up.
5. Show AI Governance: rules authoritative, anomaly advisory, supervised
   unqualified, and anomaly rate based on scored rows.
6. Show Response & Audit: simulation only, analyst confirmation required, and
   no automatic blocking.

## Verification

- Taskboard render/standard check, Ruff, compileall, and Alembic: pass.
- Full backend: `1119 passed, 1 skipped`; repeated successfully by the release
  gate.
- React lint/build and Playwright: pass; `45 passed, 1 skipped`.
- Controlled source scenario: pass in temporary storage.
- Layered detection: `288/288`, zero controlled false positives and false
  negatives.
- Assistant QA: 30 cases plus contextual follow-up continuity; all quality and
  no-side-effect dimensions pass.
- Replay dry-run: pass with zero writes.
- Large SQLite performance: `ok: true`; cached Overview `0.0185s`; no warnings.
- Repository and security audits: pass with zero findings.
- Independent release gate: `ok: true`, no failed required checks.

## Remaining Limits

- The current IsolationForest artifact has legacy provenance and does not pass
  the new controlled reliability gates.
- Supervised ML remains unqualified after the governed no-candidate decision.
- Controlled synthetic scenarios validate behavior, not independent field
  accuracy.
- MFU provider acceptance, a second physical source, real firewall forwarding,
  and shared production infrastructure are intentionally deferred.

For the advisor demonstration, no further mandatory coding phase is required.
For the strongest controlled-lab detection product, two substantial internal
phases remain: window-aware anomaly redesign and completion of genuinely
reviewed supervised evidence followed by governed qualification. Independent
field certification remains external.
