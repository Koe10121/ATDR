# v5.33 Independent Detection Evidence And Assistant Human Acceptance

## Status

v5.33 is a fail-closed evidence and acceptance workflow. It does not train,
activate, promote, or write a model. It does not create labels, alerts,
detection runs, users, or response actions. Deterministic rules remain alert-
authoritative; IsolationForest and supervised ML remain advisory; Gemini
remains read-only.

## Detection Evidence

- The existing sealed native PAN-OS blind pack contains 40 rows.
- Predictions were frozen before label access.
- Prediction tokens and review tokens are unique.
- Cross-role exact and near-duplicate overlap checks pass.
- The sealed pack covers one sanitized review day.
- The larger private native collection contains 773,551 parsed rows across 22
  chronological windows.
- Current configured labels represent one source identity and one calendar
  day; the source schema does not record independent physical-device
  attestation.
- A second verified real device is not available.
- Legitimate blind human decisions are `0/40`.
- Frozen detection metrics are therefore withheld.

The review helper now reports `working_copy_not_prepared` safely when its
optional working copy does not exist. The v5.33 command can create or resume
the ignored working copy, but it never fills human decisions.

## Frozen Supervised Gates

The gates are fixed before any blind label is opened:

| Gate | Required value |
| --- | ---: |
| Independent human blind labels | at least 20 |
| Comparable independent rows | at least 1,000 |
| Rows per binary queue class | at least 100 |
| Verified real source identities | at least 2 |
| Independent time windows | at least 2 |
| Queue F1 | at least 0.85 |
| Threat recall | at least 0.80 |
| Benign-like false-positive rate | at most 0.05 |
| Suspicious recall | at least 0.70 |
| Malicious recall | at least 0.70 |
| Expected calibration error | at most 0.10 |
| Maximum confidence/accuracy gap | at most 0.15 |

No metric is calculated until the review-copy, provenance, class-support,
blindness, and evidence-lock requirements pass. The blind set cannot be used
for retraining or threshold selection.

## Assistant Acceptance

v5.33 creates one ignored, integrity-protected human worksheet with eight
representative questions spanning:

- alert explanation;
- related-alert evidence and contextual follow-up;
- safe pre-response checks;
- log explanation;
- source health;
- case handoff;
- investigation brief; and
- ML governance.

The worksheet contains sanitized questions, answers, and trusted citation
references. It excludes raw logs, IP addresses, source names, private paths,
secrets, and action controls. Human fields are blank and
`human_must_confirm=true`; the file is never import-ready.

Human reviewers score factual correctness, evidence grounding, citation
correctness, relevance, concision, actionable usefulness, privacy, and unsafe-
action refusal from 1 to 5. They also record an overall `accept`, `revise`, or
`reject` decision, reviewer provenance, and a timezone-aware timestamp.
Automated or AI reviewer identities are rejected.

## Current Gemini Result

The bounded provider probe used a disposable, redacted snapshot of three
alerts, 24 linked normalized logs, three sanitized sources, and three case
inputs. No raw-log values, IP values, or real source names were copied.

- Gemini was accepted for seven of eight questions.
- The ML-governance question used the safe deterministic fallback and still
  passed its automated contract.
- One Gemini investigation brief exceeded the current concision acceptance
  rule; the other seven cases passed their automated contracts.
- The ML-governance case retained decision-support, lifecycle, promotion, and
  response-safety meaning.
- Timeout/failure fallback passed.
- Configured-database mutations were zero for every authoritative table.
- Human acceptance remains `0/8`; automated checks are not human approval.

Provider usage and latency are measured only as aggregate telemetry. Cost is
reported only when per-million-token rates are configured. Provider account
quota is not introspected. University/provider privacy, retention, quota, and
key-rotation approval remains external.

The measured private provider run used seven Gemini calls with median/P95
latency of `2,883.5/6,574 ms` and `24,324` total tokens. Pricing rates were not
configured, so no cost claim is made.

## Verification

- Taskboard render/check, Ruff, source compile, and Alembic drift checks pass.
- Full backend and official release suites pass: `879 passed, 1 skipped`.
- React lint/build and npm audit pass; Playwright reports `31 passed, 1
  skipped`.
- Controlled scenarios pass `24/24`; layered detection passes `288/288` with
  zero controlled false positives or false negatives.
- Deterministic Assistant QA passes `20/20`, all citation and word-budget
  checks, and every no-side-effect check.
- The private disposable preflight parses `773,551/773,551` rows across 22
  windows with zero failures, no configured-database access/write, and no
  private values returned.
- Replay dry-run parses `2/2` rows and writes nothing.
- The final performance rerun is warning-free: Overview `0.3163s`, cached
  Overview `0.0119s`, ML Governance `0.2850s`, alerts `0.0336s`, and cases
  `0.0618s`. An immediately preceding cold run measured Overview `2.1305s`,
  so cold local SQLite I/O remains a monitored operational risk.
- The official release gate returns `ok: true` with no failed required checks.

The literal compile command initially discovered ignored malformed Python
fixtures left by earlier tests under `atdr/data/processed/`. Actual source and
release compilation pass with the repository's standard processed-data
exclusion; those unrelated local artifacts were not modified.

## Commands

Safe status without writes or provider calls:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v533_independent_detection_assistant_acceptance --no-write --pretty
```

Create or resume both ignored human worksheets without filling decisions:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v533_independent_detection_assistant_acceptance --prepare-detection-review --prepare-assistant-review --pretty
```

Refresh an untouched Assistant worksheet using the configured bounded Gemini
provider:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v533_independent_detection_assistant_acceptance --prepare-assistant-review --refresh-assistant-review --execute-provider --provider-interval-seconds 1 --pretty
```

The refresh command refuses to overwrite a worksheet containing human input.

## Lifecycle Decision

Supervised lifecycle remains `shadow_observation`. No candidate is selected or
promoted. Production promotion, automatic response, and real firewall blocking
remain false. Four major evidence/productization phases remain:

1. Complete legitimate blind human detection review and the one-shot frozen
   evaluation.
2. Validate live ingestion and source holdout with a second verified physical
   device.
3. Make a governed supervised lifecycle decision only if every frozen gate
   passes.
4. Complete Assistant human acceptance and institutional Gemini privacy,
   quota, retention, and key-rotation approval.
