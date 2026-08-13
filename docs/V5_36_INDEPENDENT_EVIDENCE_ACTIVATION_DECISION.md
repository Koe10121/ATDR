# v5.36 Independent Evidence Execution And Supervised Activation Decision

## Status

v5.36 executes the remaining locally available detection and Assistant
evidence gates through one read-only coordinator. It reuses the v5.26 sealed
prediction lock, v5.27 strict human validator and frozen evaluator, v5.28
review helper and artifact audit, v5.30 registered-shadow diagnostic, and
v5.33 Assistant acceptance workflow. It does not introduce a second evidence
or activation source of truth.

The final decision is `shadow_observation`. No model was activated or
promoted. Rules remain alert-authoritative. Automatic response and real
firewall blocking remain disabled.

## Sealed Detection Evidence

The private blind pack contains 40 rows. Prediction-before-label integrity,
sealed identities, checksums, schema contract, unique review tokens, exact
role isolation, near-duplicate role isolation, and review-copy integrity pass.
Predictions, review tokens, fingerprints, raw logs, IP addresses, reviewer
identities, and private absolute paths are not returned.

Current human-review status is:

| Measure | Result |
| --- | ---: |
| Sealed rows | 40 |
| Valid genuine human decisions | 0 |
| Incomplete rows | 40 |
| Invalid rows | 0 |
| Binary queue classes represented | 0 |
| Frozen metrics returned | no |

No AI, rule, assisted, weak, Codex, Gemini, or synthetic decision is counted
as human review. The fixed prediction values remain hidden and precision,
recall, F1, false-positive rate, calibration, queue rate, and error findings
remain withheld until the strict intake contract passes.

## Registered Shadow Diagnostic

The registered calibrated ExtraTrees artifact remains checksum-valid for
read-only shadow scoring. The configured database provides 1,672 current
human-provenance rows, but they represent one source identity and one calendar
day, and training overlap cannot be independently excluded. These results are
diagnostic only and are not activation evidence:

| Metric | Configured-data diagnostic |
| --- | ---: |
| Queue precision | 0.8074 |
| Queue recall | 0.5036 |
| Queue F1 | 0.6203 |
| Benign-like false-positive rate | 0.1167 |
| Suspicious recall | 0.3511 |
| Malicious recall | 0.6452 |
| Macro / weighted F1 | 0.6835 / 0.6845 |
| ECE | 0.2101 |
| Maximum confidence/accuracy gap | 0.5723 |

The single-day temporal diagnostic is weaker: queue F1 `0.2319`, FPR
`0.2354`, suspicious recall `0.1290`, malicious recall `0.3265`, and ECE
`0.6285`. The grouped source holdout fails closed because a second verified
source is unavailable. Repeated grouped random diagnostics also miss the fixed
quality gates. None of these views changes the sealed evaluation or model
lifecycle.

## Fixed Activation Decision

The v5.30 fixed gates are reused without threshold changes. Current results:

- evidence gates: `3/9` pass;
- blind quality gates: `0/7` evaluated;
- eligible for separate manual activation review: `false`;
- model activated/promoted: `false/false`;
- response automation allowed: `false`.

Passing evidence gates are blind custody integrity, registered artifact
integrity, and fail-closed schema abstention. Current blockers are:

- zero legitimate blind human decisions;
- fewer than 1,000 independent comparable labeled rows;
- fewer than 100 rows in each binary queue class;
- one represented source identity instead of two;
- one sanitized labeled window instead of two;
- configured-data training overlap is not independently excludable; and
- all seven sealed quality metrics are therefore not evaluable.

Even a future all-green result only permits a separate explicit activation
review. The v5.36 command never writes or activates an artifact.

## Assistant And Gemini Acceptance

The existing eight-case Assistant worksheet remains integrity-protected and
passes all automated response contracts. Human acceptance is still `0/8`, so
no human semantic, usefulness, or privacy approval is claimed.

The bounded live Gemini audit passed `12/12` automated checks over six calls:

| Measure | Result |
| --- | ---: |
| Provider calls | 6 |
| Median / p95 latency | 2,879.5 / 3,832 ms |
| Input / output tokens | 20,092 / 1,480 |
| Total tokens | 21,572 |
| Raw logs or IPs sent | no |
| Configured DB mutations | 0 |
| Assistant actions executed | 0 |

Provider availability and automated answer contracts pass for this bounded
run. Provider account quota is not introspected, pricing rates are not
configured, key rotation remains a manual external procedure, and MFU/provider
privacy and retention approval remains external.

## Human Handoff

Detection review uses:

- working copy: `ml_baseline_reviews/v5_28_blind_human_review_working.csv`;
- guide: `docs/detection/V5_27_BLIND_REVIEWER_GUIDE.md`.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --prepare --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --interactive --reviewer "<institutional-id>" --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --status --pretty
```

Assistant acceptance uses
`ml_baseline_reviews/v5_33_assistant_human_acceptance_working.csv`. A genuine
reviewer must score all eight cases from 1 to 5, choose `accept`, `revise`, or
`reject`, add a real reviewer identity and timezone-aware timestamp, and set
the human confirmation fields. Neither worksheet is import-ready.

## Safety And Remaining Programs

All configured raw-log, normalized-log, alert, detection-run, label,
model-run, response-action, user, and audit counts remained unchanged.
No model artifact, label, alert, detection run, user change, or response was
created.

Four major programs remain:

1. qualified blind detection review with sufficient independent labeled support;
2. validation against a second verified physical log source;
3. Assistant human acceptance and institutional Gemini operations approval;
4. MFU/shared-preproduction operational acceptance.

## Verification

The local v5.36 closure matrix passed:

- taskboard render and standards check;
- Ruff and source-only `compileall`;
- focused regression: `43 passed`;
- full backend and release gate: `902 passed, 1 skipped`;
- Alembic: no new upgrade operations;
- npm audit: zero vulnerabilities;
- React lint and production build;
- Playwright: `31 passed, 1 skipped` (live hardware source validation);
- controlled and layered detection: `24/24` and `288/288`;
- deterministic Assistant QA: `20/20` with zero side effects;
- replay dry-run: two safe sample rows parsed with zero writes; and
- performance smoke: no warnings; Overview `0.1536s`, cached Overview
  `0.0094s`, ML Governance `0.2341s`, alert list `0.0305s`, and case summary
  `0.0507s`.

The existing scikit-learn missing-feature diagnostics remain warnings rather
than failures. No verification step activated a model or changed configured
authority data.

## Commands

Read-only decision audit:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v536_independent_evidence_activation_decision --no-write --pretty
```

Bounded redacted Gemini operations audit:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v536_independent_evidence_activation_decision --execute-provider --provider-interval-seconds 1 --no-write --pretty
```

Generated reports stay under ignored `ml_baseline_reviews/` and must not be
committed.
