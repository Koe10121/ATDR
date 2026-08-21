# v5.41 Governed Blind Evidence Acquisition

## Status

v5.41 is implemented as a privacy-safe collection and custody workflow. It
does not tune, train, freeze, activate, or promote a supervised model. The
supervised lifecycle remains `shadow_observation`, and deterministic rules
remain alert-authoritative.

Current public readiness is **Designed**:

- qualifying independently attested sources: `0 / 2`
- qualifying collection windows: `0 / 3`
- qualifying candidate rows: `0 / 240`
- prediction-blind review pack: not created
- frozen predictions: not created
- human review: not started
- frozen evaluation metrics: unavailable

This is the correct fail-closed result. Existing private evidence cannot be
renamed or reused as a new blind set.

## Evidence Boundary

The CLI revalidates both protected boundaries before inspecting any candidate
file:

1. The consumed v5.39 sealed evidence pack must still match its private
   custody digest. Only exclusion tokens are read; labels, predictions, and
   prior errors are not read.
2. The v5.40 development population is rebuilt without fitting or scoring a
   model. Its latest event time becomes a private cutoff, and its exact,
   near-duplicate, propagation, source, and duplicate-group boundaries are
   reserved from future evidence.

If either boundary is missing, altered, or internally inconsistent, v5.41
fails closed.

## Collection Contract

A collection can qualify only when all of the following are true:

- events occur strictly after the private v5.40 development cutoff
- the operator supplies a valid human source attestation
- the physical source does not overlap a development source identity
- the file has no configured-database, consumed-v5.39, or v5.40 overlap
- exact and near-duplicate families are contained
- parsing occurs in disposable SQLite storage
- no configured ATDR database count or model artifact changes

The complete review gate requires:

- at least two independently verified physical sources
- at least three disjoint collection windows
- at least 240 isolated review rows
- after genuine human review, at least 100 benign-like, 50 suspicious, and 50
  malicious decisions

Source names, window names, file paths, raw logs, IP addresses, identities,
and fingerprints are never returned by the public API or tracked reports.

## Safe CLI

Preflight the protected boundaries and current aggregate status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v541_blind_evidence_acquisition `
  --preflight-only `
  --pretty
```

Rehearse a private file without allowing it to qualify:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v541_blind_evidence_acquisition `
  --sample-path "C:\Path\Outside\Git\private-panos.log" `
  --source-name historical-rehearsal `
  --source-type firewall `
  --collection-window prior-evidence-rehearsal `
  --parser-profile palo_alto `
  --use-temp-db `
  --rehearsal-only `
  --pretty
```

A future qualifying run also needs `--source-attestation` pointing to a
private JSON document with:

```json
{
  "source_name": "operator-supplied-source-name",
  "collection_window": "operator-supplied-window-name",
  "physical_device_confirmed": true,
  "attested_by": "human reviewer identity",
  "attested_at": "ISO-8601 timestamp"
}
```

The attestation stays private. AI, bot, model, or assistant identities are
rejected as human attestors.

## Full-File Rehearsal Result

The existing private PAN-OS file was inspected through a CLI argument in a
disposable database. Only these safe aggregates were retained:

| Measure | Result |
| --- | ---: |
| Rows processed | 773,551 |
| Parser successes | 773,551 |
| Parser failures | 0 |
| Complete TRAFFIC rows | 771,932 |
| Complete THREAT rows | 1,619 |
| Configured-database overlap rows | 120,000 |
| v5.40 exact-overlap rows | 1,273 |
| v5.40 near-overlap rows | 1,619 |
| Rows at or before the cutoff | 117,162 |
| Rows strictly after the cutoff | 656,389 |
| Rows remaining after disposable exclusions | 653,498 |
| Candidate rows exercised | 240 |
| Represented strata | 8 |
| Parser/index runtime | approximately 171 seconds |

The file is **rehearsal only** and **never qualifying blind evidence**. It
overlaps configured and development evidence, lacks a qualifying independent
source attestation, and was already supplied during earlier development.

## Prediction-Blind Review

The review-pack generator is implemented but remains closed until the source,
window, row-count, custody, and frozen-candidate gates pass.

When those prerequisites exist:

1. Exactly one frozen diagnostic candidate produces predictions into a
   separate ignored seal.
2. The human CSV contains bounded parsed and behavioral evidence, human input
   fields, and opaque review references only.
3. It contains no prediction, score, suggestion, answer key, fingerprint,
   raw-log, or IP column.
4. Protected evidence columns are digest-bound. Editing them fails custody.
5. Human decisions remain invalid unless a genuine human reviewer explicitly
   confirms every row.
6. Metrics remain unavailable until review completion and class-support gates
   pass.

The pack is never marked import-ready automatically.

## AI Governance Surface

Authenticated users can read:

```text
GET /api/evidence-review/blind-evidence/status
```

The response is aggregate-only and exposes one of:

- `Designed`
- `Collecting`
- `Insufficient Sources`
- `Ready For Human Review`
- `Review Complete`
- `Ready For Frozen Evaluation`

The React AI Governance page shows source, window, row, human-review, and
lifecycle progress with `Predictions Withheld`, `Rules Authoritative`, and
`No Model Activation` safeguards.

## Verification Result

The complete local verification matrix passes:

- taskboard render and standards checks
- Ruff and source compile checks
- backend tests: `946 passed, 1 skipped`
- Alembic: no drift
- React lint and production build
- Playwright: `35 passed, 1 skipped`
- controlled port-scan scenario: passed with zero response actions
- layered detection validation: `288/288`, zero controlled false positives or
  false negatives
- SOC Assistant QA: `20/20`, zero authoritative side effects
- replay dry-run: passed without database writes
- performance smoke: all budgets passed with no warnings
- release gate: `ok: true`

Playwright initially identified horizontal overflow in the new readiness
metrics at laptop width. The responsive grid now uses three columns at that
width and five only on wider displays; the isolated regression and full
browser suite pass.

## Safety Result

The measured rehearsal confirmed:

- configured database counts unchanged
- labels written: `0`
- model runs written: `0`
- detection runs written: `0`
- alerts written: `0`
- response actions written: `0`
- model artifacts unchanged
- temporary evidence index removed
- raw logs, IPs, paths, identities, fingerprints, and secrets not returned
- automatic response disabled
- real firewall blocking disabled

## Remaining Supervised-ML Phases

Four governed phases remain before supervised decision-support activation can
even be considered:

1. **Evidence acquisition:** obtain two real independently verified devices,
   three future windows, and 240 isolated rows.
2. **Human blind review:** a genuine analyst completes all decisions and the
   class-support targets without seeing predictions.
3. **Frozen one-shot evaluation:** evaluate one previously frozen candidate
   exactly once against the sealed decisions.
4. **Governance decision and shadow observation:** only if every fixed quality,
   calibration, privacy, and stability gate passes, authorize a separate
   manual shadow activation and observe it longitudinally.

Phases 1 and 2 require external human/device evidence. Code cannot honestly
complete them alone. Failure at any phase keeps lifecycle at
`shadow_observation` and rules authoritative.

## Remaining External Blockers

- a second independently verified physical source
- three genuinely future collection windows across the source set
- 240 disjoint rows with enough reviewed class support
- a genuine human reviewer
- a stable diagnostic candidate frozen before labels are revealed
- advisor/owner approval for the final one-shot evaluation and any later
  shadow activation

No real response integration is part of this phase.
