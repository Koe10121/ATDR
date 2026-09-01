# v5.51 Detection Pipeline Field Qualification And Fresh Evidence

Date: 2026-08-31

## Decision

ATDR now has one fail-closed qualification path for field transport, PAN-OS
parsing, deterministic-rule accuracy review, and fresh evidence custody. Every
locally implementable control is present and controlled-tested. Overall field
readiness is `hardware_required` because no physical firewall/router run,
second physical source, or independent field review was supplied in this
phase.

The phase does not change detection authority. Deterministic rules remain
alert-authoritative. IsolationForest and supervised outputs remain advisory.
The supervised lifecycle remains `shadow_observation`; no model was activated,
promoted, trained, or written. Automatic response and real firewall blocking
remain disabled.

## Implemented Surface

- `atdr/app/services/v551_field_qualification_service.py` coordinates the
  disposable acceptance workflow and enforces privacy, custody, and readiness.
- `atdr/scripts/run_v551_detection_field_qualification.py` provides a bounded
  operator CLI. `--use-temp-db` is mandatory.
- The parser harness records TRAFFIC, THREAT, and SYSTEM layout compatibility,
  required-field missingness, parse accounting, and exact/near duplicate
  aggregates.
- Field expectations are accepted only through a versioned, independently
  human-confirmed private JSON contract. Only aggregate accuracy is returned.
- Rule diagnostics reuse the production deterministic rule and grouping path.
  A prediction-blind review CSV is separated from a private prediction seal.
- Threat-positive human decisions require an attack type. Assisted or AI
  identities are rejected; completed reviews are never imported automatically.
- Fresh evidence begins at the public boundary
  `2026-09-01T00:00:00+07:00`. Pre-boundary and missing-time rows are excluded.
- Exact duplicates are removed and near-duplicate families are assigned to one
  role only: development fit, calibration, threshold, or untouched future
  evaluation.
- An authenticated aggregate status is available at
  `GET /api/evidence-review/field-qualification/status` and in AI Governance.
- Public output is rejected if it contains an IP address, raw row, private
  path, source identity, fingerprint, token salt, or secret.

## Measured Local Result

The safe local preflight and full controlled pass both completed successfully.

| Check | Result |
| --- | --- |
| Local disposable preflight | Pass |
| Loopback UDP accounting | `5/5`, loss `0`, parse failures `0` |
| Tracked sample parsing | `2/2`, success `1.0000`, known layout `2` |
| Source-health contract | Pass |
| Controlled rule diagnostics | Two rows evaluated; one alert-eligible group |
| Physical firewall/router transport | Not supplied; required |
| Human field mapping | Not supplied; required |
| Prediction-blind rule review | Not supplied; required |
| Fresh attested evidence | `0` rows, `0/2` sources, `0/4` windows |
| Protected v5.49b evidence accessed | `false` |
| Labels/models/alerts/detection runs/responses written | `0/0/0/0/0` |
| Overall readiness | `hardware_required` |

The tracked sample result proves the local harness and contract, not field
accuracy. Rule precision, recall, F1, and false-positive rate remain withheld
until a genuine prediction-blind review is complete.

## Readiness State Machine

The public readiness enum has exactly five states:

1. `failed`: local disposable transport, parsing, accounting, source health,
   or safety failed.
2. `hardware_required`: no truthfully attested non-loopback firewall/router
   acceptance exists.
3. `reviewer_required`: physical transport passed, but field mapping or the
   prediction-blind rule review is incomplete.
4. `insufficient_evidence`: review passed, but source, window, row, or untouched
   future-role minimums are not met.
5. `ready`: every fixed gate passed.

The minimum evidence contract is two independently attested physical sources,
four disjoint post-boundary windows, 240 duplicate-contained rows, at least 40
rows in the untouched future role, and at least 40 complete prediction-blind
human decisions. These are qualification minimums, not a production SLA.

## Safe Commands

Local preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v551_detection_field_qualification --use-temp-db --preflight-only --pretty
```

Controlled local run without persistent generated output:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v551_detection_field_qualification --use-temp-db --no-report --pretty
```

The physical-source command and private input contracts are documented in
`docs/detection/V5_51_FIELD_QUALIFICATION_CONTRACT.md`. Generated reports,
manifests, seals, and review workspaces remain under ignored
`ml_baseline_reviews/v5_51_field_qualification/`.

## v5.49b Boundary

v5.51 does not import the v5.49b evaluator and does not open its reviews,
predictions, claim, result, identities, or fingerprints. Disjointness uses only
the public completion boundary recorded by v5.50. A row before that boundary
cannot enter any v5.51 role. The untouched future role remains label-closed.

## External Gates

- **Hardware/network owner:** configure a non-loopback firewall or router
  sender and provide a second independently verified physical device.
- **Human reviewer:** attest each collection, confirm parser fields against the
  device/source truth, and complete prediction-blind rule decisions.
- **Student/team:** schedule at least four honest post-boundary collection
  windows and preserve their private custody.
- **Repository owner:** separately approve any future commit or push.

Codex cannot truthfully replace any of these with loopback traffic, synthetic
identities, assisted labels, guessed values, or copied historical evidence.

## Remaining Roadmap

Three substantial shared-lab phases remain after v5.51:

1. v5.52 Analyst Experience And Assistant Closure.
2. v5.53 MFU IAM And Shared Deployment Acceptance.
3. v5.54 Release Candidate Closure.

Field detection qualification can be completed alongside those phases once
hardware and reviewers are available. A later supervised repair cycle may use
only the new development roles; it may not tune on the untouched future role or
the consumed v5.49b result.

## Verification

The v5.51-focused backend suite passes `11/11`. The full backend suite and
release gate pass `1037` tests with `1` intentional skip. Alembic reports no
new upgrade operations; React lint/build pass; Playwright passes `37` tests
with `1` intentional live-source skip; controlled and layered detection pass
`24/24` and `288/288` with zero controlled FP/FN; Assistant QA passes `20/20`;
replay remains dry-run; and the large-SQLite performance budgets pass. The
local qualification preflight/full runs also pass with `5/5` UDP accounting,
`2/2` parser rows, zero loss/parse failures, one rule-eligible group, and zero
authoritative writes. Repository privacy, staging, and exact-path checks are
recorded in the taskboard and allowlist.

No commit or push is authorized by this document.
