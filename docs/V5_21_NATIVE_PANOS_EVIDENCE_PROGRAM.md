# v5.21 Native PAN-OS Evidence Program

Date: 2026-08-01

## Decision

v5.21 creates a privacy-safe, native-schema evidence foundation for the next
supervised model rebuild. The complete private PAN-OS stream was parsed into a
disposable SQLite index and divided chronologically before any assisted
decision was calculated. Exact and near-duplicate families do not cross role
boundaries.

This phase does not create ground truth. Development suggestions are explicitly
weak/assisted and require human confirmation. The blind verification pack has
no rule, model, or AI suggestions and remains unopened for model development.
Neither pack is import-ready.

The lifecycle remains `shadow_observation`. Deterministic rules remain
alert-authoritative. No model was activated or promoted, and automatic response
and real firewall blocking remain disabled.

## Measured Native Evidence

| Measure | Result |
| --- | ---: |
| Nonblank rows | 773,551 |
| Parser successes | 773,551 |
| Parser failures | 0 |
| TRAFFIC rows | 771,932 |
| THREAT rows | 1,619 |
| Chronological minute windows | 22 |
| Exact duplicate rows | 0 |
| Near-duplicate rows | 52,881 |
| Exact families crossing roles | 0 |
| Near families crossing roles | 0 |

The role lock contains:

| Evidence role | Rows | Purpose |
| --- | ---: | --- |
| Development fit | 433,499 | Model fitting only |
| Calibration | 116,422 | Probability calibration only |
| Threshold | 111,626 | Queue-threshold selection only |
| Untouched future validation | 112,004 | Sealed blind/final evaluation only |
| Quarantine | 0 | Excluded evidence |

The complete run used an explicit in-memory overlap target. It did not inspect,
open, or write the configured database. Its pre/post database file marker was
unchanged.

## Review Packs

Two ignored local files were generated under `ml_baseline_reviews/`:

- a 120-row development pack with weak assisted suggestions; and
- a 40-row untouched-future verification pack with no suggestions.

Both packs are stratified across native behaviors including vendor THREAT
records, scan-like behavior, routine allowed traffic, QUIC/443,
incomplete/80, unknown TCP/UDP, and other context. They contain no raw log,
source IP, destination IP, local source path, reusable row fingerprint, or
secret.

The development pack records `human_reviewed=false`,
`human_must_confirm=true`, and `import_ready=false`. The blind pack additionally
records `blind_suggestion_suppressed=true`; its human decision fields are blank.

## PAN-OS Semantics

The field contract is documented in
`docs/detection/V5_21_PANOS_FIELD_CONTRACT.md` using official Palo Alto
Networks documentation.

Important interpretation limits are:

- TRAFFIC logs describe sessions; allow/deny, application risk, or an unusual
  port is context, not malicious ground truth by itself.
- THREAT logs indicate a Security Profile match; severity and action support
  prioritization but still require analyst context.
- application risk is contextual and cannot independently establish a
  malicious label.
- parser success does not imply a correct security label.

## Defect Found And Repaired

The first full v5.21 run passed `None` to a reusable v5.6 overlap helper. In
that helper, `None` means use the configured database URL. It opened the local
SQLite database read-only for fingerprint comparison and quarantined 120,000
overlapping rows. No data was written or deleted, but the v5.21 claim that the
configured database was not accessed was incorrect.

v5.21 now passes `sqlite:///:memory:` explicitly. A regression test requires
that value. The corrected complete run reported zero configured-database
overlap checks, zero quarantine rows, and an unchanged configured-database
marker.

## Safety And Side Effects

The corrected run created:

```text
configured database reads: 0
configured database writes: 0
labels: 0
model artifacts: 0
model activations/promotions: 0
alerts: 0
detection runs: 0
response actions: 0
```

The disposable derived-feature index was removed when the run completed. Local
manifests, packs, and reports remain ignored and must not be committed.

## Remaining Gate

The native stream provides sufficient schema-compatible development evidence
for a diagnostic v5.22 rebuild, but it does not provide independent human
ground truth or a second real device. A qualified human/advisor must verify an
adequate native set before any accuracy or activation claim. v5.22 must freeze
its candidate, calibration, threshold, and acceptance gates before opening any
blind decisions.

Five closure phases were present at the start of v5.21. With this phase
complete, four remain:

1. v5.22 supervised model rebuild;
2. v5.23 live-source acceptance;
3. v5.24 investigation and Gemini quality lock; and
4. v5.25 integrated acceptance.

The locally controllable path remains approximately four to eight focused
weeks. Human labels, a second source device, and provider/deployment approvals
can extend that schedule.

No commit or push is authorized by this phase.

## Verification

- taskboard render and standard checks: passed;
- Ruff and compileall: passed;
- focused v5.21 tests: `5 passed`;
- full backend and release-gate backend runs: `800 passed, 1 skipped` each;
- Alembic: no drift;
- React lint and production build: passed;
- Playwright: `27 passed, 1 skipped` (live-hardware test remains external);
- controlled detection: `24/24` passed;
- layered detection: `288/288` passed with zero scenario false positives or
  false negatives;
- deterministic Assistant QA: `20/20`, citation rate `1.0`, unsafe refusal
  passed, and zero authoritative side effects;
- Gemini configuration status: provider/model/key configured, raw logs
  disabled, redaction enabled, and no secret exposed; no paid provider call was
  required for this phase;
- replay dry-run: two safe rows parsed and zero rows sent/written;
- performance smoke: passed with no warnings; and
- release gate: `ok=true`, no failed required checks.

The scikit-learn regression suite retains existing warnings about all-missing
legacy features and sample weights not reaching some calibrated base
estimators. v5.22 must address those behaviors explicitly in its frozen model
contract; they do not invalidate v5.21 evidence preparation.
