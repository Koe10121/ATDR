# v5.4 Temporal Evidence Curation And Shadow Drift Monitoring

Date: 2026-07-26

## Decision

v5.4 permanently records the v5.3 evidence roles, builds a development-only
manifest, audits chronological evidence quality, and adds aggregate shadow
drift monitoring. It does not tune, select, activate, promote, or write a model
artifact.

The supervised lifecycle remains `shadow_observation`. Deterministic rules
remain alert-authoritative. Production promotion, automatic response, and real
firewall blocking remain disabled.

## Locked v5.3 Evidence

The tracked lock contains hashes and aggregate metadata only. It contains no
raw log, IP address, private path, reviewer identity, or secret.

| Evidence role | Rows | SHA-256 fingerprint |
| --- | ---: | --- |
| Governed reviewed dataset | 2,235 | `ae3d2972bdb888f0fba7631932ae512f674e5dbdb9cc72c1d3cd633d67ec4420` |
| Fit | 957 | `95247df240aa7e65f010a6cc47bc225c4da3097de7048598dd79b7a1bc04d369` |
| Calibration | 282 | `db88af63bec5b80bc19c9b3fe17f89cbe77c768cd53a3ce7c2e80ecee4a97659` |
| Threshold selection | 228 | `00f542090cb05c1ba898c15815d6cb9cff174625358d246b6fd4774625d6ff10` |
| Temporal final | 532 | `db6a13ada1a1fed71e7ec9d013be138a98f1468e4551ee24729c17e4e875e71e` |
| Duplicate quarantine | 236 | `93841bb567c28cbc1f0d090a0b583769a38a84e7bbdabb78770959bf115f9e3d` |
| Rolling future 1 | 178 | `4cbef61cb835de319c37083e41c732872bb56708065a63dcc31f7025946a8d32` |
| Rolling future 2 | 178 | `b6bb23d4949a3fe8863a6434acfeee276b830199c108fc67bac2e7eb183657f1` |
| Rolling future 3 | 176 | `4b7a887236b7293d969c12f751457042486aa15f1fc5a3dcf2d2e7055d2177f5` |
| Locked external aggregate | Not reopened | `21b4f9daaf372be4419200265bb616e6186861832e220f43dd1ad6e3a33f4978` |
| Governed shadow artifact | 3,670,115 bytes | `b3ff7a891e863924ba5f770ce15fb1638b184969c050873e1d71071edc7f79bb` |

The temporal partition fingerprint is
`625975fb955f9d7499a8eaec0c01e40db9314fe8462456d87d6c31e85aa003c2`.
The lock fails closed if any role, rolling window, external evidence summary,
or artifact fingerprint changes.

## Chronological Evidence Audit

The audit found:

- label-distribution distance from fit to final: `0.7290`;
- provenance-distribution distance: `0.5737`;
- application-distribution distance: `0.7428`;
- schema-profile distance: `0.5791`;
- destination-port distance: `0.2153`;
- network-zone distance: `0.1288`;
- 1,749 duplicate-family groups, including 190 multi-row groups and 676 rows
  in multi-row groups;
- 126 exact, 190 near, and 10 feature-fingerprint duplicate groups;
- review activity concentrated into seven days, with 563 rows on the largest
  review day; and
- one real source device across the reviewed evidence.

Each selected normalized log has one current label row. No earlier label
decision is double-counted. Rule evidence is audited independently and is not
treated as human review.

## Development-Only Evidence Manifest

| Category | Rows |
| --- | ---: |
| Development evidence | 1,467 |
| Fit | 957 |
| Calibration | 282 |
| Threshold selection | 228 |
| Locked temporal final excluded | 532 |
| Duplicate quarantine excluded | 236 |
| Total excluded | 768 |
| Genuinely human-reviewed development rows | 918 |
| Assisted or weak development rows | 549 |

Development-to-final fingerprint overlap is zero. The generated manifest
preserves row fingerprints, provenance, time role, pseudonymous source/group
identity, schema profile, duplicate group, and exclusion reason. It does not
export raw evidence or private identifiers.

`manual` and `reviewed_import` provenance can count as human review when the
review flag is present. Rule-, ML-, and hybrid-assisted provenance remains
`assisted_or_weak_review_record` even if an older field says reviewed.

## Private PAN-OS Aggregate Inspection

The private file was supplied only through `--sample-path` and was never
imported into the configured database.

- 773,551 nonblank rows;
- 771,932 TRAFFIC and 1,619 THREAT records;
- zero parser errors;
- zero exact duplicate rows in the file;
- 22 minute buckets summarized into eight chronological windows;
- unknown application rate `7.0983%`;
- one serial/device identity and therefore no independent-device claim;
- 120,000 rows overlap the configured database by SHA-256 multiplicity;
- no path, raw row, IP address, fingerprint value, or secret returned.

The full aggregate scan supplies operational drift evidence only. It has no
ground-truth labels and is not used for accuracy, threshold, or readiness
claims. A disposable 5,000-row run also completed with no configured database
or artifact change.

## Shadow Drift Result

Current state: **OOD Warning**

The governed v5.3 fit partition is the baseline and the locked temporal final
partition is the observed shadow window.

| Drift signal | Value |
| --- | ---: |
| Application total-variation distance | 0.7428 |
| Schema-profile distance | 0.5791 |
| Provenance distance | 0.5737 |
| Action distance | 0.0044 |
| Review-queue rate delta | 0.6422 |
| Missingness delta | 0.000032 |
| Fit-profile OOD rate | 0.0733 |

The aggregate status vocabulary is `Stable`, `Drift Warning`, `OOD Warning`,
or `Insufficient Evidence`. AI Governance displays the status, evidence lock,
development/exclusion counts, and concise findings only.

## Assisted Review Pack

An ignored 200-row pack was generated across QUIC/443, incomplete/80,
unknown UDP/TCP, PAN-OS THREAT, scan-like, routine-allow, and time-window
strata. Every suggestion is:

- assisted/weak;
- `human_reviewed=false`;
- `human_must_confirm=true`; and
- `import_ready=false`.

It is review-efficiency material, not a source of human labels. No import or
training was performed.

## Safety State

- database counts before and after are identical;
- labels created: `0`;
- model runs created: `0`;
- detection runs created: `0`;
- response actions created: `0`;
- active artifact bytes and modification timestamp are unchanged;
- candidate selected: `false`;
- model activated/promoted: `false`;
- response automation allowed: `false`;
- real firewall blocking enabled: `false`.

## Verification

- Taskboard render and standards checks passed.
- Whole-repo Ruff and compileall passed.
- Focused v5.1/v5.3/v5.4 safety suite: `21 passed`.
- Full backend suite: `663 passed, 1 hardware-dependent skip`.
- Alembic: no new upgrade operations detected on local SQLite.
- React lint and production build passed.
- Playwright: `26 passed, 1 live-scenario/hardware-dependent skip`.
- Controlled detection: 23 default scenarios plus the mixed-subnet scenario,
  `24/24` passed with zero false-positive/false-negative scenarios and zero
  response actions.
- Layered validation: `288/288` passed with zero FP, FN, or response actions.
- SOC Assistant QA: `20/20`, citation pass rate `1.0`, unsafe refusal passed,
  and zero response/detection/model/label side effects.
- Full private preflight: 773,551 rows, eight aggregate windows, zero parser
  errors, and no private output.
- Disposable private validation: 5,000 rows, configured database/artifact
  unchanged, and zero labels/model runs/detection runs/responses.
- Replay dry-run parsed two safe rows and wrote/sent zero.
- Read-only performance smoke: Overview `0.8017s`, cached `0.0107s`, alerts
  `0.0641s`, cases `0.1255s`, features `0.0114s`; ML Governance `2.1575s`
  produced one local advisory warning against its `2.0s` budget.
- Official release gate returned `ok: true` with no failed required checks and
  independently reran `663 passed, 1 skipped`.
- `git diff --check` passed with non-failing Windows line-ending notices; no
  path is staged and no protected artifact is tracked.

## Evidence Still Required

1. Human-reviewed chronological development evidence from regimes not reserved
   as v5.3 final/rolling evaluation.
2. Independently reviewed evidence from at least two real devices.
3. A new untouched schema-compatible external benchmark; the locked external
   result cannot become development evidence.
4. Human confirmation for any assisted review-pack suggestion.
5. Advisor approval for future evidence collection or lifecycle advancement.
6. Real-device/provider access for hardware-backed source validation.

Generated reports, the row-level manifest, and the assisted review pack remain
ignored under `ml_baseline_reviews/`. No commit or push is authorized by this
document.
