# v5.22 Frozen Shadow Candidate Contract

Date: 2026-08-02

## Purpose

This contract records the v5.22 development winner before any blind decision
is opened. It is a configuration lock, not an active or serialized model.

## Frozen Configuration

| Property | Value |
| --- | --- |
| Name | `hierarchical_two_stage_extra_trees` |
| Queue target | `non_threat` versus `needs_review` |
| Queue estimator | ExtraTrees with provenance-aware sample weights |
| Severity estimator | ExtraTrees over suspicious/malicious fit evidence |
| Calibration | sigmoid, dedicated calibration role |
| Threshold | `0.40` selected on the threshold role only |
| Numeric features | 32 |
| Categorical features | 8 |
| Schema | native PAN-OS feature contract |
| Post-prediction guard | none |
| Alert authority | none |
| Response authority | none |

The feature names and transformations remain defined by
`atdr/app/detection/v56_private_panos_model_repair.py`. v5.22 supplies explicit
defaults when a fit view has an all-null feature, preserving the 40-field
contract without silently dropping columns.

## Selection Gates

The frozen ranking uses worst-case values across all development views:

- queue F1 at least `0.80`;
- benign-like FPR at most `0.10`;
- suspicious recall at least `0.70`;
- malicious recall at least `0.70`;
- ECE at most `0.15`; and
- maximum confidence/accuracy gap at most `0.20`.

The selected configuration passes F1, FPR, and malicious-recall gates. It fails
suspicious-recall and both calibration gates. Therefore it is not eligible for
activation or promotion.

## Evidence Boundary

- v5.21 fit, calibration, and threshold roles only were used.
- Exact and near-duplicate families do not cross roles.
- The v5.3 locked final/rolling/external evidence was not used for selection.
- The v5.21 untouched-future role and blind pack were not opened.
- AI/rule/vendor-assisted decisions remain weak labels.
- A 114-row manual/reviewed-import provenance holdout was included.
- Real source-disjoint evidence is unavailable.

## Runtime Decision

No model artifact exists for this contract. The previously governed runtime
artifact remains unchanged in `shadow_observation`. Rules remain the only
alert-authoritative detector. Automatic response and real blocking remain
disabled.
