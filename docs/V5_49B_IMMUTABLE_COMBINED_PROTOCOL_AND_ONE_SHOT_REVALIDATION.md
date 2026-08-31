# v5.49b Immutable Combined Protocol And One-Shot Revalidation

## Status

v5.49b is complete. The original and supplemental protected reviews are
closed, immutable, and bound to a newly versioned fixed protocol. The protocol
was consumed exactly once. All eight locked strategies were evaluated, and no
diagnostic candidate qualified.

- original review: `120/120`, invalid `0`, closed and immutable
- supplemental review: `60/60`, invalid `0`, closed and immutable
- combined support: benign-like `95`, suspicious `39`, malicious `27`
- required support: benign-like `20`, suspicious `15`, malicious `10`
- fixed protocol: locked, valid, immutable, and unchanged after lock
- evaluation execution count: `1`
- evaluated strategies: `8/8`
- qualified diagnostic candidates: `0`
- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- model activation, promotion, automatic response, and real blocking: disabled

The result is a valid negative decision. It must not be retried, re-partitioned,
or tuned against the consumed evaluation evidence.

## Evidence Custody

The v5.49b protocol binds the original and supplemental manifests, sealed
packs, protected working copies, immutable review states, and the v5.49a
proposal through private digests. It preserves the original v5.48 protocol
unchanged. The execution claim was created atomically before evaluation labels
were opened, so interruption or a second invocation fails closed.

Public API, CLI, and dashboard status expose only aggregate counts and safety
state. They do not expose raw logs, IP addresses, source identities, private
paths, row fingerprints, reviewer identities, predictions, or digests.

## Fixed Evaluation Result

The immutable partition produced an `11`-row evaluation slice: `9` benign-like,
`0` suspicious, and `2` malicious rows. This is the key limitation. The full
combined review has ample class support, but chronological and duplicate-group
isolation left no suspicious example in the fixed evaluation role.

| Strategy | Queue precision | Queue recall | Queue F1 | FPR | Suspicious recall | Malicious recall | ECE | Confidence gap | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Calibrated ExtraTrees, flat five-class | 1.0000 | 1.0000 | 1.0000 | 0.0000 | not measurable | 1.0000 | 0.1689 | 0.5065 | fail |
| Calibrated HistGradientBoosting, flat five-class | 1.0000 | 0.5000 | 0.6667 | 0.0000 | not measurable | 0.5000 | 0.1993 | 0.6148 | fail |
| Calibrated Logistic Regression, flat five-class | 0.0000 | 0.0000 | 0.0000 | 0.0000 | not measurable | 0.0000 | 0.3251 | 0.3251 | fail |
| Binary threat-positive ExtraTrees | 1.0000 | 1.0000 | 1.0000 | 0.0000 | not measurable | 1.0000 | 0.0977 | 0.2720 | fail |
| Three-class SOC queue ExtraTrees | 1.0000 | 1.0000 | 1.0000 | 0.0000 | not measurable | 1.0000 | 0.1407 | 0.3955 | fail |
| Hierarchical two-stage ExtraTrees | 1.0000 | 1.0000 | 1.0000 | 0.0000 | not measurable | 1.0000 | 0.1162 | 0.2814 | fail |
| Binary threat-positive anchor-strict | 1.0000 | 1.0000 | 1.0000 | 0.0000 | not measurable | 1.0000 | 0.0977 | 0.2720 | fail |
| Binary threat-positive anchor-max | 1.0000 | 1.0000 | 1.0000 | 0.0000 | not measurable | 1.0000 | 0.0977 | 0.2720 | fail |

All strategies fail the suspicious-recall gate because suspicious support is
zero. Every strategy also exceeds the fixed maximum confidence/accuracy gap
of `0.15`; several fail ECE, queue, or malicious-recall gates as well. Strong
binary results on two malicious rows are not enough to establish reliability.

The supplemental pack was deliberately threat-enriched. Queue rate and
precision from this evaluation are diagnostic only and are not production
prevalence estimates.

## Authority And Mutation Proof

Configured database counts were recorded before and after the one-shot run and
were identical:

| Governed object | Before | After |
| --- | ---: | ---: |
| Raw logs | 145,232 | 145,232 |
| Normalized logs | 145,232 | 145,232 |
| Alerts | 3,231 | 3,231 |
| Labels | 2,672 | 2,672 |
| Model runs | 45 | 45 |
| Detection runs | 31 | 31 |
| Response actions | 0 | 0 |

No active model artifact was written. No model was activated or promoted. No
label, alert, detection run, or response action was created. Deterministic
rules remain the only alert authority.

## Operator Commands

The evaluation command is intentionally no longer an available operation. Use
status only:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v549b_combined_fixed_revalidation --status-only --pretty
```

A completed or claimed protocol must never be retried automatically or by an
operator. The stored aggregate result is the source of truth.

## Verification

Focused v5.47-v5.49b regressions pass `36/36`; the v5.49b suite passes `6/6`,
including a disposable execution of all eight strategies. Full backend testing
passes `1027`, with `1` intentional live-environment skip. Alembic reports no
drift. React lint/build pass and Playwright passes `37`, with `1` intentional
live-source skip. Controlled source acceptance passes; layered detection passes
`288/288`; Assistant QA passes `20/20`; replay remains dry-run; performance has
no warnings; and the release gate returns `ok: true`.

The first full pytest invocation used `.test-tmp` as its temporary root. ATDR's
backup safety policy correctly rejected repository-local backup output outside
the approved `.tmp` root, causing 12 derivative failures. The exact failed
subset then passed `29/29`, and the authoritative full rerun passed under
`.tmp`. No safety policy was weakened.

## Decision And Next Work

No supervised candidate advances. The lifecycle remains
`shadow_observation`, and the consumed evidence becomes evaluation-only.

The next supervised work must begin with fresh development evidence and a
predeclared partition contract that guarantees measurable support in every
required evaluation class without moving rows after labels are revealed. The
remaining supervised path is approximately four substantial phases:

1. Acquire fresh prediction-blind development evidence with class-support and
   duplicate-family coverage designed before review.
2. Repair and calibrate models using development roles only.
3. Validate once on a new untouched future window and a second physical source.
4. Conduct a separate human activation review if every fixed gate passes.

Broader shared-product closure remains approximately seven to eight phases,
including real-source/parser qualification, field rule FP/FN evidence, Gemini
operations governance, MFU IAM acceptance, shared deployment/security,
accessibility/usability validation, and release-candidate closure.
