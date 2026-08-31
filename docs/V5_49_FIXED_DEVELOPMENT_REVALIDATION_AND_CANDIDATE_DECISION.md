# v5.49 Fixed Development Revalidation And Candidate Decision

## Status

v5.49 is active and fail-closed. The immutable v5.48 protocol remains locked
and valid. The authoritative private workspace is now genuinely reviewed
`120/120`, invalid `0`, and formally closed, but honest aggregate class support
is benign-like `92`, suspicious `9`, and malicious `0`. The fixed support
preconditions are therefore not met, and the one permitted evaluation has not
run.

- fixed strategies: `8`
- review progress: `120/120`
- invalid review rows: `0`
- formal closure: yes
- class-support gate: failed (`92/9/0`; required `>=20/>=15/>=10`)
- evaluation execution count: `0`
- diagnostic candidate: none
- lifecycle: `shadow_observation`
- deterministic rules alert-authoritative: yes
- automatic response and real blocking: disabled

v5.49 does not access evaluation labels or manufacture substitute decisions.
v5.49a now provides a separate threat-enriched, prediction-blind protected
review workspace while preserving the closed v5.48 review and execution count
`0`.

## One-Time Execution Safety

Before evaluation labels can be opened, v5.49 now requires an atomic private
execution claim bound to the already locked protocol. A concurrent, failed, or
interrupted prior claim blocks automatic retry. This strengthens at-most-once
execution without changing any frozen partition, feature, strategy, threshold,
calibration policy, or quality gate.

## Aggregate Candidate Decision

`v549_fixed_revalidation_decision.py` is a read-only post-result validator. It
requires:

- the exact v5.48 result and execution-count contract;
- all eight strategies in locked order with no duplicate or missing strategy;
- unchanged fixed gates for every evaluated strategy;
- a diagnostic leader consistent with the frozen ranking policy; and
- zero label, model-run, detection-run, alert, response, activation, promotion,
  import, or artifact writes.

When a valid result exists, the CLI reports each strategy's precision, recall,
F1, benign-like FPR, suspicious recall, malicious recall, macro and weighted
F1, queue rate, Brier score, ECE, confidence gap, and fixed-gate checks. It may
qualify one inactive diagnostic candidate, but never authorizes activation.

Current safe status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v549_fixed_revalidation_decision --pretty
```

Current output is blocked by insufficient honest class support. Do not execute
the fixed evaluation until a separately relocked protocol is proposed and
approved after supplemental evidence closure.

## Verification So Far

- Focused v5.48/v5.49 backend tests: `19 passed`.
- Full release-gate backend tests: `1016 passed, 1 skipped`.
- Ruff and compileall pass for the touched source and tests.
- Alembic reports no drift; React lint/build and Playwright pass (`36 passed,
  1 skipped`).
- Controlled source validation passed with `10/10` rows parsed, one expected
  port-scan alert/case, and zero response actions.
- Layered detection validation passed `288/288` with zero controlled false
  positives or false negatives.
- Assistant QA passed `20/20`; replay remained dry-run only.
- Performance smoke passed. Cached Overview was `0.0141s`; the cold Overview
  query produced one narrow local warning at `1.0705s` against a `1.0s` target.
- The release gate returned `ok: true` with no failed required checks.
- The real private status reports protocol valid, review `120/120`, formal
  closure, honest support `92/9/0`, execution count `0`, and no
  evaluation-label access.
- No active model, configured data, alert authority, or response behavior was
  changed.
- Post-test custody confirms the real execution claim and result are both
  absent; staging remains empty and the 64-path allowlist is exact.

The v5.49 fixed evaluation remains intentionally unconsumed. v5.49a has prepared
a separate 60-row protected review pack without changing v5.48 custody.

## Remaining Gate

A genuine authenticated human must complete **Evidence Review > Supplemental
Threat Anchors**. Combined support is revealed only after closure. If honest
support passes, a separate v5.49b phase may approve a newly versioned fixed
protocol; v5.48 remains immutable and must not be executed under the failed
support precondition. Even a later passing development result still requires a
second genuine source and a newly sealed untouched future validation set before
supervised activation can be reconsidered.
