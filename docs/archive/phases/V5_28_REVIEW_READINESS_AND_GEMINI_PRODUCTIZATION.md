# v5.28 Blind Review Readiness and Gemini Productization

## Status

v5.28 completes the locally controllable preparation for independent blind
review and hardens the Gemini-backed SOC Assistant. Human review is explicitly
deferred: the sealed 40-row pack remains unopened by the v5.28 workflow, has
zero human decisions, and produces no blind accuracy metrics.

ATDR remains a controlled decision-support system:

- deterministic rules remain alert-authoritative;
- supervised ML remains `shadow_observation`;
- Gemini and ML remain decision support only;
- automatic response and real firewall blocking remain disabled; and
- no model was trained, selected, recalibrated, activated, or promoted.

## Blind-First Review Workflow

The private review helper creates a separate ignored working copy and never
overwrites the sealed evidence pack. It presents one structured evidence row
at a time without rule, IsolationForest, supervised, hybrid, Codex, or Gemini
suggestions. Each accepted row requires a human decision, attack type,
confidence, notes, reviewer identity, timezone-aware timestamp, reviewed flag,
and explicit confirmation.

The helper:

- preserves review tokens, protected evidence columns, and row order;
- saves atomically after each confirmed row and supports resume;
- keeps `import_ready=false` and never imports labels;
- rejects assisted provenance, altered evidence, duplicate/missing tokens,
  invalid review metadata, or privacy-contract changes; and
- reports only review progress and human decision-class support, never frozen
  prediction counts or early accuracy metrics.

The locked evaluator accepts the completed working copy through
`--review-file`. It reads evidence from the sealed pack and human fields from
the working copy. Metrics remain withheld until at least 20 legitimate reviews
and both ground-truth queue classes are present.

## Supervised Shadow Readiness

The read-only v5.28 audit confirmed:

| Check | Result |
| --- | --- |
| Lifecycle | `shadow_observation` |
| Review gate | `human_review_pending` (0 reviewed rows) |
| Registered model | calibrated ExtraTrees, binary SOC review queue |
| Artifact checksum | valid |
| Feature contract | registered, 92 numeric and 6 categorical features |
| Calibration contract | dedicated sigmoid calibration, threshold configured |
| Schema safety | fail-closed abstention; incompatible evidence is not scored |
| Registered latency | 14.7438 ms p95 for 100 rows; 250 ms gate passed |
| Shadow drift | `Insufficient Evidence` |
| Audit mutations | zero labels, models, artifacts, or response actions |
| Blind evidence opened | no |

This verifies artifact integrity and runtime safety, not predictive quality.
Blind precision, recall, F1, false-positive rate, and calibration remain
unknown until independent human review is complete.

## Post-Review Decision Tree

1. Fewer than 20 legitimate reviews or only one queue class: withhold all
   blind metrics and continue independent review.
2. Invalid working-copy or integrity contract: fail closed, repair only the
   review copy, and preserve the sealed pack.
3. Fixed quality gates fail: remain in shadow, repair using development
   evidence only, then create a new untouched blind pack.
4. Fixed gates pass: remain in shadow until independent evidence and governance
   requirements are complete; activation still requires explicit review.
5. Prediction leakage or lock mismatch: invalidate the pack and create a new
   untouched pack without reusing exposed rows.

## Gemini Hardening

The provider adapter now adds configurable token and visible-answer budgets,
bounded retries, typed timeout/rate-limit/network/service errors, a process-
local circuit breaker, deterministic fallback, and aggregate operational
telemetry. Telemetry contains counts, latency, token totals, estimated cost,
and outcome state only. It does not retain prompts, answers, raw logs, IPs,
private paths, or secrets.

The Assistant UI refreshes provider status after each answer, shows concise
health/fallback/usage information, preserves bounded session context across
dashboard navigation, and retains the existing safety badges. API keys,
prompts, debug JSON, and private evidence remain hidden.

## Measured Gemini Result

The configured Gemini provider passed all 12 fixed checks over six bounded
questions built from privacy-safe disposable snapshots of current dashboard
records:

- provider calls: 6;
- median / p95 latency: 3,494.5 / 3,795 ms;
- input / output / total tokens: 19,157 / 2,842 / 21,999;
- citation, context, concision, privacy, and safe-recommendation gates: passed;
- forced provider-timeout fallback: passed;
- configured-database mutation deltas: all zero; and
- raw logs, IP addresses, secrets, and private paths returned: none.

This bounded automated evaluation does not prove universal semantic accuracy
or provider deployment approval.

## Commands

Human review can be started later without changing the sealed pack:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --prepare --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --interactive --reviewer "<institutional-id>" --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --status --pretty
```

After the review gate is met, the evidence custodian runs the locked evaluator
once against the separate working copy:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_blind_review_evaluation --review-file ".\ml_baseline_reviews\v5_28_blind_human_review_working.csv" --pretty
```

The read-only readiness and bounded Gemini checks are:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_supervised_readiness_audit --no-write --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_gemini_real_alert_quality --execute-provider --provider-interval-seconds 1 --pretty
```

## Remaining Major Phases

Supervised ML has approximately three evidence phases remaining:

1. independent human review and one locked evaluation;
2. development-only repair plus a new blind pack if fixed gates fail; and
3. genuinely independent second-source/device evidence and activation
   governance if every fixed gate passes.

The Assistant has approximately two product-evidence phases remaining:

1. qualified human semantic, usefulness, and privacy evaluation; and
2. approved-host provider governance covering privacy approval, quota/cost
   limits, monitoring, key rotation, and failure operations.

External dependencies remain a qualified human reviewer, a second native
source/device, university/provider approval, and an approved deployment host.

## Verification Result

- taskboard render and standard check: passed;
- Ruff and compileall: passed;
- backend and official release suite: `848 passed, 1 skipped`;
- Alembic: no drift;
- React lint/build: passed;
- Playwright: `27 passed, 1 skipped` (external live-source gate);
- controlled scenarios: `24/24`;
- layered detection: `288/288`, zero controlled FP/FN;
- deterministic Assistant QA: `20/20`;
- configured Gemini: six calls, `12/12`;
- replay dry-run: two safe rows parsed, zero writes;
- 145,232-row performance smoke: no warnings, Overview `0.555s` cold and
  `0.0089s` cached, alert list `0.0542s`, case summary `0.025s`, and ML
  Governance `1.2401s`;
- official release gate: `ok: true`; and
- exact cumulative allowlist: `44/44`, staging empty, private/generated
  evidence ignored, and sensitive-content scan clean.

One initial verification attempt used an unnecessarily long pytest temp path
and triggered a Windows path-length failure in a template-launcher fixture.
The Windows-safe short-root rerun passed. The full suite also identified an
older v5.24 fallback contract that recognized only the legacy generic provider
error; it was updated to accept the new typed safe failure reasons and its
targeted 15-test regression plus the full suite pass.
