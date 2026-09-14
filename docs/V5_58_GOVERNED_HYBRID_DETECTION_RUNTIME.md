# v5.58 Governed Hybrid Detection Runtime Closure

Date: 2026-09-05

## Decision

ATDR now has one explicit runtime contract for every detection layer. The
locally supported state is:

| Layer | Effective state | Normal-job behavior | Authority |
| --- | --- | --- | --- |
| Deterministic rules | `active_authoritative` | Evaluated for every bounded detection scope | May create and deduplicate alerts |
| IsolationForest | `active_advisory` when its artifact is available; otherwise `unavailable` or `abstained` | Scores the bounded normal detection batch and records anomaly context | Cannot create, suppress, close, reprioritize, or change alert severity |
| Supervised SOC queue | `unqualified` | Eligibility is checked on every ML-enabled detection run; inference is refused | No alert or response authority |
| Hybrid triage | `active_advisory` when an advisory signal is available; otherwise `abstained` | Combines bounded rule and advisory context for analyst interpretation | Cannot alter authoritative alert decisions |
| Response | `simulation_only` | Requires an analyst decision through the guarded simulation workflow | No automatic response or real blocking |

This is a controlled local decision-support product, not an autonomous detector
and not a production certification.

## Runtime Trace

The normal path is:

1. file/API, replay, durable job, or UDP syslog ingestion;
2. raw evidence preservation;
3. PAN-OS or generic syslog parsing and normalization;
4. bounded IsolationForest advisory scoring when requested and available;
5. supervised runtime eligibility and schema checks;
6. source/time-aware deterministic rule evaluation and correlation;
7. rule-authoritative alert creation or deduplication;
8. bounded rule, anomaly, supervised, and hybrid explanation;
9. React alert triage, AI Governance, and read-only Assistant presentation; and
10. analyst-approved response simulation and audit.

`atdr/app/services/detection_service.py` now records `detection_layers` in the
detection-run result, stored run details, and audit details. An advisory-model
failure does not stop rule evaluation. ML-only evidence is never admitted to
the authoritative rule set.

The run-level contract is deliberately aggregate and bounded. It contains the
authoritative verdict and at most 20 unique rule IDs, anomaly score range/mean
and limitation codes, supervised queue confidence and explicit abstention or
eligibility refusal, hybrid analyst priority, evidence strength, no more than
three missing-context statements, and no more than three recommended checks.
Alert detail then supplies the record-specific rule contributions, ML status,
missing context, and analyst checks without embedding raw log content.

## Supervised Fail-Closed Decision

The latest authoritative aggregate decision remains v5.49b:

- evaluation consumed: yes;
- candidate selected: no;
- production promotion: no;
- active artifact written: no;
- reason: the fixed evaluation had no suspicious support and every strategy
  failed the confidence-gap gate.

The historical v5.1 lifecycle row and artifact remain preserved as history.
They are not current runtime authorization. Runtime scoring requires all of the
following before `active_shadow` can be reported:

- a latest governance decision that explicitly qualifies one model version;
- all development gates passed;
- an immutable candidate freeze;
- confirmation that protected evaluation evidence was excluded from training;
- a matching registered model/version;
- complete model, target, feature, threshold, calibration, and provenance
  metadata;
- a present artifact with a valid checksum;
- strict validation and shadow-safety evidence; and
- the private shadow-scoring switch explicitly enabled.

Missing or incompatible evidence returns `unqualified` or `unavailable`. The
ordinary prediction path no longer falls back to the legacy classifier. A
legacy diagnostic can be used only by an explicit internal diagnostic call and
is labeled `diagnostic_legacy`.

Lifecycle status inspection is read-only by default. It does not execute the
older shadow-scoring service merely because status, registry, alert detail, or
Assistant context was requested.

## Development-Only Repair Result

The existing v5.45 development repair was rerun through its private-path CLI
contract with disposable storage. It did not open or tune on protected v5.49b
evaluation evidence.

Aggregate result:

- status: `development_repair_incomplete`;
- eight existing governed strategies compared;
- diagnostic leader: `calibrated_extra_trees_flat_5class`;
- strict passing views: `0/3`;
- candidate freeze ready: false;
- candidate frozen: false;
- IsolationForest reliability gate: failed;
- model activated or promoted: false;
- response automation allowed: false.

The blockers are model instability, unreliable anomaly sensitivity, one real
source, assisted evidence that is not independent ground truth, and the lack of
a new untouched independent window. No generated candidate or report is
tracked. The private sample path, rows, identities, IPs, fingerprints, and
protected decisions are not returned here.

## API And Analyst Surfaces

Authenticated analysts and admins can inspect:

```text
GET /api/ml/runtime-status
```

The payload contains only safe aggregate state. It exposes no artifact path,
checksum, dataset fingerprint, raw log, IP address, identity, or secret.

AI Governance shows separate cards for Rules, IsolationForest, Supervised,
Hybrid Triage, and Response. The registry separates historical lifecycle and
artifact metadata from effective runtime authorization. Alert detail labels
the supervised area **Supervised Signal** and reports `unqualified`,
`unavailable`, or `abstained` instead of inventing a prediction.

The SOC Assistant receives the same bounded explanation/model report. It says
that rules are authoritative, anomaly output is advisory, and supervised
runtime is currently unqualified. Gemini may tighten wording only after the
same context is redacted and allowlisted; it cannot create a missing score.

## Operator Check

Run the read-only status check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v558_governed_hybrid_runtime --require-safe --pretty
```

Expected local result:

- rules: `active_authoritative`;
- IsolationForest: `active_advisory` when the configured artifact is present;
- supervised: `unqualified` with scoring disabled;
- response: `simulation_only`;
- database writes, alerts created, response actions created, and model
  activations: `0`.

## Safety Invariants

- Rules remain the only alert-authoritative detection layer.
- IsolationForest, supervised ML, and hybrid scoring never create or suppress
  an alert.
- v5.49b remains immutable and is not rerun, inspected, or tuned.
- No label is fabricated or overwritten.
- No active supervised artifact is written.
- Automatic response and real firewall blocking remain disabled.
- Generated/private evidence remains ignored.

## Verification

The complete local matrix passes:

- v5.58 focused runtime tests: `10/10`;
- full backend suite: `1077 passed, 1 skipped`;
- independent release-gate backend suite: `1077 passed, 1 skipped`;
- taskboard render/standard check, Ruff, compileall, and Alembic drift check;
- React lint and production build (`2300` modules transformed);
- Playwright: `42 passed, 1` intentional live-hardware skip, including desktop,
  tablet, mobile, keyboard, overflow, and automated WCAG A/AA checks;
- controlled deterministic validation: `24/24`;
- layered validation: `288/288`, controlled FP/FN `0/0`;
- Assistant QA: `30/30`, citation rate `1.0`, average/max answer length
  `56.1/110` words, follow-up continuity passed, and zero side effects;
- replay dry-run: `2/2` rows parsed and zero writes;
- read-only performance smoke: all budgets passed, cold Overview `0.6696s`,
  cached Overview `0.0095s`, and no warnings;
- repository security scan: zero findings across `1383` scanned text paths;
- governed-runtime inspection and deployment-operation checks; and
- release gate: `ok=true` with no failed required checks.

Deferred-system preflights remain test-ready and fail closed:

- local live-source preflight passes while `phase_complete=false` and
  `real_device_validated=false`;
- MFU template-shell handoff is configured, while B2B/admin/provider 2FA
  acceptance remains unavailable and no provider call was made;
- Gemini provider/model/key configuration is detected without exposing the
  key, raw log context remains disabled, IP redaction remains enabled, and the
  status check makes no provider call;
- PostgreSQL multi-worker preflight returns `blocked_by_environment` when no
  private test/restore database URLs or PostgreSQL tools are supplied, with no
  database modification or credentials returned; and
- deployment-operation validation passes its source contract while retaining
  `production_ready=false`.

An initial non-authoritative pytest attempt placed backup fixtures under a
disallowed in-repository temp root. The backup boundary correctly rejected it.
The affected `49/49` regression slice and both complete backend runs pass under
the approved `.tmp/` root.

The exact changed-path boundary is recorded in
`docs/V5_58_COMMIT_ALLOWLIST.md`. No path is staged, committed, or pushed by
this phase.

## Remaining Work

One substantial local phase remains: v5.59 repository consolidation. It should
reduce the active documentation and historical-tool surface without deleting
audit evidence or changing runtime behavior.

The following are externally gated and remain test-ready rather than locally
fabricated: second-device field evidence, MFU IAM preproduction lifecycle,
institutional Gemini governance, approved PostgreSQL/TLS deployment, physical
teammate acceptance, and any later supervised activation evidence.
