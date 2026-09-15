# ATDR Final Engineering Validation Summary

## Scope

ATDR is a lab-ready AI-assisted SOC triage prototype for firewall and syslog
data. It preserves raw evidence, normalizes records, tracks sources and
ingestion runs, applies layered detection, groups alerts and cases, supports
human label review, and records simulated analyst-approved response actions.

This document summarizes the controlled engineering evidence through v2.0. It
does not certify production deployment.

## Final Candidate

- Candidate: `independent_fpr_stabilized`
- Candidate role: frozen validation candidate for SOC triage decision support
- Base profile: `external_recall_plus`
- Blind calibration assessment: `raw_confidence`
- Source/scenario identity inputs: prohibited
- Behavior-window evidence: preserved
- Ambiguous unresolved high-port services: routed to analyst review
- Production promoted: false
- Model activated: false
- Response automation: disabled
- Real firewall blocking: disabled

The candidate lock is generated with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.lock_v20_candidate --pretty
```

Generated lock metadata and hashes remain under ignored
`demo_exports/benchmarks/`.

## Validation Chain

| Phase | Evidence |
| --- | --- |
| v0.7 | Fixed synthetic scenario detection validation |
| v0.8 | Generated variation and generalization checks |
| v0.9 | Rule, anomaly, supervised, and hybrid layer comparison |
| v1.0 | End-to-end ingestion, detection, investigation, response, and audit workflow |
| v1.1 | Reliability baseline, drift, stress, and benchmark framework |
| v1.2 | Sanitized benchmark preparation and benchmark-only ML workflow |
| v1.5 | Internal AI readiness benchmark |
| v1.6 | Separate unseen synthetic holdout transfer check |
| v1.7-v1.8 | External boundary improvement, reviewed benchmark finalization, and calibration |
| v1.9 | New independent holdout and controlled source validation |
| v1.9b | Identity-independent false-positive stabilization |
| v2.0 | Frozen-candidate fresh blind revalidation and final controlled source acceptance |

## Fresh Blind Revalidation

The v2.0 holdout uses a new seed, new timestamps, seven source names, sixteen
scenario families, and 700 synthetic rows. It is not used for threshold or
profile tuning.

| Metric | Result |
| --- | ---: |
| Rows | 700 |
| Exact overlap with previous snapshots | 0 |
| Near-pattern overlap | 335 |
| Threat precision | 0.8906 |
| Threat recall | 0.9459 |
| Threat F1 | 0.9174 |
| Benign-like false-positive rate | 0.1303 |
| Suspicious recall | 0.8556 |
| Malicious recall | 0.9000 |
| Macro F1 | 0.8680 |
| Weighted F1 | 0.8753 |
| False positives | 43 |
| False negatives | 20 |

Raw-confidence calibration passed without fitting or selecting a calibrator on
the blind holdout:

- ECE: `0.0757`
- Brier score: `0.0751`
- maximum confidence/accuracy gap: `0.1878`

The fresh blind candidate meets the configured targets without tuning.
The earlier local draft that cross-fitted confidence calibration on blind
labels is superseded by this no-fit assessment. Classification metrics were
unchanged.

## Controlled Source Acceptance

The final controlled validation uses temporary SQLite databases and safe
synthetic replay/syslog-style inputs. It does not modify the current local
database.

- raw logs preserved: 28
- normalized logs: 28
- parse successes: 25
- tracked parse failures: 3
- alerts: 2
- cases: 2
- deduplicated alert updates: 1
- source registration and health: passed
- parser profile and raw fallback tracking: passed
- Why flagged evidence: passed
- protected-IP response denial: passed
- audit recording: passed
- explicit approved response remained simulated: passed
- automatic responses: 0
- real firewall changes: 0

Real router or firewall hardware was not connected. Vendor-specific forwarding
and long-duration source stability remain future controlled lab work.

## Readiness v8

Readiness v8 passed 22 of 22 checks with:

`final_controlled_validation_candidate`

This means the frozen candidate passed the fresh blind synthetic holdout and
the final controlled source/replay acceptance workflow. It does not mean
production promotion.

## Safety Posture

- ML output remains analyst decision support.
- No model can directly create a response action.
- Simulated response requires an authorized analyst, confirmation, and a note.
- Protected internal/management targets are denied and audited.
- Real enforcement connectors are not implemented.
- Local JWT/RBAC is suitable for lab use, not enterprise production IAM.
- External OIDC groundwork remains disabled until a provider is configured.

## Why This Is Not Production Deployment

Production use would still require:

- real router/firewall UDP/TCP forwarding validation;
- sustained soak, load, retention, and failure-recovery testing;
- PostgreSQL or another managed relational deployment;
- hardened secrets, TLS, backup, monitoring, and patching;
- external IAM/SSO and formal role governance;
- vendor-approved response connector design and change control;
- independent security review and penetration testing;
- larger independently reviewed real-world labels;
- ongoing drift, calibration, and false-positive monitoring;
- privacy, retention, incident-response, and operational approval.

## Reproduce The Final Validation

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.lock_v20_candidate --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.build_fresh_blind_holdout --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v20_fresh_blind_revalidation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_final_controlled_source_acceptance --pretty
```

Generated reports, snapshots, and CSVs remain ignored under
`demo_exports/benchmarks/`.
