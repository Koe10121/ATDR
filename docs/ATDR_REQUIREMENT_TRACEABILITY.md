# ATDR Requirement Traceability

This matrix maps current product requirements to implementation and evidence.
Historical phase-by-phase traceability is preserved under `docs/archive/`.

| Requirement | Implementation evidence | Verification evidence | Status |
| --- | --- | --- | --- |
| FR-ING-01 ingestion | `atdr/app/routers/logs.py`, ingestion/job services, syslog receiver | backend ingestion, operation worker, large-file, and source scenario tests | Implemented locally; physical source pending |
| FR-PAR-01 parsing | `atdr/app/parsers/`, parser-quality services | parser contract, drift, field-qualification, and layered tests | Implemented for governed profiles |
| FR-DET-01 rules | `atdr/app/detection/`, detection service/router | controlled source and layered `288`-case validation | Implemented; real FP/FN evidence external |
| FR-ML-01 anomaly | ML services and model governance routes | anomaly reliability and runtime-contract tests | Advisory only |
| FR-ML-02 supervised | supervised lifecycle, registry, evidence, calibration, and decision services | v5.49b aggregate decision and v5.58 fail-closed runtime tests | `unqualified`; no active candidate |
| FR-EXP-01 explanations | explanation, investigation, alert, and case services | explanation/adversarial and analyst-workflow tests | Implemented |
| FR-AST-01 Assistant | assistant service, provider adapter, schemas, router | Assistant backend QA, provider-failure, privacy, and Playwright tests | Read-only; Gemini approval external |
| FR-ALT-01 analyst workflow | alert/case/label/audit routes and React pages | end-to-end analyst journey, UI tests, and v5.60 remote-clone acceptance | Implemented locally and in clean clone |
| FR-RSP-01 response | response service/router and safety config | response simulation and no-side-effect tests | `simulation_only` |
| FR-IAM-01 identity | shell handoff, auth/security services, shell lifecycle scripts | auth, packaged handoff, fail-closed provider, startup, and browser tests | Clean-clone controls verified; MFU acceptance external |
| FR-OPS-01 operations | health/metrics, durable jobs, backup/restore, deploy assets | v5.60 `27/27` clean-clone gates plus PostgreSQL CI, recovery, performance, release, and security gates | Local release candidate verified; host acceptance external |
| FR-UI-01 dashboard | `frontend/src/App.tsx`, pages, API/hooks, shared components | lint, build, Playwright, viewport and accessibility checks | Engineering baseline complete |
| GOV-01 process | taskboard, T1-T20 template, current locks, exact allowlists | taskboard standard and repository-surface audits | Active |
| SEC-01 repository safety | ignore policy, security scan, dependency audits, CodeQL | local scanner and CI workflows | Implemented; ongoing operation required |

## Current Safety Trace

| Invariant | Evidence |
| --- | --- |
| Rules remain alert-authoritative | v5.58 runtime contract and detection tests |
| Supervised runtime is unqualified | v5.49b negative decision and fail-closed scoring path |
| No model activation/promotion | registry and no-mutation tests |
| Assistant remains read-only | service/router permissions and side-effect tests |
| Raw external LLM log context is off | Assistant config/status and provider tests |
| Response remains simulated | config doctor, response service, release gate |
| Consumed evaluation remains immutable | protected evidence and at-most-once protocol tests |

## External Trace

MFU identity lifecycle, Gemini institutional governance, an approved shared
host, a physical teammate repetition, and independent physical-source detection
evidence remain owner-backed acceptance tracks. Their preflights and stop
conditions are maintained in `docs/EXTERNAL_ACCEPTANCE.md` and the active
security/deployment contracts.

The full pre-v5.59 ledger is retained unchanged at
`docs/archive/governance/ATDR_REQUIREMENT_TRACEABILITY_THROUGH_V5_58.md`.
