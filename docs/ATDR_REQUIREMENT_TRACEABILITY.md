# ATDR Requirement Traceability

This matrix maps current product requirements to implementation and evidence.
Historical phase-by-phase traceability is preserved under `docs/archive/`.

| Requirement | Implementation evidence | Verification evidence | Status |
| --- | --- | --- | --- |
| FR-ING-01 ingestion | `atdr/app/routers/logs.py`, ingestion/job services, syslog receiver | backend ingestion, operation worker, large-file, and source scenario tests | Implemented locally; physical source pending |
| FR-PAR-01 parsing | `atdr/app/parsers/`, parser-quality services | parser contract, drift, field-qualification, and layered tests | Implemented for governed profiles |
| FR-DET-01 rules | `atdr/app/detection/`, detection service/router | controlled source and layered `288`-case validation | Implemented; real FP/FN evidence external |
| FR-ML-01 anomaly | v5.61 bootstrap, v5.63.1 telemetry, and v5.64 chronological/context/cohort/OOD evaluator | denominator, chronology, duplicate isolation, determinism, redaction, OOD, no-install, strategy-duplicate-disclosure, API, and Playwright tests | Reproducible advisory capability; 0/32 v5.64 variants qualified (28 distinct, 4 a disclosed duplicate); not threat-accuracy validated |
| FR-ML-02 supervised | supervised lifecycle, registry, v5.62 consumed-evidence exclusion, v5.63 append-only 1,000-row capacity, protected batched review, and development preflight | v5.49b aggregate decision, v5.58 runtime tests, and v5.62-v5.63 backend/UI safety tests | 300+700 rows selected; `0/1,000` reviewed; one source; `unqualified`; no active candidate |
| FR-EXP-01 explanations | explanation, investigation, alert, and case services | explanation/adversarial and analyst-workflow tests | Implemented |
| FR-AST-01 Assistant | assistant service, provider adapter, schemas, router, and v5.63.1 advisor acceptance | `30/30` quality cases, follow-up continuity, bounded live Gemini probe, provider-failure, privacy, no-side-effect, and Playwright tests | Read-only and demo-verified; Gemini institutional approval external |
| FR-ALT-01 analyst workflow | alert/case/label/audit routes and React pages | end-to-end analyst journey, UI tests, and v5.60 remote-clone acceptance | Implemented locally and in clean clone |
| FR-RSP-01 response | response service/router, `windows_firewall_connector.py`, and safety config | response simulation, real-enforcement (mocked-connector), self-host-protection, and expiry-sweep tests | `simulation_only` by default; explicit local/lab opt-in real host-firewall enforcement implemented |
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
| Response remains simulated by default; real enforcement is opt-in, local/lab-only, and host-scoped | config doctor, response service, `windows_firewall_connector.py` tests, release gate |
| Consumed evaluation remains immutable | protected evidence and at-most-once protocol tests |
| Fresh supervised evidence stays prediction blind | v5.62 owner isolation plus v5.63 per-batch isolation, redaction, sealed evaluation role, and no-write tests |
| Fixed supervised gates cannot be weakened | v5.62-v5.63 protocol equality and fail-closed source/support checks |
| Supplemental evidence is append-only | v5.63 original-pack preservation, overlap rejection, unique-family checks, and zero added evaluation rows |
| Second-source identity is not fabricated | v5.63 same-device rejection, aggregate-only distinct-device preflight, and unchanged source gate |
| Anomaly training is explicit and isolated | v5.61 confirmation gate, ignored destination checks, disposable SQLite, and setup/start non-execution tests |
| Anomaly telemetry uses honest denominators | v5.63.1 scored-row rate, database coverage, all-row prevalence, API schemas, UI labels, and regression tests |
| Unqualified anomaly replacement is refused | v5.63.1 fixed gates, private-safe comparison, manifest validation, atomic installer boundary, and no-install tests |
| Candidate holdout stays untouched during anomaly selection | v5.64 four-role protocol, boundary-family quarantine, validation-only selection, and no-candidate holdout exclusion |
| Anomaly does not duplicate rule authority | v5.64 rule-overlap accounting, zero alert/suppression writes, and 99.01% best-candidate overlap disclosure |
| Advisor workflow does not mutate configured state | v5.63.1 disposable acceptance, 10/10 stages, 24/24 workflow checks, and explicit configured-DB exclusion |

## External Trace

MFU identity lifecycle, Gemini institutional governance, an approved shared
host, a physical teammate repetition, and independent physical-source detection
evidence remain owner-backed acceptance tracks. Their preflights and stop
conditions are maintained in `docs/EXTERNAL_ACCEPTANCE.md` and the active
security/deployment contracts.

The full pre-v5.59 ledger is retained unchanged at
`docs/archive/governance/ATDR_REQUIREMENT_TRACEABILITY_THROUGH_V5_58.md`.
