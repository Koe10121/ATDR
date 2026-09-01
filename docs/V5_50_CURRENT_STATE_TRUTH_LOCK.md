# v5.50 Current-State Truth Lock And Finish-Line Consolidation

Date: 2026-08-31

## Decision

ATDR is a controlled-lab defensive SOC platform with a complete local workflow
from log collection through normalization, deterministic detection,
investigation, bounded Assistant support, simulated analyst-approved response,
and audit. It is not production-certified.

The published source baseline is commit
`1866086e6ba9d0e6ac752e4b44e2b54a2acd6fb0`. GitHub Actions run
`33348242534` passed the backend release gate, frontend dashboard, and
disposable PostgreSQL persistence jobs.

v5.49b is the current supervised decision. Its immutable protocol bound 180
genuine protected decisions with aggregate support `95/39/27`, was consumed
exactly once, evaluated eight fixed strategies, and selected no candidate. The
evaluation role contained nine benign-like rows, zero suspicious rows, and two
malicious rows. Suspicious recall was not measurable and every strategy failed
the fixed confidence-gap limit. The result cannot be rerun, repartitioned, or
tuned.

Rules remain alert-authoritative. IsolationForest and supervised output remain
advisory. Supervised lifecycle remains `shadow_observation`; no model is
activated or production-promoted. The SOC Assistant remains read-only.
Automatic response and real firewall blocking remain disabled.

## Scope And Privacy

v5.50 changes documentation and governance only. It does not change API,
database, parser, detection, ML, Assistant, IAM, frontend, deployment, or
response behavior.

Only aggregate v5.49b facts are public. Protected rows, decisions, reviewer
identities, paths, fingerprints, predictions, execution claims, digests, raw
logs, provider payloads, credentials, and secrets remain private and ignored.

## Current Product Matrix

| Area | Classification | Current controlled state | Remaining acceptance | Primary owner |
| --- | --- | --- | --- | --- |
| Log ingestion | Complete for controlled lab; externally blocked for field use | File/API import, replay, loopback UDP syslog, durable jobs, committed chunks, resume, cancellation, backpressure, staging retention, and source health are implemented. Large private-file and disposable scale paths have been exercised without tracking raw evidence. | Non-loopback field forwarding, authenticated/encrypted transport where required, long-running operation, and at least two verified devices. | Codex for harnesses; hardware/network owner and team for field proof. |
| Parsing and normalization | Complete for supported controlled contracts; partial for field breadth | PAN-OS TRAFFIC/THREAT/SYSTEM contracts, CSV-safe parsing, generic syslog, raw fallback, raw evidence preservation, quality accounting, layout compatibility, and drift warnings are implemented. | Device-documentation field qualification across additional PAN-OS versions, two physical sources, and any later vendor profiles. | Codex plus hardware/network owner and reviewer. |
| Deterministic detection | Complete for controlled regression; externally blocked for field accuracy | Versioned 19-rule catalog, five-minute source-scoped correlation, deduplication, cases, explanations, and recommendations are implemented. Controlled scenarios pass `24/24`; layered regression passes `288/288`. | Independently reviewed real-traffic FP/FN measurement, environment baselines, and long-window/distributed field behavior. | Codex for diagnostics; human reviewer and hardware owner for truth. |
| IsolationForest | Implemented but not reliable enough for authority | Advisory anomaly score and governance visibility are implemented. It cannot authorize alerts or response. | Current evidence shows benign noise and weak threat capture; it remains non-authoritative unless new evidence proves reliability. | Codex for development analysis; reviewer for evidence. |
| Supervised ML | Workflow complete; candidate incomplete and evidence-blocked | Evidence custody, leakage controls, calibration, strategy comparison, registry visibility, protected review, and one-shot evaluation are implemented. v5.49b selected no candidate. | Fresh development evidence, a second physical source, an untouched predeclared future evaluation, stable calibration/recall/FPR, and separate human activation approval. | Codex, human reviewer, hardware owner, and repository owner. |
| Alert explanations | Complete for controlled analyst workflow; partial for organizational context | Alerts expose what happened, why flagged, evidence strength, missing context, related logs, ATT&CK-style context, and bounded analyst checks. | Asset criticality, business ownership, prior analyst outcomes, and external ticket/incident integration. | Codex plus student/team and advisor for domain context. |
| SOC Assistant | Complete for controlled read-only use; externally blocked for shared provider acceptance | Authenticated SQLAlchemy-backed bounded context, citations, concise intent contracts, contextual follow-up, actor-scoped history, IP redaction, raw-log exclusion, deterministic fallback, Gemini/OpenAI/Claude adapters, provider resilience/telemetry, audit, and feedback are implemented. It cannot mutate system state. | Institutional Gemini privacy/retention approval, shared quota/cost/key-rotation operations, persistent provider monitoring, and representative field usability evaluation. | Codex, Gemini/provider owner, advisor, and human analysts. |
| Dashboard | Complete for controlled workflow; human acceptance partial | React routes cover overview, alerts, logs, Assistant, response, controls, audit, tuning, evidence review, ML governance, users, and scenarios with RBAC and responsive regression coverage. | Formal WCAG/assistive-technology audit and independent analyst usability acceptance. | Codex plus student/team and human analysts. |
| MFU IAM | Implementation foundation complete; externally blocked | The approved companion shell is the normal entry. ATDR has secure one-time handoff, allowed-origin/return-path controls, school-domain mapping, analyst default, group-based admin mapping, local recovery, and secret-safe status. | University-approved preproduction origins/callbacks/groups, provider 2FA, account recovery, deprovisioning, viewer policy, and institutional acceptance. | Advisor/university and student/team, with Codex integration support. |
| Persistence and operations | Controlled implementation complete; approved deployment blocked | SQLite local profile, PostgreSQL compatibility/CI, 2/4-worker coordination, 100k/250k qualification, health/readiness, request IDs, Prometheus metrics, operational alerts, retention tooling, and backup/restore checks are implemented. | Approved multi-host environment, DNS/TLS, managed secrets, protected shared storage, persistent monitoring/paging, and measured deployment RPO/RTO. | Deployment owner with Codex operator tooling. |
| Testing and security | Strong controlled baseline; additional implementation and external review required | Backend, Ruff, Alembic, React lint/build/Playwright, controlled detection, Assistant QA, performance, release, PostgreSQL CI, and npm audit gates exist. | Backend dependency audit, SBOM, secret scanning, SAST/CodeQL, DAST/penetration testing, and scheduled environment recovery drills. | Codex for automation; deployment/security owner for environment testing. |
| Repository hygiene | Complete for current controlled baseline | Published v5.49b baseline is clean. Private environment, database, log, review, model, and generated evidence paths are ignored. | Preserve exact-path review and separate approval for every commit/push. | Codex and repository owner. |

## Corrected Stale Claims

- The active baseline is v5.49b at commit `1866086...`, not the older v5.17
  checkpoint.
- v5.18 PostgreSQL qualification is published history, not uncommitted work.
- No calibrated ExtraTrees model is a qualified current active candidate.
- Current supervised status is no-candidate `shadow_observation`, not a generic
  `candidate_only` claim.
- v5.49b is complete, immutable, consumed exactly once, and negative; it is no
  longer a pending protected revalidation.
- PostgreSQL compatibility, multi-worker behavior, scale, and backup/restore
  have controlled evidence. Only approved shared deployment remains external.
- Observability includes metrics, request IDs, health/readiness, operational
  alerts, and maintenance tooling; persistent external monitoring remains open.
- Gemini has bounded adapter and quality evidence, but no institutional privacy
  or production-service approval.

## Ownership Ledger

### Codex Can Complete Independently

- Parser fixtures, drift diagnostics, deterministic-rule regression, and
  privacy-safe acceptance harnesses.
- Development-only ML experiments using only newly declared development roles.
- Assistant concision, grounding, fallback, cost telemetry, privacy checks, and
  deterministic/provider evaluation harnesses.
- Accessibility automation, dashboard defects, CI security tooling, SBOM and
  dependency checks, deployment manifests, and operator documentation.
- Exact allowlists, source-truth maintenance, release verification, and repo
  hygiene checks.

### External Participation Is Required

- Human reviewers: genuine semantic labels, usability judgments, and any model
  activation decision.
- Hardware/network owner: non-loopback sender, second physical source, and
  approved forwarding path.
- Advisor/MFU: IAM callbacks/origins/groups, 2FA/recovery/deprovisioning policy,
  privacy approval, and preproduction access.
- Provider owner: Gemini billing/quota, key custody/rotation, retention policy,
  and shared-use approval.
- Deployment owner: Linux/PostgreSQL host, DNS/TLS, managed secrets, monitoring,
  shared storage, load/failover, and RPO/RTO drills.
- Repository owner: every commit, push, release, or activation approval.

## Shortest Remaining Roadmap

After v5.50, four substantial phases remain for a credible shared-lab release
candidate. External availability may block a phase, but blocked gates must not
be replaced by fabricated evidence.

1. **v5.51 Detection Pipeline Field Qualification And Fresh Evidence:** add
   privacy-safe field acceptance and fresh-development evidence contracts;
   qualify real forwarding, parser fields, and rule FP/FN when hardware and
   reviewers are available; do not tune on v5.49b.
2. **v5.52 Analyst Experience And Assistant Closure:** complete representative
   Assistant evaluation, provider governance telemetry, accessibility, and
   analyst workflow usability.
3. **v5.53 MFU IAM And Shared Deployment Acceptance:** validate the approved
   IAM lifecycle and PostgreSQL/TLS/secrets/monitoring/backup environment.
4. **v5.54 Release Candidate Closure:** clean-clone teammate acceptance,
   security/recovery matrix, frozen supported configurations, rollback, and
   final honest product statement.

Controlled senior-project scope is closed by v5.50. Shared-lab release scope
requires v5.51-v5.54. Production certification additionally requires ongoing
organization-owned security, operations, and field evidence and is not a fixed
version count.

## Verification

The complete v5.50 matrix passed:

- taskboard render and standards check: pass;
- Ruff and compileall: pass;
- backend: `1027 passed, 1 skipped`;
- Alembic: no new upgrade operations;
- React lint/build: pass;
- Playwright: `37 passed, 1 skipped`;
- disposable controlled source: pass with one expected port-scan alert and zero
  response actions;
- controlled scenarios: `24/24`;
- layered detection: `288/288`, controlled FP/FN `0/0`;
- deterministic Assistant QA: `20/20`, citation rate `1.0`, average/max answer
  length `62/117` words, no authoritative mutations;
- replay dry-run: two rows parsed, zero sent/imported/written;
- performance smoke: `ok: true`, all fixed budgets passed, no warnings;
- release gate: `ok: true`, no failed required checks.

The first direct backend command encountered a Windows ACL denial in the global
pytest `%TEMP%` directory, causing fixture setup errors rather than test
failures. The authoritative rerun used the repository's ignored, approved
`.tmp` contract and passed. The release gate independently reran the same
`1027/1` suite with its own `.tmp` paths and passed.

Final Git diff, privacy, ignored-output, staging, and exact allowlist checks are
recorded in the taskboard and v5.50 handoff.

No v5.50 commit or push is authorized by this document.

## v5.51 Recommended Implementation Prompt

```text
We completed v5.50 Current-State Truth Lock and Finish-Line Consolidation.

Next phase: v5.51 Detection Pipeline Field Qualification And Fresh Evidence.

Goal:
Close every detection-pipeline task Codex can complete now and provide one
fail-closed field-acceptance path for the external hardware/reviewer gates,
without tuning on consumed v5.49b evidence or changing alert authority.

Constraints:
- Do not reset/delete the database.
- Do not access, rerun, repartition, relabel, or tune against v5.49b protected
  evidence, claim, result, or evaluation labels.
- Do not fabricate a second source or human label.
- Do not activate/promote a model or write an active artifact.
- Keep rules alert-authoritative; ML remains advisory.
- Keep automatic response and real firewall blocking disabled.
- Keep private logs and generated evidence ignored and out of Git.
- Do not commit/push without separate exact-path approval.

Tasks:
1. Reverify the v5.50 source-truth and privacy boundary.
2. Create a versioned field-qualification contract for non-loopback syslog,
   source identity, parser layout/field accuracy, loss/duplicate accounting,
   source health, rule FP/FN review, and stop conditions.
3. Add a dry-run-first, privacy-safe acceptance CLI that accepts private source
   paths/receiver settings only through arguments or environment, uses
   disposable storage, and reports aggregates without paths, IPs, raw logs,
   fingerprints, credentials, or secrets.
4. Add parser layout fixtures and drift/fallback tests for every supported
   PAN-OS TRAFFIC/THREAT/SYSTEM contract that can be validated locally.
5. Add deterministic-rule field diagnostics and an independent-review pack
   format that hides model predictions and never marks assisted evidence human.
6. Define fresh development roles and a future untouched evaluation protocol
   after the v5.49b cutoff. Prove overlap/duplicate exclusion, but do not tune or
   evaluate unless genuinely new evidence exists.
7. Expose aggregate field-readiness status only; report Hardware Required,
   Reviewer Required, Ready, Failed, or Insufficient Evidence.
8. Add tests for privacy, duplicate containment, source attestation, parser
   fallback, no v5.49b access, no label/model/alert/response writes, and
   conservative readiness.
9. Update status, T1-T20, PRD, traceability, compliance, runbook, taskboard, and
   an exact commit allowlist.
10. Run the complete backend/frontend/detection/Assistant/performance/release
    and repository-hygiene matrix with disposable/test storage only.

Report:
- what was completed without external help
- field gates still requiring hardware, reviewer, advisor, or provider
- parser/rule findings and any honest FP/FN metrics
- fresh development/evaluation evidence counts, or Insufficient Evidence
- supervised lifecycle and all safety invariants
- files changed, verification results, exact allowlist
- substantial phases remaining after v5.51
- exact v5.52 recommendation
- no commit/push until separately approved
```
