# ATDR Product Finish Line

Date: 2026-08-31

## Purpose

This document is the short, decision-oriented finish plan for ATDR. It reduces
the remaining roadmap to the work needed to close the product responsibly. It
does not change runtime behavior, protected review evidence, model lifecycle,
or response safety.

ATDR is considered complete for the senior-project/shared-lab target when it
can reliably collect supported logs, preserve and normalize evidence, detect
and explain suspicious behavior, assist an analyst, and operate through a
repeatable deployment workflow with honest limitations.

Production certification, automatic containment, and real firewall blocking
are not part of this finish line.

## Source Truth

Use these sources in this order when status statements disagree:

1. Runtime source and mounted routes under `atdr/app/` and `frontend/src/`.
2. Tests, release scripts, and `.github/workflows/ci.yml`.
3. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md` and the latest completed versioned
   status document.
4. `docs/ATDR_REQUIREMENT_TRACEABILITY.md` and `docs/prd/PRD-ATDR.md`.
5. Older roadmap/status documents as historical evidence only.

## Finish Definition

| Product outcome | Required finish evidence |
|---|---|
| Collect logs | File upload, API upload, replay, durable/resumable import, and controlled syslog input reconcile raw and normalized counts without losing evidence. |
| Parse and normalize | Supported PAN-OS records satisfy the versioned parser contract; unsupported or malformed records preserve raw evidence with an explicit limited/fallback state. |
| Detect threats | Deterministic rules remain alert-authoritative, source/time scoped, deduplicated, and validated by controlled plus independent evidence. |
| Use ML safely | IsolationForest and supervised output remain advisory until fixed evidence gates pass. A failed candidate decision is an honest acceptable result, not a reason to weaken gates. |
| Explain findings | Every alert exposes what happened, why it was flagged, evidence strength, missing context, related logs, and bounded analyst checks. |
| Assist analysts | The SOC Assistant answers from bounded ATDR evidence, cites records, remains concise, preserves context, redacts sensitive fields, and falls back safely if Gemini is unavailable. |
| Present operations | The React dashboard provides clear source, alert, investigation, Assistant, governance, response, and audit workflows without unsafe or misleading claims. |
| Authenticate users | The MFU shell remains the normal entry; local recovery stays explicit; role mapping and external lifecycle behavior fail closed. |
| Operate safely | Shared deployment has PostgreSQL, worker, TLS, secrets, monitoring, backup/restore, and recovery evidence for the approved environment. |
| Release reproducibly | A teammate can set up and start the approved shell plus ATDR from a clean clone, and CI/release gates pass from the published commit. |

## Current Closure Position

### Implemented And Controlled-Validated

- File/API import, replay, local UDP syslog, source management, source health,
  durable jobs, resumable chunks, cancellation, and backpressure.
- PAN-OS TRAFFIC/THREAT/SYSTEM parsing, generic syslog, raw fallback, parser
  quality accounting, and raw evidence preservation.
- Versioned deterministic rule catalog, source/time correlation, alert
  deduplication, case grouping, explanations, and analyst recommendations.
- Controlled detection acceptance (`24/24`) and layered validation (`288/288`).
- Advisory IsolationForest and governed supervised experimentation with
  leakage controls and a fail-closed shadow lifecycle.
- Read-only SOC Assistant with deterministic grounding, Gemini/provider
  adapters, citations, bounded history, concise response contracts, privacy
  guards, audit, feedback, and safe fallback.
- React SOC workflows, admin/analyst RBAC, responsive viewport regression,
  operation health, AI Governance, and simulated response controls.
- SQLite local workflow, PostgreSQL CI and measured single-host qualification,
  multi-worker coordination, metrics, request IDs, and backup/restore tooling.

### Not Yet Closed

- Non-loopback forwarding from a real firewall/router and a second independent
  physical source.
- Independently labeled real-source false-positive/false-negative evidence.
- MFU preproduction callback/origin, group mapping, provider-managed 2FA,
  recovery, and deprovisioning acceptance.
- Institutional Gemini privacy, quota, cost, retention, and key-rotation
  approval for shared use.
- Approved-host DNS/TLS, managed secrets, persistent monitoring, shared
  storage, and measured deployment RPO/RTO.
- Formal accessibility/assistive-technology and independent analyst usability
  acceptance.

## Consolidated Remaining Roadmap

The previous roadmap is consolidated into the current v5.50 truth lock plus
four substantial product closure phases. Do not create additional phases
unless a verified defect or an external acceptance result requires one.

### v5.49b - Combined Fixed Revalidation (Complete)

- Genuine protected review is complete at `180/180`.
- The immutable combined evaluation ran exactly once.
- All eight strategies were evaluated and no candidate qualified.
- Evaluation suspicious support is zero and calibration confidence gaps fail.
- No model, artifact, alert authority, or response behavior changed.

Exit: one immutable negative result exists and lifecycle remains safely in
`shadow_observation`. The result is published at
`1866086e6ba9d0e6ac752e4b44e2b54a2acd6fb0`, and GitHub Actions run
`33348242534` is green.

### v5.51 - Detection Pipeline Field Qualification

- Consolidate v5.43-v5.49b into one source-backed public baseline.
- Remove stale baseline claims and duplicate/conflicting roadmap wording.
- Reconcile README, current-state, AI/ML, PRD, traceability, compliance, and
  taskboard documents.
- Confirm no protected/generated/private evidence is tracked.
- Publish one exact allowlist after separate approval.

Exit: the active source-of-truth documents, taskboard, and exact allowlist
describe the same current system state. Commit/push still require separate
approval.

### v5.51 - Detection Pipeline Field Qualification

This phase combines live-source, parser, rule, and supervised lifecycle work.

- Exercise non-loopback syslog and at least two verified devices when hardware
  becomes available.
- Qualify parser layouts and drift warnings against observed device records.
- Measure rule FP/FN behavior using independently reviewed real evidence.
- Branch from the immutable v5.49b negative result:
  - passing diagnostic candidate: freeze it for shadow observation only;
  - failed candidate: collect new development evidence and never tune against
    the consumed fixed evaluation.
- Keep rules authoritative and report insufficient evidence explicitly.

Exit: source/parser/rule field evidence is accepted, and supervised lifecycle
has a documented shadow/no-candidate decision without weakened gates.

Implementation update: the disposable service/CLI, parser compatibility and
field-accuracy contract, prediction-blind rule review, duplicate-contained
fresh roles, authenticated aggregate API, and AI Governance status are now
implemented and locally verified. Current status remains `hardware_required`:
the physical transport, second source, four post-boundary windows, and genuine
field/rule reviews are external and have not been fabricated. v5.51 therefore
closes Codex-owned harness work while leaving its field-acceptance exit open.

### v5.52 - Analyst Experience And Assistant Closure

- Run representative alert, source, case, and workflow questions through the
  deterministic and configured Gemini paths.
- Enforce concise intent-specific answers, citations, context continuity,
  privacy, fallback, latency, quota, and cost visibility.
- Complete formal keyboard, screen-reader, contrast, focus, responsive, and
  analyst-usability checks across the primary workflow.
- Remove remaining dashboard density or ambiguous status wording found by
  evidence, without adding new feature areas.

Exit: analysts can move from alert to evidence, recommendation, Assistant, and
simulated response without losing context or seeing misleading claims.

Implementation update: the locally controllable exit is complete. Entity
switches and reset prompts rotate conversations; ordinary follow-ups retain the
primary record; four sanitized tab-scoped turns survive navigation; provenance
is visible; and intent budgets are 55-120 words with at most two follow-ups.
Assistant QA passes `20/20`, and configured Gemini minimal/full synthetic probes
pass with no raw logs, secrets, or authoritative writes. Institutional provider
governance and formal independent usability/accessibility acceptance remain
external.

### v5.53 - IAM And Shared Deployment Acceptance

- Validate the approved MFU shell handoff in preproduction.
- Confirm callback origins, allowed domains, group-to-role mapping, 2FA,
  recovery, disabled-account behavior, and deprovisioning.
- Deploy PostgreSQL workers behind HTTPS with managed secrets, monitoring,
  alert routing, protected shared staging, scheduled retention, and verified
  backups.
- Execute load, failover, restore, and disaster-recovery drills and record
  measured RPO/RTO.

Exit: the approved environment passes the existing fail-closed preproduction
checklist. Local recovery, automatic response, and real blocking remain safe.

### v5.54 - Final Release Candidate Closure

- Run clean-clone teammate setup with the approved versioned MFU shell.
- Run the complete backend, frontend, PostgreSQL, detection, Assistant,
  performance, security, recovery, and hygiene matrix.
- Complete dependency/SBOM, secret-scanning, SAST, and release documentation.
- Freeze the supported configurations, known limitations, rollback procedure,
  and final product statement.

Exit: one tagged release candidate is reproducible, CI-green, documented, and
honest about every external or disabled capability.

## Parallel Work Rules

While a protected review or one-shot evaluation is active:

- Do not edit backend or frontend runtime files that could restart services.
- Do not touch protected review state, predictions, fingerprints, claims, or
  result files.
- Documentation-only planning may proceed in new, non-conflicting files.
- Do not update the taskboard or current status until the protected phase has a
  final aggregate result.
- Do not run broad verification against the active workspace.

## Ownership

| Owner | Required work |
|---|---|
| Codex | Implementation, tests, diagnostics, documentation, privacy guards, deployment references, CI/security automation, and exact allowlists. |
| Human reviewer | Genuine labels and semantic/usability judgments. AI suggestions never become human evidence automatically. |
| Repository owner | Commit/push approval, activation decision, environment approval, and custody of private files and secrets. |
| Advisor / MFU | IAM application, callbacks, groups, 2FA/recovery/deprovisioning policy, privacy approval, and preproduction access. |
| Hardware/network owner | Real firewall/router forwarding, second device, approved routing, and source identity. |
| Provider/deployment owner | Gemini quota/billing/rotation, PostgreSQL host, DNS/TLS, managed secrets, monitoring, storage, and recovery environment. |

## Stop-Doing List

To finish soon, ATDR will not add more synthetic tuning phases, new dashboard
modules, new model families, automatic response, real blocking, or duplicated
IAM/login systems unless a fixed acceptance result proves they are necessary.
The priority is evidence, consolidation, external acceptance, and release.

## Distance To Finish

- Controlled senior-project product: v5.49b plus v5.50 closure.
- Strong analyst-facing controlled release: add v5.52.
- Credible shared-lab release candidate: complete v5.51-v5.54.
- Substantial phases remaining after v5.52: two, plus the parallel external
  v5.51 field-evidence gate.
- Production certification is not a fixed version count; it additionally
  requires organization-owned operations, security review, and ongoing field
  evidence.
