# Product Requirements: ATDR

| Field | Value |
| --- | --- |
| Product | MFU AI-Driven Log-Based Threat Detection and Response |
| Baseline | v5.60 Clean-Machine Release Candidate Acceptance |
| Status | Controlled local release candidate |
| Production ready | No |
| Primary users | SOC analyst, ATDR administrator, approved operator |

## Product Purpose

ATDR collects firewall and syslog evidence, preserves and normalizes records,
detects explainable suspicious behavior, presents analyst-ready investigations,
and provides a read-only AI Assistant. The product prioritizes evidence,
traceability, safe failure, and analyst control over automated containment.

## Required Workflow

1. Authenticate through the approved MFU shell or explicit local recovery.
2. Register or inspect a log source.
3. Import a file, receive syslog, or replay a bounded sample.
4. Preserve raw evidence and normalize supported fields.
5. Run alert-authoritative deterministic rules.
6. Add anomaly, supervised, and hybrid evidence only where eligible.
7. Investigate an alert with related logs, source health, explanation, and
   recommendations.
8. Ask the SOC Assistant for concise, cited decision support.
9. Record assignment, notes, labels, and any simulated response decision.
10. Preserve an audit trail.

## Functional Requirements

| ID | Requirement | Current status |
| --- | --- | --- |
| FR-ING-01 | File/API import, replay, durable large-file jobs, and UDP syslog ingestion | Implemented; physical-source acceptance external |
| FR-PAR-01 | PAN-OS TRAFFIC/THREAT/SYSTEM, generic syslog, and raw-fallback normalization with warnings | Implemented; additional devices/versions external |
| FR-DET-01 | Versioned, correlated, deduplicated, explainable rule detection | Implemented and alert-authoritative |
| FR-ML-01 | Advisory IsolationForest scoring with governance visibility | Implemented; not authoritative |
| FR-ML-02 | Governed supervised SOC queue with leakage, calibration, and activation gates | Implemented but runtime `unqualified` |
| FR-EXP-01 | Explain why flagged, evidence strength, missing context, related logs, mappings, and next checks | Implemented |
| FR-AST-01 | Read-only deterministic and optional Gemini Assistant over bounded cited context | Implemented; institutional provider approval external |
| FR-ALT-01 | Alert assignment, notes, status, cases, and audit history | Implemented |
| FR-RSP-01 | Analyst-confirmed simulated response with no automatic or real blocking | Implemented as simulation only |
| FR-IAM-01 | MFU shell-first identity handoff with analyst default and configured group-to-admin mapping | Implemented locally; university acceptance external |
| FR-OPS-01 | Durable jobs, health, metrics, request IDs, backup/restore, retention, and deployment references | Implemented; approved-host evidence external |
| FR-UI-01 | Responsive React SOC workflows with error/loading/empty states and accessibility baseline | Implemented; independent usability audit external |

## Architecture Contract

- API: FastAPI on Python 3.11.
- UI: React, TypeScript, and Vite.
- Persistence: SQLAlchemy/Alembic; SQLite locally and PostgreSQL for an approved
  shared deployment.
- Detection: deterministic Python rules plus advisory scikit-learn layers.
- Identity entry: approved external MFU Node/Vue/MongoDB companion shell.

ATDR does not use MongoDB for security data and is not migrated to the shell's
Node/Vue architecture.

## Detection And AI Authority

- Rules are `active_authoritative` and may create alerts.
- IsolationForest is `active_advisory` when eligible.
- Supervised runtime is `unqualified`; inference fails closed.
- Hybrid triage is advisory.
- Gemini can synthesize only bounded ATDR context and is not a source of facts.
- The Assistant cannot perform actions.
- Response is `simulation_only` and requires an analyst decision.

The consumed v5.49b evaluation selected no supervised candidate. Future work
must use fresh development evidence, a second physical source, a predeclared
untouched future role, genuine prediction-blind human review, stable fixed
gates, and separate activation approval.

## Security And Privacy

- Use HttpOnly ATDR sessions after server-mediated shell handoff.
- Default external users to analyst; admin requires an approved private group.
- Never place school tokens, OTPs, bridge secrets, or API keys in URLs or
  browser storage.
- Exclude raw logs from external LLM context by default and redact IPs.
- Never expose secrets, private paths, protected decisions, predictions, or
  evidence fingerprints through status endpoints.
- Keep private data and generated evidence outside Git.

## Quality Requirements

- Migrations remain additive and Alembic reaches head without drift.
- Supported startup remains reproducible through `scripts/setup_team.cmd` and
  `scripts/start_system.cmd`.
- A genuine remote-clone acceptance must use isolated dependencies and storage,
  reject missing provider configuration, verify shell handoff contracts, leave
  no processes behind, and clean only its verified temporary directory.
- Failures produce bounded diagnostics without secret disclosure.
- Controlled detection and Assistant suites remain deterministic and green.
- Large SQLite queries preserve bounded cold behavior and fast cached paths.
- PostgreSQL, multiworker, backup, recovery, security, and CodeQL checks remain
  part of release qualification.

## Acceptance Boundary

Local source, tests, disposable data, and CI support a controlled release
candidate. Production acceptance additionally requires the owner-backed items
in `docs/EXTERNAL_ACCEPTANCE.md`. Missing external evidence must remain visible
and must never be replaced with a configured flag or synthetic result.

Historical requirements through v5.58 are preserved at
`docs/archive/governance/PRD_ATDR_THROUGH_V5_58.md`.
