# ATDR University Compliance Checklist

This checklist records the active process standard. Historical evidence remains
available in archived phase and T1-T20 records.

## Workflow And Evidence

| Requirement | State | Evidence |
| --- | --- | --- |
| Inspect source before implementation | Satisfied | Active engineering workflow and T1-T20 records |
| Maintain an ATDR-specific PRD | Satisfied | `docs/prd/PRD-ATDR.md` |
| Maintain requirement traceability | Satisfied | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Maintain tasklist and HTML progress board | Satisfied | `docs/tasks/tasklist-progress.md` and generated HTML |
| Record non-trivial work with T1-T20 | Satisfied | current record under `docs/changes/`; history under `docs/archive/changes/` |
| Preserve supervisor references without adopting the wrong stack | Satisfied | `docs/reference/` remains reference-only |
| Keep exact approval-gated commit boundaries | Satisfied | current allowlist plus archived allowlists |
| Prove clean-clone reproducibility | Satisfied locally | v5.60 genuine `origin/main` clone passed `27/27`; physical teammate repetition remains external |
| Reproduce anomaly capability safely | Satisfied locally | v5.61 preflight, exact confirmation, disposable training, ignored provenance, and advisory-only acceptance |

## Product Integrity

| Requirement | State | Evidence |
| --- | --- | --- |
| Collect and preserve log evidence | Implemented locally | file/API/replay/syslog and durable ingestion services/tests |
| Parse and normalize with quality visibility | Implemented for supported profiles | parser contracts, warnings, drift and field tests |
| Explain deterministic detection | Implemented | rule catalog, explanations, related evidence, recommendations |
| Keep AI/ML claims honest | Satisfied | rules authoritative; anomaly/hybrid advisory and not threat-accuracy validated; supervised unqualified |
| Preserve human-label provenance | Satisfied | protected review, weak-label separation, no automated human claims |
| Keep Assistant grounded and read-only | Satisfied locally | bounded context, citations, redaction, fallback, no-side-effect tests |
| Keep response controlled | Satisfied | simulation only; no automatic response or real blocking |

## Security And Operations

| Requirement | State | Remaining owner action |
| --- | --- | --- |
| MFU shell-first authentication | Packaged clean-clone controls verified | university preproduction and real-account lifecycle acceptance |
| Least-privilege role mapping | Implemented fail closed | approved MFU admin group identifier |
| Secret and private-evidence exclusion | Implemented | continue scanning every release |
| Migration and database compatibility | Implemented | approved-host operational evidence |
| Backup, restore, monitoring, and recovery | Repository-ready | measured owner RPO/RTO and drill evidence |
| Dependency/SAST checks | Implemented | maintain CI, audits, and CodeQL |
| Accessibility baseline | Automated checks pass | independent assistive-technology/usability review |

## Mandatory Safety State

- `production_ready=false`
- rules `active_authoritative`
- supervised runtime `unqualified`
- Assistant read-only
- raw external LLM logs disabled
- response `simulation_only`
- automatic response disabled
- real firewall blocking disabled

Configuration alone is not acceptance. Missing human, hardware, university,
provider, deployment, or repository-owner evidence must remain explicitly
pending.

The complete compliance ledger through v5.58 is preserved at
`docs/archive/governance/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST_THROUGH_V5_58.md`.
