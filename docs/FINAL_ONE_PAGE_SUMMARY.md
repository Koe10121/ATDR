# ATDR Final One-Page Project Summary

## Project Title

**AI-Driven Log-Based Threat Detection and Response System (ATDR)**

## Problem

Firewall and syslog systems generate more records than analysts can inspect
manually. Rule-only detection is explainable but may miss unfamiliar behavior.
Machine learning can improve prioritization but may produce false positives or
unsafe confidence. A trustworthy solution must preserve evidence, explain its
findings, and keep response authority with the analyst.

## Solution

ATDR is a controlled lab-scale SOC triage prototype that:

- ingests file, replay, safe scenario, and local syslog inputs;
- preserves raw evidence before parsing;
- normalizes Palo Alto and generic syslog fields;
- tracks source health and data quality;
- combines rules, behavior windows, IsolationForest anomaly scoring,
  supervised triage, and hybrid risk;
- creates explainable, deduplicated alerts;
- groups related activity into lightweight cases;
- supports human label review and AI Governance;
- records simulated analyst-approved response actions and audit evidence.

## Architecture

```text
Log Source
  -> Raw Evidence
  -> Parser Profile
  -> Normalized Log
  -> Rule / Anomaly / Supervised Signals
  -> Hybrid Risk
  -> Alert And Case
  -> Analyst Investigation
  -> Simulated Response
  -> Audit Trail
```

**Technology stack**

- Backend: Python, FastAPI, Pydantic
- Frontend: React, TypeScript, Vite
- Database: SQLAlchemy, Alembic, SQLite
- ML: scikit-learn
- Security: local JWT, admin/analyst RBAC
- Verification: Ruff, Pytest, Alembic check, ESLint, TypeScript build,
  Playwright, performance smoke, release gate

## Final Validation

Fresh blind holdout:

| Metric | Result |
| --- | ---: |
| Rows / sources / scenarios | 700 / 7 / 16 |
| Threat precision | 0.8906 |
| Threat recall | 0.9459 |
| Threat F1 | 0.9174 |
| Benign-like FPR | 0.1303 |
| Suspicious recall | 0.8556 |
| Malicious recall | 0.9000 |
| Readiness checks | 22/22 |

Confidence assessment passed without blind-label fitting:

- ECE: 0.0757
- Brier score: 0.0751
- Maximum confidence gap: 0.1878

Controlled source acceptance:

- 28 raw logs
- 25 parse successes
- 3 tracked failures
- 2 alerts
- 2 cases
- Deduplication, explanation, protected-IP denial, and audit verified
- 0 automatic responses

## Current Status And Safety Boundary

- **Final Controlled Validation Candidate**
- **Decision Support Only**
- **Response Automation Disabled**
- **Not Production Promoted**
- **Real firewall blocking disabled**
- Candidate/profile: `independent_fpr_stabilized`

These results demonstrate controlled academic readiness. They do not establish
production accuracy or deployment approval.

## Limitations

- No completed real router/firewall forwarding pilot.
- No production high availability, retention, backup, or disaster recovery.
- SQLite is not validated for shared production scale.
- Local JWT/RBAC is not enterprise IAM.
- Synthetic and reviewed datasets cannot represent all real traffic.
- No real enforcement connector.
- Case grouping is not a full incident-ticketing platform.

## Future Work

1. Run a controlled multi-day real-device syslog pilot.
2. Review real-source false positives and drift.
3. Expand independently reviewed real-source labels.
4. Validate PostgreSQL and shared-lab deployment.
5. Add TLS, secret management, backup, retention, and monitoring.
6. Complete university OIDC after provider and role policy approval.
7. Design a vendor-approved response connector with rollback and formal
   authorization while keeping it disabled until validated.

## Conclusion

ATDR demonstrates an end-to-end, evidence-preserving, AI-assisted SOC workflow
that combines explainable detection with human review and response safety. The
engineering prototype is complete for final academic demonstration within its
controlled lab scope.

