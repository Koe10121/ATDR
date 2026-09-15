# ATDR Detection And ML Productization Plan

## Status

Planning document for the production-readiness track. This does not activate a model, change thresholds, write model artifacts, write labels, enable automatic response, enable real firewall blocking, or claim production readiness.

## Source Evidence

ATDR source evidence inspected:

- `atdr/app/detection/rules.py`
- `atdr/app/services/detection_service.py`
- `atdr/app/detection/ml_detector.py`
- `atdr/app/detection/supervised_detector.py`
- `atdr/app/ml/features.py`
- `atdr/app/detection/v355_severity_target_policy_reframing.py`
- `atdr/app/routers/ml.py`
- `atdr/app/routers/dashboard.py`
- `frontend/src/pages/MLGovernance.tsx`
- `frontend/src/pages/AlertsTriage.tsx`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/V3_30_DETECTION_ML_QUALITY_REVALIDATION.md`
- `docs/V3_55_SEVERITY_TARGET_POLICY_REFRAMING.md`
- `docs/V3_56_SOC_QUEUE_DIAGNOSTIC_INTEGRATION.md`
- `docs/V3_59_SUPERVISED_OUTPUT_POLICY_CONTRACT.md`

Supervisor-template evidence inspected:

- `<MFU_SHELL_ROOT>\docs\prd\PRD-MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSE.md`
- `<MFU_SHELL_ROOT>\docs\AI-WORKFLOW.md`
- `<MFU_SHELL_ROOT>\docs\tasks\tasklist-progress.md`

Supervisor-template conclusion: the template supplies process discipline, PRD traceability, IAM/security workflow, task tracking, and release expectations. It does not contain a reusable log-threat detection or ML pipeline. ATDR should keep its FastAPI/React/Python ML design and adapt only the workflow evidence standards.

## Current Detection Architecture

ATDR currently uses a layered detection design:

1. Raw firewall/syslog/file evidence is stored first.
2. Parser profiles normalize logs where possible while preserving raw evidence.
3. Rule detection in `rules.py` generates explainable evidence signals.
4. `detection_service.py` groups and deduplicates evidence into alerts.
5. IsolationForest anomaly scoring in `ml_detector.py` marks unusual logs as an assistive signal.
6. Supervised ML experiments in `supervised_detector.py` and v3.x diagnostic modules evaluate label-driven SOC triage candidates.
7. Dashboard and SOC Assistant expose why-flagged explanations, source references, queue diagnostics, and safety constraints.

## Current Strengths

- Deterministic rules are explainable and documented in `docs/DETECTION_RULE_CATALOG.md`.
- Alert grouping/deduplication preserves raw evidence while reducing alert spam.
- Controlled scenario validation exists for parser, detection, source health, and no-response safety.
- Feature engineering includes behavior-window features such as source counts, deny ratios, diversity, unknown-app counts, high-risk app counts, and scan-like behavior score.
- The best documented supervised direction is a binary SOC review-queue target, not exact severity classification.
- v3.55/v3.59 evidence supports queue-score decision support while exact severity remains explanation/ranking only.
- AI Governance and SOC Assistant already display that ML is decision support, not response authority.

## Current Limitations

- Exact suspicious/malicious/needs_context classification remains semantically unstable.
- Older supervised model registry entries can still confuse users if active artifact metadata is incomplete.
- Multiple v3.x diagnostic scripts exist, but they are not yet unified into one product-grade model evaluation command.
- Generated ML reports live under ignored review/report folders and are not part of a stable artifact registry contract.
- Calibration and split stability are proven only for selected diagnostic policies, not for every active training path.
- Rule configuration is code-driven rather than a versioned product rule-pack contract.
- Real-source drift monitoring remains limited without sustained hardware/syslog validation.
- The system does not yet have a formal model promotion workflow suitable for a SaaS product.

## Productization Direction

ATDR should productize detection/ML around three separate contracts:

| Layer | Product Role | Authority |
| --- | --- | --- |
| Rule and hybrid evidence | Primary alert evidence and explanation | Can create alerts, subject to grouping/dedup/suppression |
| Anomaly scoring | Assistive unusualness signal | Cannot create response by itself |
| Supervised SOC queue | Decision-support prioritization | Can recommend analyst review priority, but cannot activate response |

Exact severity and exact attack labels should remain explanation/ranking fields until future evidence proves stable multi-class performance across time, random, source-aware, and fresh holdout validation.

## Target Product Contracts

### 1. Rule Pack Contract

Create a versioned rule-pack manifest:

- rule id
- title
- attack type hint
- score contribution
- required normalized fields
- confidence class
- likely false positives
- analyst next checks
- expected scenario coverage
- ATT&CK-style mapping when applicable

Candidate artifact:

```text
docs/detection/ATDR_RULE_PACK_CONTRACT.md
```

Future runtime artifact:

```text
atdr/app/detection/rule_catalog.py
```

### 2. Scenario Corpus Contract

Promote controlled safe scenarios into a stable regression corpus:

- benign/normal allowed traffic
- scanning-like traffic
- repeated dedup traffic
- generic syslog mixed data
- malformed/raw fallback data
- app-risk-only noise
- QUIC/443 benign-like traffic
- unknown UDP scan-like traffic
- high-volume outbound behavior

Each scenario should define:

- expected parser result
- expected normalized row count
- expected alert range
- allowed alert types
- forbidden alert types
- expected explanation completeness
- expected response action count: always 0

### 3. SOC Queue Model Contract

Use the binary review queue target as the primary supervised ML product contract:

- `non_threat`
- `needs_review`

Requirements:

- queue precision minimum target
- queue recall minimum target
- benign-like false-positive maximum
- calibration target, including ECE and confidence/accuracy gap
- split stability target across time, random, and source-aware splits
- no model activation unless all gates pass
- no response automation from queue output

### 4. Exact Severity Policy

Exact severity labels are useful for explanation and ranking but should remain blocked from hard production use until:

- exact class stability passes across multiple split strategies
- suspicious recall does not collapse
- malicious recall stays acceptable
- calibration passes
- independent/fresh holdout validation passes
- real-source drift is monitored

Current policy: explanation/ranking only.

### 5. Model Registry Contract

The supervised model registry should clearly separate:

- active artifact state
- candidate diagnostic runs
- evaluation-only runs
- legacy artifacts with unknown metadata
- activation and rollback events

Every candidate should expose:

- model family
- feature set version
- data snapshot or label snapshot reference
- split strategy
- key metrics
- calibration status
- readiness decision
- promotion decision
- safety flags: model activated, production promoted, response automation allowed

## Recommended Implementation Phases

### v3.71 Rule Pack And Scenario Contract

Status: implemented as a source-backed contract and read-only validator.

Goal: make rules and scenario expectations product-grade.

Deliverables:

- `docs/detection/ATDR_RULE_PACK_CONTRACT.md`
- `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`
- `atdr/scripts/validate_rule_pack_contract.py`
- `atdr/tests/test_rule_pack_contract.py`
- no threshold or behavior change unless a clear bug is found

### v3.72 Unified Detection/ML Evaluation Command

Status: implemented as a read-only productization evaluator.

Goal: replace scattered ad hoc diagnostics with a single safe evaluator.

Command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --pretty
```

Optional controlled scenario validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --include-scenarios --scenario normal_allowed_traffic --scenario port_scan_like_traffic --pretty
```

Report sections:

- rule-pack and scenario-corpus contract status
- optional temporary-DB controlled scenario quality
- latest supervised output policy artifact summary
- latest safe training-target artifact summary
- lightweight label/model/response counts
- exact severity warning
- response-safety invariants
- required blockers and advisory gaps

### v3.73 SOC Queue Candidate Integration Cleanup

Goal: make the stable queue candidate easier to understand and use as decision support.

Deliverables:

- clear ML Governance queue panel
- alert detail queue-support section if diagnostic result exists
- SOC Assistant explanation of queue score as decision support
- no model activation
- no automatic response

### v3.74 Model Registry And Artifact Safety Cleanup

Goal: remove confusion around unknown active artifacts and candidate-only runs.

Deliverables:

- active artifact metadata warning
- candidate model summary table
- activation blocked unless explicit reviewed gate passes
- rollback/activation audit clarity
- tests proving no automatic activation

### v3.75 Drift And Real-Source Monitoring

Goal: prepare for shared lab and real firewall/syslog data.

Deliverables:

- source-level parse drift metrics
- unknown-app drift
- alert-type drift
- queue-score drift
- high-noise source detection
- safe warnings in Operations Health

### v3.76 ML Promotion Gate Hardening

Goal: define the minimum gate before any future model activation discussion.

Required gates:

- stable queue metrics across standard splits
- calibration passed
- no response automation
- no raw log export
- reviewed label provenance sufficient
- model artifact hash recorded
- rollback path tested
- administrator approval required
- documented safety review

## Acceptance Gates

Before any future supervised model activation can even be considered:

- backend tests pass
- Alembic has no drift
- React lint/build/e2e pass
- release gate passes
- scenario corpus passes
- no automatic response actions are created
- no labels are written by diagnostic scripts
- no model artifact is written unless the command is explicitly a training command
- model registry marks candidates as candidate-only
- dashboard states decision support only

## What Requires User Or External Input

- Real firewall/router/syslog hardware for sustained validation.
- Approved production/lab database plan if moving beyond SQLite.
- Advisor-approved policy for using school or private logs in model training.
- Formal definition of acceptable false-positive/false-negative budgets.
- Formal policy for whether an ML queue score can ever affect alert priority.
- Human-reviewed label governance if future labels are imported.

## Immediate Next Recommendation

Implement v3.71: Rule Pack And Scenario Contract.

This is the safest next engineering step because it improves the foundation for detection quality without changing runtime thresholds, retraining models, enabling response automation, or requiring external hardware.
