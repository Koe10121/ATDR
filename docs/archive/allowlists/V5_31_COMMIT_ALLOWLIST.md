# v5.31 Exact Commit Allowlist

## Purpose

This file defines the exact tracked review boundary for v5.31 Deterministic
Detection and Explainability Adversarial Reliability Lock.

It does not authorize staging, committing, pushing, or force operations. Those
actions require a separate explicit user approval.

## Exact Paths (28)

```text
atdr/app/detection/attack_mapping.py
atdr/app/detection/explanations.py
atdr/app/detection/rule_catalog.py
atdr/app/detection/rules.py
atdr/app/detection/v531_adversarial_reliability.py
atdr/app/detection/v56_private_panos_model_repair.py
atdr/app/services/alert_service.py
atdr/app/services/assistant_service.py
atdr/app/services/case_service.py
atdr/app/services/detection_service.py
atdr/scripts/run_v531_detection_explainability_adversarial_reliability.py
atdr/tests/test_detection_explanations.py
atdr/tests/test_rules.py
atdr/tests/test_v49_detection_ml_reliability.py
atdr/tests/test_v531_detection_explainability_adversarial_reliability.py
data/samples/scenarios/adversarial/v5_31_detection_corpus.json
data/samples/scenarios/ddos_or_connection_flood_like.txt
docs/AI_TRAINING_RUNBOOK.md
docs/ATDR_REQUIREMENT_TRACEABILITY.md
docs/CURRENT_AI_ML_PRODUCT_STATUS.md
docs/DETECTION_RULE_CATALOG.md
docs/V5_31_COMMIT_ALLOWLIST.md
docs/V5_31_DETECTION_EXPLAINABILITY_ADVERSARIAL_RELIABILITY.md
docs/changes/T1_T20_V5_31_DETECTION_EXPLAINABILITY_ADVERSARIAL_RELIABILITY.md
docs/detection/ATDR_DETECTION_TAXONOMY.md
docs/detection/ATDR_RULE_PACK_CONTRACT.md
docs/tasks/tasklist-progress.html
docs/tasks/tasklist-progress.md
```

## Explicit Exclusions

Do not stage or track:

- `.env` or any private environment/profile file;
- databases, backups, logs, uploaded evidence, or processed data;
- model artifacts, labels, reviews, prediction locks, fingerprints, or private
  evidence manifests;
- `ml_baseline_reviews/`, `demo_exports/`, generated reports, build/test
  output, or temporary databases;
- private PAN-OS paths, raw rows, IP addresses, source identities, reviewer
  identities, provider credentials, or secrets; or
- any path not listed above.

## Review Commands

```powershell
git status --short --untracked-files=all
git diff --check
git diff --name-only
git ls-files --others --exclude-standard
git diff --cached --name-only
```

Expected staging state is empty. Before any later approved Git operation,
compare the normalized changed-path set exactly with these 28 paths and stop
on any mismatch.
