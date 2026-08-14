# v5.40 Exact Commit Allowlist

This file records the exact tracked boundary for v5.40. It does not authorize
staging, committing, or pushing. Separate explicit owner approval is required.

Exact path count: **12**.

1. `atdr/app/detection/v540_development_supervised_repair.py`
2. `atdr/scripts/run_v540_development_supervised_repair.py`
3. `atdr/tests/test_v540_development_supervised_repair.py`
4. `docs/AI_TRAINING_RUNBOOK.md`
5. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
6. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
7. `docs/V5_40_COMMIT_ALLOWLIST.md`
8. `docs/V5_40_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
9. `docs/changes/T1_T20_V5_40_DEVELOPMENT_SUPERVISED_REPAIR.md`
10. `docs/detection/V5_40_NEW_BLIND_EVIDENCE_PROTOCOL.md`
11. `docs/tasks/tasklist-progress.html`
12. `docs/tasks/tasklist-progress.md`

Explicitly excluded:

- `.env` files, credentials, and provider payloads;
- databases, private logs, raw evidence, IP addresses, source identities,
  paths, review tokens, fingerprints, digests, and reviewer decisions;
- labels, model artifacts, generated reports, blind packs, predictions, and
  calibration output;
- `ml_baseline_reviews/`, `demo_exports/`, processed evidence, `.tmp/`, and
  test artifacts; and
- every path not listed above.

The allowlist preserves `shadow_observation`, deterministic-rule authority,
read-only ML decision support, response simulation, and disabled real firewall
blocking.
