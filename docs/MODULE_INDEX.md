# Module Index: Live vs. Historical

Date: 2026-09-22

## Why this exists

`atdr/app/detection/` and `atdr/app/services/` contain 177 files, a large
majority named `vNNN_*` after the development iteration that produced them.
Filename alone does not tell you whether a module is still executed by the
running system or is a completed one-time campaign script whose *output*
(not its code) is what the live system actually reads. This index answers
that question for every file, so a reviewer never has to walk the import
graph by hand to find out what `v340_suspicious_boundary_model.py` (for
example) actually is.

## Method

Every `.py` file under `atdr/` (685 files across `app/`, `scripts/`,
`tests/`) was parsed with Python's `ast` module to extract every import
statement, including ones nested inside functions or conditionals. No file
in `atdr/app` uses `importlib`/`__import__`/dynamic imports, so a static
import graph is complete and decisive — there are no "uncertain" cases in
this index. A module is **live** if it is reachable by import from
`atdr/app/main.py` or any `atdr/app/routers/*.py` file, directly or
transitively. A module is **historical** if its only referrers are its own
one-off `atdr/scripts/run_vNNN_*.py` script and/or `atdr/tests/test_vNNN_*.py`
test.

**Total: 177 files → 130 live / 47 historical (26.6%).**

## The historical population is not a version range

A natural guess is that "dead" modules form contiguous version ranges
(e.g. "everything from v330 to v362"). They don't. The 47 historical files
are individual abandoned side-branches sitting *inside* two long-lived,
still-active lineages, plus a few fully self-contained dead clusters:

1. **The dashboard-evaluation lineage** (`v330` → `v372`, rooted in
   `routers/dashboard.py`) is mostly live. Its dead side-branches:
   `v333, v334, v336, v338, v339, v340, v345, v350, v354`.
2. **The evidence-qualification lineage** (`v49`–`v57`, `v398`, `v521`–`v563`,
   rooted in `routers/evidence_review.py` and `routers/ml.py`) is mostly
   live. Its dead side-branches: `v514, v515, v516, v517, v518` (services),
   `v519` (detection), `v525` (services), `v531` (detection), `v538`
   (services).
3. **Fully self-contained dead islands** (no live root at all):
   - `v13_training.py`, `v14b_false_positive.py`, `v14c_malicious_recovery.py`
     — note `v14_false_positive.py` (no letter suffix) is a **different,
     live** file, imported by `v330_detection_ml_quality.py`. Easy to
     conflate with its dead `v14b`/`v14c` siblings by name alone.
   - `v564_window_aware_anomaly.py` — genuinely unwired. The anomaly model
     actually loaded at startup is `v561_anomaly_bootstrap_service.py`
     (`atdr/app/main.py:39`). `v564` is unpromoted research, not a
     supersession, despite the adjacent version number.
   - `v565_extended_evidence_expansion.py` / `v567_signal_concentrated_evidence_expansion.py`
     (detection) and their matching `*_review_service.py` files (services),
     plus `single_source_development_evaluation.py` and
     `supervised_review_worksheet_service.py`. These are the v5.65/v5.67
     supervised-evidence-campaign tiers — they were run as one-time CLI
     tools (`export_supervised_review_worksheet.py` /
     `import_supervised_review_worksheet.py`) against CSV worksheets, not
     through the live web UI. Their *output* (reviewed rows) was appended
     to a shared evidence pool file that `v530_supervised_evidence_closure.py`
     (live) reads generically — `v530` never imports `v565`/`v567`
     directly. Verified: neither module appears anywhere in
     `atdr/app/routers/*.py`. The earlier tiers, `v562`/`v563`, by
     contrast, **do** have live, router-wired review services
     (`v562_supervised_qualification_review_service.py`,
     `v563_supervised_expansion_review_service.py`) and their own panels in
     the Evidence Review UI — only the later, higher-volume tiers moved to
     the offline CSV workflow.

13 more historical files are non-versioned one-off admin/ops tooling, each
reachable only from its own script+test pair: `audit_retention_service.py`,
`load_test_service.py`, `mfu_iam_validation.py`,
`mfu_shell_package_service.py`, `ml_baseline_review_service.py`,
`repository_cleanup_service.py`, `repository_security_service.py`,
`repository_surface_service.py`, `staged_input_retention_service.py`,
`template_bridge_contract.py`, `template_shell_auth.py`, plus the two named
above.

## Full table

"Root entry" is the router (or `main.py`) that the module is ultimately
reachable from. `__init__.py` package markers are excluded.

### `atdr/app/detection/`

| Module | Status | Root entry / why |
|---|---|---|
| attack_mapping.py | live | logs.py |
| boundary_analysis.py | live | ml.py |
| cost_sensitive.py | live | ml.py |
| explanations.py | live | logs.py |
| hybrid_scoring.py | live | logs.py |
| ml_detector.py | live | main.py |
| model_comparison.py | live | ml.py |
| rule_catalog.py | live | logs.py |
| rules.py | live | logs.py |
| runtime_contract.py | live | ml.py |
| schema_contracts.py | live | ml.py |
| scoring.py | live | detection.py |
| single_source_development_evaluation.py | historical | script + test only |
| supervised_detector.py | live | ml.py |
| supervised_recovery.py | live | ml.py |
| supervised_workflow.py | live | ml.py |
| suspicious_recall_analysis.py | live | ml.py |
| threshold_tuning.py | live | ml.py |
| v13_training.py | historical | scripts + test only |
| v14_false_positive.py | live | dashboard.py (imported by v330) |
| v14b_false_positive.py | historical | script + test only; also imported by dead v14c |
| v14c_malicious_recovery.py | historical | script + test only |
| v49_detection_ml_reliability.py | live | evidence_review.py |
| v51_supervised_lifecycle.py | live | ml.py |
| v52_shadow_reliability.py | live | evidence_review.py |
| v53_temporal_generalization.py | live | ml.py |
| v54_temporal_evidence.py | live | ml.py |
| v55_development_model_repair.py | live | evidence_review.py |
| v56_private_panos_model_repair.py | live | evidence_review.py |
| v57_independent_shadow_revalidation.py | live | ml.py |
| v330_detection_ml_quality.py | live | dashboard.py |
| v331_noise_reduction.py | live | evidence_review.py |
| v332_guard_validation.py | live | dashboard.py |
| v333_guard_refinement.py | historical | script + test only |
| v334_soc_queue_redesign.py | historical | script + test only |
| v335_split_stability_repair.py | live | dashboard.py |
| v336_label_semantics.py | historical | script + test only |
| v337_evidence_feature_enrichment.py | live | dashboard.py |
| v338_calibrated_threshold_search.py | historical | script + test only; also imported by dead v339, v340 |
| v339_suspicious_recall_recovery.py | historical | script + test only |
| v340_suspicious_boundary_model.py | historical | script + test only |
| v341_label_semantics_audit.py | live | dashboard.py |
| v342_label_policy_reframing.py | live | dashboard.py |
| v343_hybrid_soc_queue.py | live | dashboard.py |
| v344_two_stage_soc_queue.py | live | dashboard.py |
| v345_queue_precision_severity_recall.py | historical | script + test only |
| v346_queue_target_separability.py | live | dashboard.py |
| v347_queue_target_repair_proposal.py | live | dashboard.py |
| v348_repaired_queue_target_model.py | live | dashboard.py |
| v349_repaired_queue_severity_model.py | live | dashboard.py |
| v350_queued_severity_semantics.py | historical | script + test only |
| v351_queue_severity_interface.py | live | dashboard.py |
| v352_repaired_interface_severity_model.py | live | dashboard.py |
| v353_severity_feature_repair.py | live | dashboard.py |
| v354_severity_target_semantics_audit.py | historical | script + test only |
| v355_severity_target_policy_reframing.py | live | dashboard.py |
| v357_queue_rule_hybrid_agreement.py | live | dashboard.py |
| v359_supervised_output_policy_contract.py | live | dashboard.py |
| v362_supervised_training_target_contract.py | live | dashboard.py |
| v372_unified_detection_ml_evaluation.py | live | dashboard.py (direct import) |
| v398_independent_holdout_validation.py | live | evidence_review.py |
| v399_multisource_frozen_revalidation.py | historical | script + test only; also imported by dead v400 |
| v400_provider_blinded_external_validation.py | historical | script + test only; also imported by dead v401 |
| v401_schema_aware_soc_queue.py | historical | script + test only |
| v519_independent_labeled_validation.py | historical | script + tests only; also imported by dead v520_schema_aware_abstention_validation.py |
| v520_schema_aware_abstention.py | live | ml.py |
| v520_schema_aware_abstention_validation.py | historical | script + test only (distinct file from v520_schema_aware_abstention.py above) |
| v521_native_panos_evidence.py | live | evidence_review.py |
| v522_supervised_model_rebuild.py | live | evidence_review.py |
| v526_native_blind_qualification.py | live | evidence_review.py |
| v527_blind_review_evaluation.py | live | evidence_review.py |
| v528_blind_review_helper.py | live | evidence_review.py |
| v528_supervised_readiness.py | live | evidence_review.py (distinct file from v528_blind_review_helper.py, both live) |
| v530_supervised_evidence_closure.py | live | evidence_review.py |
| v531_adversarial_reliability.py | historical | script + test only |
| v540_development_supervised_repair.py | live | evidence_review.py (via v541-v549a, which the router imports directly) |
| v541_governed_blind_evidence.py | live | evidence_review.py (direct import) |
| v542_development_candidate_freeze.py | live | evidence_review.py (direct import) |
| v543_temporal_stability_repair.py | live | evidence_review.py (direct import) |
| v544_chronological_evidence.py | live | evidence_review.py |
| v545_development_model_repair.py | live | evidence_review.py (direct import) |
| v546_manual_anchor_transfer_repair.py | live | evidence_review.py (direct import) |
| v547_manual_anchor_acquisition.py | live | evidence_review.py (direct import) |
| v548_manual_anchor_fixed_revalidation.py | live | evidence_review.py (direct import) |
| v549_fixed_revalidation_decision.py | historical | script + test only (distinct from live v549a/v549b) |
| v549a_supplemental_threat_anchor_acquisition.py | live | evidence_review.py (direct import) |
| v549b_combined_fixed_revalidation.py | live | evidence_review.py (direct import) |
| v562_supervised_qualification_campaign.py | live | evidence_review.py |
| v563_fresh_evidence_expansion.py | live | evidence_review.py |
| v564_window_aware_anomaly.py | historical | script + test only; NOT referenced in main.py (v561 is the live anomaly module) |
| v565_extended_evidence_expansion.py | historical | one-time CSV-worksheet campaign tool; no live importer |
| v567_signal_concentrated_evidence_expansion.py | historical | one-time CSV-worksheet campaign tool; no live importer |
| v5631_advisor_demo_reliability.py | historical | scripts + test only; also imports dead v564 |

### `atdr/app/services/`

| Module | Status | Root entry / why |
|---|---|---|
| account_verification_service.py | live | auth.py |
| active_learning_service.py | live | ml.py |
| alert_service.py | live | alerts.py |
| assistant_llm.py | live | assistant.py |
| assistant_response_contracts.py | live | assistant.py |
| assistant_service.py | live | assistant.py (direct import) |
| assisted_label_service.py | live | ml.py |
| audit_retention_service.py | historical | script + test only |
| backup_monitoring_service.py | live | observability.py |
| case_service.py | live | alerts.py |
| class_temporal_coverage_service.py | live | ml.py |
| dashboard_service.py | live | dashboard.py (direct import) |
| database_coordination_service.py | live | evidence_review.py |
| demo_service.py | live | demo.py (direct import) |
| detection_coordination_service.py | live | detection.py |
| detection_service.py | live | detection.py (direct import) |
| email_service.py | live | auth.py |
| evidence_review_service.py | live | evidence_review.py (direct import) |
| job_dispatcher.py | live | jobs.py (direct import) |
| job_service.py | live | jobs.py |
| label_quality_service.py | live | ml.py |
| load_test_service.py | historical | script + test only |
| log_service.py | live | logs.py |
| metrics_service.py | live | observability.py |
| mfu_iam_service.py | live | auth.py |
| mfu_iam_validation.py | historical | script + test only |
| mfu_shell_package_service.py | historical | scripts + test only; also imported by dead v560 |
| ml_baseline_review_service.py | historical | script + test only |
| ml_evidence_snapshot_service.py | live | ml.py |
| ml_label_service.py | live | ml.py |
| ml_service.py | live | ml.py |
| observability_service.py | live | main.py (direct import) |
| operation_run_service.py | live | logs.py |
| operation_worker.py | live | evidence_review.py |
| persistence_service.py | live | observability.py |
| preproduction_acceptance_service.py | live | observability.py |
| private_log_preflight_service.py | live | evidence_review.py |
| repository_cleanup_service.py | historical | script + test only |
| repository_security_service.py | historical | script + test only |
| repository_surface_service.py | historical | script + test only |
| response_service.py | live | response.py (direct import) |
| resumable_ingestion_service.py | live | jobs.py |
| runtime_parser_quality_service.py | live | sources.py |
| source_service.py | live | sources.py |
| staged_input_retention_service.py | historical | script + test only |
| staging_service.py | live | jobs.py |
| supervised_review_worksheet_service.py | historical | scripts + test only; imports dead v565/v567 review services |
| suppression_service.py | live | suppressions.py |
| syslog_service.py | live | evidence_review.py |
| template_bridge_contract.py | historical | scripts + tests only |
| template_shell_auth.py | historical | scripts + test only |
| tuning_service.py | live | detection.py (direct import) |
| user_service.py | live | auth.py |
| watchlist_service.py | live | watchlists.py |
| windows_firewall_connector.py | live | main.py (direct import) |
| v50_shadow_validation_service.py | historical | scripts + test only |
| v58_shadow_scoring_service.py | live | ml.py |
| v59_shadow_observation_service.py | live | ml.py |
| v510_detection_operations_service.py | live | ml.py (direct import) |
| v511_shadow_monitoring_service.py | live | ml.py (direct import) |
| v512_parser_baseline_service.py | live | ml.py (direct import) |
| v514_large_file_runtime_service.py | historical | script + test only; also imported by dead v515-v518 |
| v515_runtime_soak_service.py | historical | script + test only; also imported by dead v516 |
| v516_memory_query_service.py | historical | script + test only; also imported by dead v517, v518 |
| v517_postgres_multiworker_service.py | historical | script + test only; also imported by dead v518 |
| v518_postgres_scale_service.py | historical | script + test only |
| v523_live_source_acceptance_service.py | live | evidence_review.py |
| v524_investigation_gemini_quality_service.py | live | evidence_review.py |
| v525_integrated_acceptance_service.py | historical | script + test only |
| v527_gemini_real_alert_quality_service.py | live | evidence_review.py (distinct from detection's v527_blind_review_evaluation.py) |
| v533_independent_acceptance_service.py | live | evidence_review.py |
| v536_independent_evidence_activation_service.py | live | evidence_review.py |
| v538_product_reliability_service.py | historical | script + test only |
| v539_independent_evidence_decision_service.py | live | evidence_review.py |
| v548_manual_anchor_review_service.py | live | evidence_review.py (direct import) |
| v549a_supplemental_threat_anchor_review_service.py | live | evidence_review.py (direct import) |
| v551_field_qualification_service.py | live | evidence_review.py (direct import) |
| v553_release_readiness_service.py | live | observability.py (direct import) |
| v560_clean_machine_acceptance_service.py | historical | script + test only |
| v561_anomaly_bootstrap_service.py | live | main.py:39 (direct import — the live anomaly module) |
| v562_supervised_qualification_review_service.py | live | evidence_review.py (direct import) |
| v563_supervised_expansion_review_service.py | live | evidence_review.py (direct import) |
| v565_extended_expansion_review_service.py | historical | one-time CSV-worksheet campaign tool; no live importer |
| v567_signal_concentrated_expansion_review_service.py | historical | one-time CSV-worksheet campaign tool; no live importer |

## Maintaining this index

This was generated by a full static import-graph trace (`ast`-parsing every
file under `atdr/`, breadth-first from `main.py` + every router). If new
`vNNN_*` modules are added, re-run the same method rather than guessing from
filenames — as this index's own corrections to an earlier, less rigorous
version-range guess demonstrate, adjacent version numbers are not a
reliable signal of live vs. historical status.
