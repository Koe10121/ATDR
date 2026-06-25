from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v362_supervised_training_target_contract import (
    SAFE_QUEUE_TARGETS,
    build_safe_training_target_adapter,
    build_supervised_training_target_contract,
    run_v362_supervised_training_target_contract,
)
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _label(label: str, *, reviewed: bool = True) -> SimpleNamespace:
    return SimpleNamespace(id=None, label=label, reviewed=reviewed, label_source="manual" if reviewed else "weak")


def _log(app: str, action: str, port: int) -> SimpleNamespace:
    return SimpleNamespace(id=None, app=app, action=action, dst_port=port, raw_log=None)


def _base_row(**overrides):
    row = {
        "v337_rule_backed_allow_flag": 0,
        "v337_anomaly_signal_flag": 0,
        "v337_web_scan_context_flag": 0,
        "v337_incomplete_scan_context_flag": 0,
        "v337_unknown_scan_context_flag": 0,
        "v337_web_low_signal_flag": 0,
        "v337_utility_low_signal_flag": 0,
        "v337_low_signal_allow_flag": 0,
        "v337_behavior_evidence_strength": 0.0,
        "v337_benign_web_likelihood_score": 0.0,
        "v337_traffic_family": "web_general",
    }
    row.update(overrides)
    return row


def test_v362_safe_training_target_adapter_maps_exact_labels_to_queue_targets():
    prepared = {
        "y": ["benign", "benign", "suspicious"],
        "labels": [_label("benign"), _label("benign"), _label("suspicious", reviewed=False)],
        "logs": [_log("quic-base", "allow", 443), _log("ssl", "allow", 443), _log("unknown-udp", "allow", 53)],
    }
    frame = pd.DataFrame(
        [
            _base_row(
                v337_web_low_signal_flag=1,
                v337_low_signal_allow_flag=1,
                v337_benign_web_likelihood_score=2.0,
                v337_traffic_family="web_low_signal",
            ),
            _base_row(
                v337_rule_backed_allow_flag=1,
                v337_behavior_evidence_strength=4.5,
                v337_traffic_family="web_rule_backed",
            ),
            _base_row(
                v337_unknown_scan_context_flag=1,
                v337_behavior_evidence_strength=3.5,
                v337_traffic_family="unknown_scan_context",
            ),
        ]
    )

    adapter = build_safe_training_target_adapter(prepared, frame)

    assert adapter["all_rows_mapped_to_safe_targets"] is True
    assert set(adapter["target_distribution"]).issubset(SAFE_QUEUE_TARGETS)
    assert adapter["target_distribution"]["non_threat"] == 1
    assert adapter["target_distribution"]["needs_review"] == 2
    assert ["benign->non_threat", 1] in adapter["original_label_to_safe_target"]
    assert ["benign->needs_review", 1] in adapter["original_label_to_safe_target"]
    assert ["suspicious->needs_review", 1] in adapter["original_label_to_safe_target"]
    assert adapter["row_sample"][0]["exact_label_policy"] == "explanation_or_ranking_only"
    assert adapter["row_sample"][0]["raw_log_included"] is False
    assert adapter["row_sample"][0]["human_review_written"] is False


def test_v362_contract_blocks_exact_label_targets_and_automation():
    adapter = {
        "all_rows_mapped_to_safe_targets": True,
        "target_distribution": {"non_threat": 2, "needs_review": 1},
        "high_severity_semantic_issue_count": 1,
        "weak_high_severity_semantic_issue_count": 1,
    }
    contract = build_supervised_training_target_contract(
        adapter=adapter,
        split_drift=[
            {
                "split_mode": "time",
                "status": "evaluated",
                "absolute_rate_shift": 0.05,
            }
        ],
    )

    assert contract["decision"] == "safe_queue_target_adapter_ready"
    assert contract["recommended_training_target"] == "binary_soc_review_queue"
    assert contract["exact_label_policy"] == "explanation_or_ranking_only"
    assert contract["runtime_activation_allowed"] is False
    assert contract["production_promotion_allowed"] is False
    assert contract["response_automation_allowed"] is False
    assert contract["allowed_training_targets"]["binary_soc_review_queue"]["status"] == "diagnostic_training_allowed"
    assert contract["blocked_training_targets"]["flat_5class_exact_label"]["status"] == "blocked"
    assert contract["quality_warnings"]
    assert contract["checks_passed"] == contract["checks_total"]


def test_v362_runner_writes_ignored_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v362_supervised_training_target_contract(
            db,
            output_dir=tmp_path,
            test_size=0.3,
            min_samples=6,
        )
        after_labels = db.scalar(select(func.count(MLLabel.id)))
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["phase"] == "v3.62"
    assert result["contract"]["recommended_training_target"] == "binary_soc_review_queue"
    assert result["contract"]["exact_label_policy"] == "explanation_or_ranking_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["raw_logs_included"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()
    assert "raw_line" not in Path(result["latest_summary_path"]).read_text(encoding="utf-8")
