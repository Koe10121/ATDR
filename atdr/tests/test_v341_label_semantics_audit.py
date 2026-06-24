from pathlib import Path

import pandas as pd
from sqlalchemy import func, select

from atdr.app.db.models import MLLabel, MLModelRun, ResponseAction
from atdr.app.detection.v341_label_semantics_audit import classify_semantic_issue, run_v341_label_semantics_audit
from atdr.tests.test_v331_noise_reduction import _seed_labels, _session


def _row(values: dict):
    return pd.Series(values)


def test_v341_classifies_low_signal_threat_label_as_semantic_issue():
    issue = classify_semantic_issue(
        "suspicious",
        _row(
            {
                "v337_rule_backed_allow_flag": 0,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_web_low_signal_flag": 1,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 0.4,
                "v337_benign_web_likelihood_score": 3.0,
                "v337_traffic_family": "web_low_signal",
            }
        ),
    )

    assert issue["issue"] == "threat_label_on_low_signal_traffic"
    assert issue["severity"] >= 3
    assert issue["recommendation"] == "recheck_as_needs_context_or_benign_unusual"


def test_v341_classifies_evidence_backed_benign_like_label_as_semantic_issue():
    issue = classify_semantic_issue(
        "benign",
        _row(
            {
                "v337_rule_backed_allow_flag": 1,
                "v337_anomaly_signal_flag": 0,
                "v337_web_scan_context_flag": 0,
                "v337_incomplete_scan_context_flag": 0,
                "v337_unknown_scan_context_flag": 0,
                "v337_web_low_signal_flag": 0,
                "v337_utility_low_signal_flag": 0,
                "v337_behavior_evidence_strength": 4.0,
                "v337_benign_web_likelihood_score": -1.0,
                "v337_traffic_family": "web_rule_backed",
            }
        ),
    )

    assert issue["issue"] == "benign_like_label_with_threat_evidence"
    assert issue["severity"] >= 3
    assert issue["recommendation"] == "recheck_as_suspicious_or_needs_context"


def test_v341_label_semantics_audit_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=8)
        before_labels = db.scalar(select(func.count(MLLabel.id)))
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v341_label_semantics_audit(
            db,
            test_size=0.3,
            min_samples=6,
            sample_limit=10,
            output_dir=tmp_path,
        )
        after_labels = db.scalar(select(func.count(MLLabel.id)))
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert result["safety"]["labels_written"] is False
    assert before_labels == after_labels == result["safety"]["ml_labels_after"]
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert result["sample"]["import_ready"] is False
    assert Path(result["report_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.41 Supervised Label Semantics Audit" in report_text
    assert "No labels were written" in report_text
