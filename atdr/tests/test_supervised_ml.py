import csv
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from io import BytesIO, StringIO
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AlertEvidence, MLLabel, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import attack_mapping_for_type
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.detection import supervised_detector
from atdr.app.detection import supervised_workflow
from atdr.app.detection.boundary_analysis import build_boundary_analysis, write_boundary_report
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.detection.model_comparison import compare_supervised_models
from atdr.app.detection.suspicious_recall_analysis import (
    build_suspicious_recall_error_report,
    write_suspicious_recall_error_report,
)
from atdr.app.detection.threshold_tuning import tune_model_thresholds
from atdr.app.detection.supervised_recovery import (
    build_benign_class_debug_report,
    build_current_supervised_dataset_audit,
    build_evaluation_split_diagnostics,
    build_supervised_label_target_plan,
    evaluate_weak_label_impact,
    export_supervised_recovery_review_sample,
    rebuild_clean_registered_baseline,
    render_evaluation_split_diagnostics,
    run_binary_threat_positive_experiment,
    run_benign_recovery_experiment,
    run_stage1_threshold_tuning,
    run_two_stage_recovery_experiment,
    write_benign_class_debug_report,
    write_evaluation_split_diagnostics,
    write_soc_triage_final_recommendation,
    write_soc_triage_model_strategy_report,
    write_supervised_label_target_plan,
)
from atdr.app.detection.supervised_workflow import (
    activate_supervised_model,
    analyze_supervised_errors,
    evaluate_active_supervised_model,
    export_supervised_dataset_snapshot,
    generate_supervised_sanity_report,
    list_supervised_models,
    rollback_supervised_model,
    run_supervised_experiment,
    tune_supervised_model_candidates,
)
from atdr.app.detection.cost_sensitive import cost_sensitive_report
from atdr.app.services.active_learning_service import (
    build_active_learning_review_sample,
    export_active_learning_review_sample_csv,
    export_balanced_recovery_review_sample_csv,
    export_benign_needs_context_final_gap_sample_csv,
    export_final_small_label_gap_sample_csv,
    export_large_pool_active_learning_sample_csv,
    export_stage1_threat_recall_review_sample_csv,
    export_suspicious_recall_review_sample_csv,
    export_training_window_threat_review_sample_csv,
    write_balanced_recovery_review_sample,
    write_benign_needs_context_final_gap_sample,
    write_final_small_label_gap_sample,
    write_large_pool_active_learning_sample,
    write_stage1_threat_recall_review_sample,
    write_suspicious_recall_review_sample,
    write_training_window_threat_review_sample,
    write_active_learning_review_sample,
)
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage, write_class_temporal_coverage_report
from atdr.app.services.label_quality_service import build_label_quality_issues, export_label_quality_issues_csv
from atdr.app.main import app
from atdr.app.ml.features import build_log_features
from atdr.app.ml.benchmark_adapter import BenchmarkDatasetSpec, benchmark_dataset_report
from atdr.app.services.assisted_label_service import export_label_review_sample, generate_assisted_labels
from atdr.app.services.ml_label_service import build_label_review_queue, export_review_queue_csv, import_ml_labels_csv
from atdr.app.services.ml_service import baseline_drift_report
from atdr.app.services.log_service import import_raw_log_line
from atdr.app.services.user_service import create_user
from atdr.scripts import seed_demo_labels
from atdr.tests.test_parser import TRAFFIC_LINE


def _test_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _client_with_log() -> tuple[TestClient, int]:
    TestingSession = _test_session()
    with TestingSession() as db:
        create_user(db, username="admin", password="admin123", role="admin")
        result = import_raw_log_line(db, TRAFFIC_LINE, source_name="unit-test", actor="test")
        log_id = int(result["normalized_log_id"])

    def override_get_db() -> Generator[Session, None, None]:
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), log_id


def _login(client: TestClient) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _add_log(
    db: Session,
    index: int,
    *,
    src_ip: str = "10.0.0.10",
    action: str = "allow",
    app: str = "ssl",
    app_risk: int = 2,
    label: str | None = None,
) -> NormalizedLog:
    generated = datetime(2026, 5, 20, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=index * 20)
    raw = RawLog(raw_line=f"sample log {index}", syslog_timestamp=generated, device_hostname="mfu-fw")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=generated,
        log_type="TRAFFIC",
        subtype="end",
        src_ip=src_ip,
        dst_ip=f"203.0.113.{index % 4}",
        app=app,
        src_zone="inside",
        dst_zone="outside",
        src_port=40000 + index,
        dst_port=443 + index,
        protocol="tcp",
        action=action,
        bytes=1000 + index,
        packets=10 + index,
        app_risk=app_risk,
        is_anomaly=action in {"deny", "drop"},
        anomaly_score=-0.2 if action in {"deny", "drop"} else 0.05,
        parsed_json={},
    )
    db.add(log)
    db.flush()
    if label:
        db.add(
            MLLabel(
                log_id=log.id,
                label=label,
                attack_type="normal" if label.startswith("benign") else "port_scan",
                confidence=4,
                reviewer="tester",
                review_note="unit test label",
            )
        )
    return log


def test_ml_label_api_create_update_list_and_export():
    client, log_id = _client_with_log()
    try:
        headers = _login(client)
        created = client.post(
            "/api/ml/labels",
            json={"log_id": log_id, "label": "suspicious", "attack_type": "port_scan", "confidence": 4, "review_note": "reviewed"},
            headers=headers,
        )
        assert created.status_code == 200
        label_id = created.json()["id"]
        assert created.json()["reviewer"] == "admin"

        updated = client.put(
            f"/api/ml/labels/{label_id}",
            json={"label": "malicious", "attack_type": "malware_c2", "confidence": 5},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["label"] == "malicious"

        labels = client.get("/api/ml/labels?label=malicious", headers=headers)
        assert labels.status_code == 200
        assert labels.json()[0]["id"] == label_id

        exported = client.get("/api/ml/labels/export", headers=headers)
        assert exported.status_code == 200
        assert "malicious" in exported.text
        assert "malware_c2" in exported.text
    finally:
        app.dependency_overrides.clear()


def test_ml_label_csv_template_import_and_review_queue_api():
    client, log_id = _client_with_log()
    try:
        headers = _login(client)
        template = client.get("/api/ml/labels/template", headers=headers)
        assert template.status_code == 200
        assert "log_id,label,attack_type,confidence,review_note" in template.text
        assert "attack_type" in Path("atdr/data/samples/ml_label_template.csv").read_text(encoding="utf-8")

        csv_body = f"log_id,label,attack_type,confidence,review_note\n{log_id},suspicious,port_scan,4,CSV review\n"
        imported = client.post(
            "/api/ml/labels/import",
            files={"upload": ("labels.csv", BytesIO(csv_body.encode()), "text/csv")},
            headers=headers,
        )
        assert imported.status_code == 200
        assert imported.json()["created"] == 1

        csv_update = f"log_id,label,attack_type,confidence,review_note\n{log_id},malicious,malware_c2,5,Updated CSV review\n"
        updated = client.post(
            "/api/ml/labels/import",
            files={"upload": ("labels.csv", BytesIO(csv_update.encode()), "text/csv")},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["skipped"] == 1
        assert updated.json()["protected_manual"] == 1

        updated_with_override = client.post(
            "/api/ml/labels/import?overwrite_manual=true",
            files={"upload": ("labels.csv", BytesIO(csv_update.encode()), "text/csv")},
            headers=headers,
        )
        assert updated_with_override.status_code == 200
        assert updated_with_override.json()["updated"] == 1

        labels = client.get(f"/api/ml/labels?log_id={log_id}", headers=headers)
        assert labels.status_code == 200
        assert labels.json()[0]["label"] == "malicious"

        queue = client.get("/api/ml/review-queue?include_labeled=true", headers=headers)
        assert queue.status_code == 200
        exported_queue = client.get("/api/ml/review-queue/export?include_labeled=true", headers=headers)
        assert exported_queue.status_code == 200
        assert "priority_reasons" in exported_queue.text
        active_sample = client.get("/api/ml/active-learning/review-sample/export?limit=5", headers=headers)
        assert active_sample.status_code == 200
        assert "reason_selected_for_review" in active_sample.text
        focused_sample = client.get("/api/ml/active-learning/review-sample/export?limit=5&focus=malicious,suspicious", headers=headers)
        assert focused_sample.status_code == 200
        assert "time_window" in focused_sample.text
        quality_sample = client.get("/api/ml/labels/quality-issues/export?limit=5", headers=headers)
        assert quality_sample.status_code == 200
        assert "human_review_decision" in quality_sample.text
        coverage = client.get("/api/ml/class-temporal-coverage", headers=headers)
        assert coverage.status_code == 200
        assert "class_coverage" in coverage.json()
        coverage_export = client.get("/api/ml/class-temporal-coverage/export", headers=headers)
        assert coverage_export.status_code == 200
        assert "Class Temporal Coverage" in coverage_export.text
    finally:
        app.dependency_overrides.clear()


def test_review_queue_prioritizes_unlabeled_anomaly_and_exports_csv():
    Session = _test_session()
    with Session() as db:
        suspicious = _add_log(db, 1, action="deny", app="unknown-tcp", app_risk=5)
        _add_log(db, 2, action="allow", app="ssl", app_risk=2, label="benign")
        db.commit()

        queue = build_label_review_queue(db, limit=10)
        csv_text = export_review_queue_csv(queue)

    assert queue[0]["log_id"] == suspicious.id
    assert queue[0]["priority_score"] >= 50
    assert "unlabeled" in queue[0]["priority_reasons"]
    assert "unknown-tcp" in csv_text
    assert "log_id,generated_time" in csv_text
    assert ",label,attack_type,confidence,review_note" in csv_text


def test_csv_import_service_reports_row_errors():
    Session = _test_session()
    with Session() as db:
        _add_log(db, 1)
        db.commit()
        result = import_ml_labels_csv(
            db,
            "log_id,label,attack_type,confidence,review_note\n1,not_a_label,normal,3,bad\n999,benign,normal,3,missing\n",
            reviewer="tester",
        )

    assert result["created"] == 0
    assert result["failed"] == 2
    assert result["errors"]
    assert result["error_summary"]["invalid_label"] == 1
    assert result["error_summary"]["log_missing"] == 1


def test_reviewed_csv_import_preserves_assisted_provenance_and_protects_manual_labels():
    Session = _test_session()
    with Session() as db:
        assisted_log = _add_log(db, 1, action="deny", app="unknown-tcp", app_risk=5)
        manual_log = _add_log(db, 2, action="allow", app="ssl", app_risk=2)
        unreviewed_sample_log = _add_log(db, 3, action="drop", app="unknown-tcp", app_risk=5)
        assisted = MLLabel(
            log_id=assisted_log.id,
            label="suspicious",
            attack_type="policy_violation",
            confidence=4,
            reviewer="codex_assisted",
            review_note="Assisted label: suspicious. Weak label.",
            label_source="assisted_rule",
            reviewed=False,
        )
        manual = MLLabel(
            log_id=manual_log.id,
            label="benign",
            attack_type="normal",
            confidence=5,
            reviewer="analyst",
            review_note="Manual analyst decision.",
            label_source="manual",
            reviewed=True,
        )
        unchanged_sample = MLLabel(
            log_id=unreviewed_sample_log.id,
            label="suspicious",
            attack_type="policy_violation",
            confidence=3,
            reviewer="codex_assisted",
            review_note="Assisted label: suspicious. Weak label.",
            label_source="assisted_rule",
            reviewed=False,
        )
        db.add_all([assisted, manual, unchanged_sample])
        db.commit()

        csv_body = (
            "label_id,log_id,label,attack_type,confidence,label_source,reviewed,human_review_decision,human_review_note\n"
            f"{assisted.id},{assisted_log.id},suspicious,malware_c2,5,assisted_rule,false,malicious,Confirmed by sample review\n"
            f"{manual.id},{manual_log.id},benign,policy_violation,4,manual,true,suspicious,Attempt to overwrite manual label\n"
            f"{unchanged_sample.id},{unreviewed_sample_log.id},suspicious,policy_violation,3,assisted_rule,false,,\n"
        )
        result = import_ml_labels_csv(db, csv_body, reviewer="admin")
        db.refresh(assisted)
        db.refresh(manual)
        db.refresh(unchanged_sample)

    assert result["updated"] == 1
    assert result["skipped"] == 2
    assert result["protected_manual"] == 1
    assert assisted.label == "malicious"
    assert assisted.attack_type == "malware_c2"
    assert assisted.reviewed is True
    assert assisted.label_source == "assisted_rule"
    assert assisted.reviewer == "codex_assisted"
    assert "Human review by admin: Confirmed by sample review" in (assisted.review_note or "")
    assert manual.label == "benign"
    assert manual.reviewer == "analyst"
    assert unchanged_sample.reviewed is False


def test_active_learning_csv_import_skips_blank_rows_and_accepts_reviewed_decisions():
    Session = _test_session()
    with Session() as db:
        reviewed_log = _add_log(db, 1, action="deny", app="unknown-tcp", app_risk=5)
        blank_log = _add_log(db, 2, action="allow", app="ssl", app_risk=2)
        reviewed_label = MLLabel(
            log_id=reviewed_log.id,
            label="suspicious",
            attack_type="unknown_anomaly",
            confidence=3,
            reviewer="codex_assisted",
            review_note="Assisted label.",
            label_source="assisted_rule",
            reviewed=False,
        )
        blank_label = MLLabel(
            log_id=blank_log.id,
            label="benign",
            attack_type="normal",
            confidence=3,
            reviewer="codex_assisted",
            review_note="Assisted label.",
            label_source="assisted_rule",
            reviewed=False,
        )
        db.add_all([reviewed_label, blank_label])
        db.commit()

        csv_body = (
            "label_id,log_id,current_label,current_attack_type,label_source,reviewed,model_prediction,confidence,human_review_decision,human_review_note\n"
            f"{reviewed_label.id}.0,{reviewed_log.id},suspicious,policy_violation,assisted_rule,false,malicious,0.9533,malicious,Confirmed malicious pattern\n"
            f"{blank_label.id},{blank_log.id},benign,normal,assisted_rule,false,benign,0.9911,,\n"
        )
        result = import_ml_labels_csv(db, csv_body, reviewer="admin")
        db.refresh(reviewed_label)
        db.refresh(blank_label)

    assert result["updated"] == 1
    assert result["skipped"] == 1
    assert result["failed"] == 0
    assert reviewed_label.label == "malicious"
    assert reviewed_label.attack_type == "policy_violation"
    assert reviewed_label.confidence == 3
    assert reviewed_label.reviewed is True
    assert blank_label.reviewed is False


def test_reviewed_csv_import_accepts_spreadsheet_integer_label_ids():
    Session = _test_session()
    with Session() as db:
        log = _add_log(db, 1, action="deny", app="unknown-tcp", app_risk=5)
        label = MLLabel(
            log_id=log.id,
            label="suspicious",
            attack_type="unknown_anomaly",
            confidence=3,
            reviewer="codex_assisted",
            review_note="Assisted label.",
            label_source="assisted_rule",
            reviewed=False,
        )
        db.add(label)
        db.commit()

        csv_body = (
            "label_id,log_id,human_review_decision,human_review_attack_type,human_review_confidence,human_review_note\n"
            f"{label.id}.0,{log.id},malicious,port_scan,4,spreadsheet kept id as float\n"
        )
        result = import_ml_labels_csv(db, csv_body, reviewer="reviewer")
        db.refresh(label)

    assert result["failed"] == 0
    assert result["updated"] == 1
    assert label.label == "malicious"
    assert label.reviewed is True


def test_label_import_protects_reviewed_assisted_labels_without_correction_mode():
    Session = _test_session()
    with Session() as db:
        log = _add_log(db, 1, label="suspicious")
        db.flush()
        label = db.scalar(select(MLLabel).where(MLLabel.log_id == log.id))
        assert label is not None
        label.label_source = "assisted_rule"
        label.reviewed = True
        db.commit()

        csv_body = (
            "label_id,log_id,human_review_decision,human_review_attack_type,human_review_confidence,human_review_note\n"
            f"{label.id},{log.id},malicious,port_scan,4,corrected after boundary review\n"
        )
        protected = import_ml_labels_csv(db, csv_body, reviewer="reviewer")
        db.refresh(label)
        assert label.label == "suspicious"

        corrected = import_ml_labels_csv(db, csv_body, reviewer="reviewer", correction_mode=True)
        db.refresh(label)

    assert protected["protected_reviewed"] == 1
    assert protected["updated"] == 0
    assert corrected["updated"] == 1
    assert corrected["changed_decisions"] == 1
    assert label.label == "malicious"


def test_assisted_label_generation_dry_run_apply_and_review_sample():
    Session = _test_session()
    with Session() as db:
        _add_log(db, 1, action="allow", app="ssl", app_risk=2)
        _add_log(db, 2, action="deny", app="unknown-tcp", app_risk=5)
        _add_log(db, 3, action="drop", app="unknown-tcp", app_risk=5)
        db.commit()

        dry_run = generate_assisted_labels(db, limit=10, apply=False, min_confidence=1)
        applied = generate_assisted_labels(db, limit=10, apply=True, reviewer="codex_assisted", min_confidence=3)
        sample_csv = export_label_review_sample(db)
        labels = list(db.scalars(select(MLLabel)))

    assert dry_run["mode"] == "dry_run"
    assert dry_run["candidate_count"] == 3
    assert "csv" in dry_run
    assert applied["created"] >= 2
    assert labels
    assert all(label.label_source.startswith("assisted") for label in labels)
    assert all(label.reviewed is False for label in labels)
    assert "Weak label" in labels[0].review_note
    assert "human_review_decision" in sample_csv


def test_feature_generation_adds_five_minute_context():
    Session = _test_session()
    with Session() as db:
        _add_log(db, 1, action="allow")
        _add_log(db, 2, action="deny", app="unknown-tcp", app_risk=5)
        current = _add_log(db, 3, action="allow")
        db.commit()

        features = build_log_features(db, current)

    assert features["src_ip_5min_log_count"] == 3
    assert features["src_ip_5min_deny_count"] == 1
    assert features["src_ip_5min_unique_dst_ports"] == 3
    assert features["src_ip_5min_unknown_app_count"] == 1
    assert features["src_ip_5min_high_risk_app_count"] == 1
    assert features["deny_rate_5min"] > 0
    assert features["hour_of_day"] == 8
    assert features["is_after_hours"] == 0


def test_behavior_window_features_handle_missing_fields():
    Session = _test_session()
    with Session() as db:
        raw = RawLog(raw_line="missing fields", syslog_timestamp=None, device_hostname="mfu-fw")
        db.add(raw)
        db.flush()
        log = NormalizedLog(raw_log_id=raw.id, parsed_json={})
        db.add(log)
        db.commit()

        features = build_log_features(db, log)

    assert features["src_ip_15min_event_count"] >= 1
    assert features["dst_ip_1h_event_count"] == 0
    assert features["unknown_app_flag"] in {0, 1}
    assert features["scanning_like_behavior_score"] >= 0


def test_attack_mapping_and_alert_explanation_summary():
    Session = _test_session()
    with Session() as db:
        log = _add_log(db, 1, action="deny", app="unknown-tcp", app_risk=5)
        alert = Alert(
            title="High: Possible scan",
            alert_type="possible_port_scan",
            src_ip=log.src_ip,
            dst_ip=log.dst_ip,
            threat_score=75,
            severity="High",
            explanation="Possible scanning behavior.",
            matched_rules_json=[
                {
                    "code": "possible_port_scan",
                    "title": "Possible port scanning behavior",
                    "score": 25,
                    "explanation": "Source touched many destination ports.",
                }
            ],
            recommended_response="Investigate source.",
        )
        alert.evidence.append(AlertEvidence(normalized_log_id=log.id))
        db.add(alert)
        db.commit()
        db.refresh(alert)

        mapping = attack_mapping_for_type("port_scan")
        summary = build_alert_detection_summary(db, alert)

    assert mapping["technique_id"] == "T1046"
    assert summary["attack_mapping"]["technique_id"] == "T1046"
    assert "Flagged by deterministic rule evidence" in summary["why_flagged"]
    assert summary["alert_authority"]["layer"] == "deterministic_rules"
    assert summary["alert_authority"]["authoritative_rule_count"] == 1
    assert summary["anomaly_evidence"]["evidence_role"] == "advisory_only"
    assert "Source touched" in " ".join(summary["top_evidence_points"])


def test_model_comparison_report_runs_on_small_data(tmp_path):
    Session = _test_session()
    report_path = tmp_path / "model_comparison_report.md"
    with Session() as db:
        for index in range(1, 7):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(7, 13):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app_risk=5, label="suspicious")
        db.commit()

        result = compare_supervised_models(db, output_path=report_path, test_size=0.25, min_samples=6)

    assert result["ok"] is True
    assert result["best_model"]
    assert len(result["models"]) >= 4
    assert result["promotion_gate"]["decision"] == "candidate_only"
    assert result["promotion_gate"]["response_automation_allowed"] is False
    assert report_path.exists()
    assert "Promotion Gate" in report_path.read_text(encoding="utf-8")
    assert "Dataset type" in report_path.read_text(encoding="utf-8")


def test_active_learning_review_sample_export_prioritizes_disagreement(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 7):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(7, 13):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        ambiguous = _add_log(db, 13, src_ip="198.51.100.99", action="drop", app="unknown-tcp", app_risk=5)
        db.add(
            MLLabel(
                log_id=ambiguous.id,
                label="needs_context",
                attack_type="unknown_anomaly",
                confidence=2,
                reviewer="tester",
                review_note="needs review",
                label_source="manual",
                reviewed=True,
            )
        )
        db.commit()

        supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.25, min_samples=6)
        rows = build_active_learning_review_sample(db, limit=5)
        csv_text = export_active_learning_review_sample_csv(db, limit=5)

    assert rows
    assert "reason_selected_for_review" in csv_text
    assert "human_review_decision" in csv_text
    assert any("needs_context" in row["reason_selected_for_review"] or "disagrees" in row["reason_selected_for_review"] for row in rows)


def test_threshold_tuning_and_cost_sensitive_report_runs(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    report_path = tmp_path / "thresholds.md"
    with Session() as db:
        for index in range(1, 9):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(9, 17):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(17, 23):
            _add_log(db, index, src_ip="198.51.100.8", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        context_log = _add_log(db, 23, src_ip="198.51.100.9", action="allow", app="incomplete", app_risk=4)
        db.add(
            MLLabel(
                log_id=context_log.id,
                label="needs_context",
                attack_type="unknown_anomaly",
                confidence=2,
                reviewer="tester",
                review_note="uncertain",
                reviewed=True,
            )
        )
        db.commit()

        result = tune_model_thresholds(db, split="time", test_size=0.3, min_samples=6, output_path=report_path)

    assert result["ok"] is True
    assert {"conservative", "balanced", "aggressive", "suspicious_recall", "malicious_recall", "threat_positive"}.issubset(
        {mode["mode"] for mode in result["modes"]}
    )
    assert "cost_sensitive" in result["modes"][0]["metrics"]
    assert "threat_positive" in result["modes"][0]["metrics"]
    assert report_path.exists()
    cost = cost_sensitive_report(["malicious", "benign"], ["benign", "malicious"])
    assert cost["threat_false_negatives"] == 1
    assert cost["total_cost"] >= 10


def test_promotion_gate_distinguishes_analyst_review_from_production_promotion():
    gate = supervised_detector._promotion_gate_for_training(
        label_distribution={"benign": 400, "benign_unusual": 200, "suspicious": 180, "malicious": 90},
        reviewed_distribution={"benign": 100, "benign_unusual": 100, "suspicious": 90, "malicious": 60},
        weak_distribution={"benign": 300, "benign_unusual": 100, "suspicious": 90, "malicious": 30},
        reviewed_count=350,
        temporal_coverage={"malicious_train_count": 31},
        split="time",
        metrics={
            "macro_average": {"f1": 0.72},
            "threat_positive": {"f1": 0.91},
            "per_class": {
                "suspicious": {"recall": 0.72},
                "malicious": {"recall": 0.55},
            },
        },
    )

    assert gate["decision"] == "eligible_for_analyst_review"
    assert gate["analyst_review_eligible"] is True
    assert gate["production_promoted"] is False
    assert gate["eligible_for_promotion"] is False
    assert gate["response_automation_allowed"] is False
    assert any("Suspicious recall remains below" in warning for warning in gate["warnings"])


def test_label_quality_issue_export_detects_inconsistent_and_risky_labels():
    Session = _test_session()
    with Session() as db:
        risky_benign = _add_log(db, 1, src_ip="203.0.113.5", action="deny", app="unknown-tcp", app_risk=5)
        risky_benign.ml_labels.append(
            MLLabel(
                label="benign",
                attack_type="normal",
                confidence=3,
                reviewer="tester",
                review_note="questionable",
                reviewed=True,
            )
        )
        low_evidence_malicious = _add_log(db, 2, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=1)
        low_evidence_malicious.ml_labels.append(
            MLLabel(
                label="malicious",
                attack_type="malware_c2",
                confidence=3,
                reviewer="tester",
                review_note="questionable",
                reviewed=True,
            )
        )
        db.commit()

        issues = build_label_quality_issues(db)
        csv_text = export_label_quality_issues_csv(db)

    assert issues
    assert "benign_despite_high_risk_evidence" in csv_text
    assert "malicious_without_strong_evidence" in csv_text
    assert "human_review_decision" in csv_text
    assert "current_attack_type" in csv_text
    assert "suggested_review_focus" in csv_text


def test_label_quality_csv_can_be_reimported_after_human_review():
    Session = _test_session()
    with Session() as db:
        risky_benign = _add_log(db, 1, src_ip="203.0.113.5", action="deny", app="unknown-tcp", app_risk=5)
        label = MLLabel(
            log_id=risky_benign.id,
            label="benign",
            attack_type="normal",
            confidence=3,
            reviewer="codex_assisted",
            review_note="weak label",
            label_source="assisted_rule",
            reviewed=False,
        )
        db.add(label)
        db.commit()

        csv_text = export_label_quality_issues_csv(db)
        reader = csv.DictReader(StringIO(csv_text))
        rows = list(reader)
        assert rows
        rows[0]["human_review_decision"] = "suspicious"
        rows[0]["human_review_attack_type"] = "policy_violation"
        rows[0]["human_review_confidence"] = "4"
        rows[0]["human_review_note"] = "Corrected from quality issue review"
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=reader.fieldnames or [])
        writer.writeheader()
        writer.writerows(rows)
        reviewed_csv = output.getvalue()
        result = import_ml_labels_csv(db, reviewed_csv, reviewer="admin")
        db.refresh(label)

    assert result["updated"] >= 1
    assert label.label == "suspicious"
    assert label.attack_type == "policy_violation"
    assert label.reviewed is True


def test_class_temporal_coverage_report_flags_missing_training_class(tmp_path):
    Session = _test_session()
    report_path = tmp_path / "coverage.md"
    with Session() as db:
        for index in range(1, 9):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(9, 13):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(13, 17):
            _add_log(db, index, src_ip="198.51.100.8", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        report = build_class_temporal_coverage(db, test_size=0.3)
        written = write_class_temporal_coverage_report(db, output_path=report_path, test_size=0.3)

    assert report["malicious_test_count"] > 0
    assert report["malicious_train_count"] == 0
    assert any("malicious exists in the test window" in warning for warning in report["warnings"])
    assert written["status"] == "exported"
    assert "Class Temporal Coverage" in report_path.read_text(encoding="utf-8")


def test_malicious_focused_active_learning_marks_training_window_candidates(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 12):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        early_risky = _add_log(db, 12, src_ip="198.51.100.70", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(13, 23):
            _add_log(db, index, src_ip="198.51.100.8", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.3, min_samples=6, split="time")
        rows = build_active_learning_review_sample(db, limit=10, focus="malicious,suspicious,needs_context")
        csv_text = export_active_learning_review_sample_csv(db, limit=10, focus="malicious,suspicious,needs_context")

    assert rows
    assert "time_window" in csv_text
    assert "training_window" in csv_text
    assert any(row["log_id"] == early_risky.id or "training-window" in row["reason_selected_for_review"] for row in rows)


def test_round4_boundary_active_learning_export_prioritizes_boundary_cases(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    output_path = tmp_path / "round4.csv"
    round5_path = tmp_path / "round5.csv"
    with Session() as db:
        for index in range(1, 10):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=2, label="benign")
        for index in range(10, 18):
            _add_log(db, index, src_ip="198.51.100.10", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(18, 27):
            _add_log(db, index, src_ip="198.51.100.11", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.3, min_samples=6, split="time")
        rows = build_active_learning_review_sample(
            db,
            limit=12,
            focus="malicious,suspicious,needs_context",
            strategy="boundary",
        )
        result = write_active_learning_review_sample(
            db,
            limit=12,
            output_path=output_path,
            focus="malicious,suspicious,needs_context",
            strategy="boundary",
        )
        round5 = write_active_learning_review_sample(
            db,
            limit=12,
            output_path=round5_path,
            focus="malicious,suspicious,needs_context",
            strategy="threat_boundary",
        )

    assert result["status"] == "exported"
    assert result["strategy"] == "boundary"
    assert round5["status"] == "exported"
    assert round5["strategy"] == "threat_boundary"
    assert output_path.exists()
    assert round5_path.exists()
    assert rows
    assert any(
        "boundary" in row["reason_selected_for_review"] or "training-window" in row["reason_selected_for_review"]
        for row in rows
    )
    assert "human_review_decision" in output_path.read_text(encoding="utf-8")
    assert "human_review_decision" in round5_path.read_text(encoding="utf-8")


def test_training_window_threat_review_sample_and_boundary_report_run(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    sample_path = tmp_path / "training-window.csv"
    boundary_path = tmp_path / "boundary.md"
    with Session() as db:
        for index in range(1, 10):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=2, label="benign")
        for index in range(10, 18):
            _add_log(db, index, src_ip="198.51.100.10", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(18, 27):
            _add_log(db, index, src_ip="198.51.100.11", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.3, min_samples=6, split="time")
        csv_text = export_training_window_threat_review_sample_csv(db, limit=10)
        exported = write_training_window_threat_review_sample(db, limit=10, output_path=sample_path)
        diagnostics = supervised_detector.training_dataset_diagnostics(db)
        boundary = build_boundary_analysis(db, test_size=0.3, min_samples=6)
        written = write_boundary_report(db, output_path=boundary_path, test_size=0.3, min_samples=6)

    assert exported["status"] == "exported"
    assert sample_path.exists()
    assert "split_window" in csv_text
    assert "human_review_decision" in csv_text
    assert diagnostics["excluded_from_training"] >= 0
    assert boundary["ok"] is True
    assert "hierarchical_candidate" in boundary
    assert written["report_path"] == str(boundary_path)
    assert "Suspicious / Malicious Boundary Report" in boundary_path.read_text(encoding="utf-8")


def test_suspicious_recall_report_and_review_export_run(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    report_path = tmp_path / "suspicious-recall.md"
    sample_path = tmp_path / "suspicious-recall.csv"
    with Session() as db:
        for index in range(1, 46):
            if index % 3 == 0:
                _add_log(db, index, src_ip="198.51.100.30", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
            elif index % 3 == 1:
                log = _add_log(db, index, src_ip="198.51.100.20", action="allow", app="incomplete", app_risk=4, label="suspicious")
                log.dst_port = 995
            else:
                _add_log(db, index, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=2, label="benign")
        for label in db.scalars(select(MLLabel)).all():
            if label.label == "suspicious" and label.id % 2 == 0:
                label.reviewed = False
                label.label_source = "assisted_hybrid"
        db.commit()

        supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.3, min_samples=6, split="time")
        report = build_suspicious_recall_error_report(db, test_size=0.3, min_samples=6)
        written = write_suspicious_recall_error_report(db, output_path=report_path, test_size=0.3, min_samples=6)
        csv_text = export_suspicious_recall_review_sample_csv(db, limit=20)
        exported = write_suspicious_recall_review_sample(db, limit=20, output_path=sample_path)

    assert report["ok"] is True
    assert "threshold_profiles" in report
    assert any(profile["profile"] == "suspicious_recall" for profile in report["threshold_profiles"])
    assert written["report_path"] == str(report_path)
    assert "Suspicious Recall Error Report" in report_path.read_text(encoding="utf-8")
    assert "threat_positive_score" in csv_text
    assert "human_review_decision" in csv_text
    assert exported["rows"] > 0


def test_baseline_drift_report_handles_missing_fields():
    Session = _test_session()
    with Session() as db:
        _add_log(db, 1, action="allow", app="ssl", app_risk=2)
        raw = RawLog(raw_line="missing app/action", syslog_timestamp=None, device_hostname="mfu-fw")
        db.add(raw)
        db.flush()
        db.add(NormalizedLog(raw_log_id=raw.id, src_ip="10.0.0.99", dst_port=3389, parsed_json={}))
        db.commit()

        report = baseline_drift_report(db)

    assert report["total_logs"] == 2
    assert "app_distribution" in report
    assert "action_distribution" in report
    assert report["unknown_app_rate"] >= 0


def test_benchmark_adapter_does_not_mix_with_real_labels():
    csv_body = (
        "src_port,dst_port,bytes,packets,app_risk,protocol,action,app,label,attack_type\n"
        "12345,443,5000,10,2,tcp,allow,ssl,normal,normal\n"
        "23456,22,1000,8,5,tcp,deny,ssh,port_scan,port_scan\n"
        "34567,4444,9000,20,5,tcp,deny,unknown,malicious,malware\n"
    )
    report = benchmark_dataset_report(csv_body, BenchmarkDatasetSpec(dataset_name="unit-benchmark", source_type="public_csv"))

    assert report["dataset_name"] == "unit-benchmark"
    assert report["writes_to_real_labels"] is False
    assert report["label_distribution"]["benign"] == 1
    assert report["label_distribution"]["malicious"] == 1
    assert any("must not be presented as real deployment accuracy" in warning for warning in report["warnings"])


def test_supervised_training_time_split_and_reviewed_label_warnings(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 9):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(9, 17):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app_risk=5, label="suspicious")
        for label in db.scalars(select(MLLabel)).all():
            label.label_source = "assisted_rule"
            label.reviewed = False
        first_label = db.scalar(select(MLLabel).order_by(MLLabel.id))
        assert first_label is not None
        first_label.reviewed = True
        first_label.label_source = "manual"
        db.commit()

        result = supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.25, min_samples=6, split="time")
        report = supervised_detector.supervised_model_report(db)

    assert result["trained"] is True
    assert result["split_strategy"] == "time"
    assert result["sample_weighting"]["enabled"] is True
    assert result["threshold_profile"] == "balanced"
    assert "cost_sensitive" in result["metrics"]
    assert "threat_positive" in result["metrics"]
    assert "direct_model_metrics" in result
    assert "mixed_label_evaluation" in result["evaluation"]
    assert "Reviewed-label sample is too small for reliable model validation." in result["validation_warnings"]
    assert result["promotion_gate"]["response_automation_allowed"] is False
    assert result["model_readiness_checklist"]["status"] == "candidate_only"
    assert result["class_temporal_coverage"]["reviewed_label_target"] == 300
    assert report["reviewed_label_distribution"]
    assert report["weak_label_distribution"]
    assert report["model_readiness_checklist"]["items"]


def test_supervised_dataset_snapshot_and_feature_metadata(tmp_path):
    Session = _test_session()
    with Session() as db:
        for index in range(1, 9):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(9, 17):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        db.commit()

        result = export_supervised_dataset_snapshot(db, output_root=tmp_path, split="time", test_size=0.25)

    assert result["status"] == "exported"
    assert result["contains_raw_payloads"] is False
    assert result["feature_set_metadata"]["feature_set_version"] == "behavior_windows_v3_leakage_safe"
    assert Path(result["features_csv"]).exists()
    assert "raw_line" not in Path(result["features_csv"]).read_text(encoding="utf-8").splitlines()[0]


def test_supervised_experiment_tuning_and_error_analysis_reports(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 10):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=2, label="benign")
        for index in range(10, 18):
            _add_log(db, index, src_ip="198.51.100.10", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(18, 27):
            _add_log(db, index, src_ip="198.51.100.11", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        experiment = run_supervised_experiment(db, output_root=tmp_path / "experiments", split="time", test_size=0.3, min_samples=6)
        tuning = tune_supervised_model_candidates(db, output_root=tmp_path / "tuning", split="time", test_size=0.3, min_samples=6)
        analysis = analyze_supervised_errors(db, output_path=tmp_path / "errors.md", split="time", test_size=0.3, min_samples=6)

    assert experiment["ok"] is True
    assert any(model["name"] == "extra_trees" for model in experiment["models"])
    assert experiment["threshold_profile"] == "balanced"
    assert all("direct_model_metrics" in model for model in experiment["models"] if model["name"] != "hybrid_score_baseline")
    assert experiment["production_promoted"] is False
    assert tuning["status"] == "completed"
    assert tuning["response_automation_allowed"] is False
    assert analysis["status"] == "exported"
    assert "Supervised Error Analysis" in Path(analysis["report_path"]).read_text(encoding="utf-8")


def test_supervised_sanity_report_evaluates_active_and_candidates(tmp_path, monkeypatch):
    active_path = tmp_path / "active-supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=active_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 10):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=2, label="benign")
        for index in range(10, 18):
            _add_log(db, index, src_ip="198.51.100.10", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(18, 27):
            _add_log(db, index, src_ip="198.51.100.11", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        trained = supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.3, min_samples=6, split="time")
        active = evaluate_active_supervised_model(db, split="time", test_size=0.3, min_samples=6)
        sanity = generate_supervised_sanity_report(
            db,
            output_path=tmp_path / "sanity.md",
            split="time",
            test_size=0.3,
            min_samples=6,
        )

    assert trained["trained"] is True
    assert active["ok"] is True
    assert active["threshold_profile"] == "balanced"
    assert sanity["status"] == "exported"
    assert sanity["production_promoted"] is False
    assert sanity["response_automation_allowed"] is False
    assert sanity["experiment"]["promotion_gate"]["production_promoted"] is False
    assert "threshold-decision path" in Path(sanity["report_path"]).read_text(encoding="utf-8")


def test_supervised_recovery_audit_binary_and_review_sample(tmp_path, monkeypatch):
    active_path = tmp_path / "active-supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=active_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 10):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app="ssl", app_risk=2, label="benign")
        for index in range(10, 18):
            _add_log(db, index, src_ip="198.51.100.10", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(18, 27):
            _add_log(db, index, src_ip="198.51.100.11", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        for label in db.scalars(select(MLLabel)).all():
            if label.label == "benign":
                label.reviewed = False
                label.label_source = "assisted_rule"
        db.commit()

        audit = build_current_supervised_dataset_audit(db, output_path=tmp_path / "audit.md", split="time", test_size=0.3)
        weak = evaluate_weak_label_impact(db, split="time", test_size=0.3, min_samples=6)
        binary = run_binary_threat_positive_experiment(db, output_path=tmp_path / "binary.md", split="time", test_size=0.3, min_samples=6)
        two_stage = run_two_stage_recovery_experiment(db, output_path=tmp_path / "two-stage.md", split="time", test_size=0.3, min_samples=6)
        sample = export_supervised_recovery_review_sample(db, output_path=tmp_path / "recovery.csv", limit=8)
        label_plan = write_supervised_label_target_plan(db, output_path=tmp_path / "label-plan.md", split="time", test_size=0.3)
        label_plan_raw = build_supervised_label_target_plan(db, split="time", test_size=0.3)
        large_pool_csv = export_large_pool_active_learning_sample_csv(db, limit=5, candidate_pool_limit=20)
        large_pool = write_large_pool_active_learning_sample(
            db,
            output_path=tmp_path / "large-pool.csv",
            limit=8,
            candidate_pool_limit=30,
        )

    assert audit["status"] == "exported"
    assert audit["train_label_distribution"]
    assert audit["missing_feature_summary"]
    assert weak["status"] == "completed"
    assert "mixed_default" in weak["diagnostics"]
    assert binary["decision"] == "candidate_experimental"
    assert binary["response_automation_allowed"] is False
    assert two_stage["decision"] == "candidate_experimental"
    assert sample["rows"] > 0
    assert label_plan["reviewed_total"] > 0
    assert label_plan_raw["reviewed_total"] == label_plan["reviewed_total"]
    assert label_plan["production_promoted"] is False
    assert large_pool["rows"] > 0
    assert large_pool["response_automation_allowed"] is False
    csv_header = Path(sample["path"]).read_text(encoding="utf-8").splitlines()[0]
    assert "human_review_attack_type" in csv_header
    assert "human_review_decision" in large_pool_csv.splitlines()[0]
    assert "large log pool" in Path(label_plan["report_path"]).read_text(encoding="utf-8").lower()
    assert "human_review_decision" in Path(large_pool["path"]).read_text(encoding="utf-8").splitlines()[0]


def test_balanced_recovery_review_sample_avoids_malicious_heavy_selection(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "atdr.app.services.active_learning_service.predict_supervised_log",
        lambda _db, log_id, rule_score=0: {
            "predicted_label": "suspicious" if rule_score >= 55 else "benign",
            "confidence": 0.72,
            "class_probabilities": {"benign": 0.6, "suspicious": 0.35, "malicious": 0.05},
        },
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 21):
            log = _add_log(db, index, action="allow", app="ssl", app_risk=2, label="benign" if index % 5 == 0 else None)
            log.dst_port = 443
            log.is_anomaly = False
            log.anomaly_score = 0.02
        for index in range(21, 29):
            log = _add_log(db, index, action="allow", app="incomplete", app_risk=3, label="needs_context" if index % 2 == 0 else None)
            log.dst_port = 0
        for index in range(29, 39):
            log = _add_log(db, index, src_ip="198.51.100.9", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
            log.dst_port = 22 if index % 2 == 0 else 995
            log.is_anomaly = True
            log.anomaly_score = -0.35
        for index in range(39, 43):
            log = _add_log(db, index, src_ip="203.0.113.10", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
            log.dst_port = 4444
        db.commit()

        csv_text = export_balanced_recovery_review_sample_csv(db, limit=30)
        written = write_balanced_recovery_review_sample(db, limit=30, output_path=tmp_path / "balanced.csv")

    rows = list(csv.DictReader(StringIO(csv_text)))
    assert written["rows"] > 0
    assert written["bucket_distribution"].get("benign_candidate", 0) > 0
    assert written["production_promoted"] is False
    assert written["response_automation_allowed"] is False
    assert "human_review_decision" in csv_text.splitlines()[0]
    assert {row["current_label"] for row in rows}.isdisjoint({"malicious"})
    assert any("benign gap recovery" in row["reason_selected"] for row in rows)
    assert any("needs_context gap recovery" in row["reason_selected"] for row in rows)


def test_stage1_recovery_review_sample_and_threshold_tuning(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "atdr.app.services.active_learning_service.predict_supervised_log",
        lambda _db, log_id, rule_score=0: {
            "predicted_label": "benign" if log_id % 3 else "suspicious",
            "confidence": 0.61,
            "malicious_probability": 0.28 if log_id % 3 else 0.76,
            "class_probabilities": {"benign": 0.58, "benign_unusual": 0.12, "suspicious": 0.2, "malicious": 0.1},
        },
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 13):
            log = _add_log(db, index, action="allow", app="ssl", app_risk=2, label="benign" if index % 4 == 0 else None)
            log.dst_port = 443
            log.is_anomaly = False
            log.anomaly_score = 0.03
        for index in range(13, 19):
            _add_log(db, index, action="allow", app="incomplete", app_risk=3, label="needs_context")
        for index in range(19, 29):
            log = _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
            log.dst_port = 995
        for index in range(29, 35):
            log = _add_log(db, index, src_ip="198.51.100.8", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
            log.dst_port = 4444
        db.commit()

        csv_text = export_stage1_threat_recall_review_sample_csv(db, limit=40)
        written_sample = write_stage1_threat_recall_review_sample(db, limit=40, output_path=tmp_path / "stage1.csv")
        tuning = run_stage1_threshold_tuning(db, output_path=tmp_path / "stage1-threshold.md", split="time", test_size=0.3, min_samples=6)
        boundary = write_boundary_report(db, output_path=tmp_path / "boundary.md", split="time", test_size=0.3, min_samples=6)

    rows = list(csv.DictReader(StringIO(csv_text)))
    malicious_rows = [row for row in rows if row["current_label"] == "malicious"]
    assert written_sample["rows"] > 0
    assert written_sample["production_promoted"] is False
    assert written_sample["response_automation_allowed"] is False
    assert "threat_positive_score" in csv_text.splitlines()[0]
    assert len(malicious_rows) <= max(5, round(len(rows) * 0.25))
    assert any("Stage 1" in row["reason_selected"] for row in rows)
    assert {item["profile"] for item in tuning["profiles"]} == {
        "conservative",
        "balanced",
        "recall_high",
        "recall_max_review_queue",
    }
    assert tuning["production_promoted"] is False
    assert tuning["response_automation_allowed"] is False
    threshold_text = Path(tuning["report_path"]).read_text(encoding="utf-8")
    assert "Estimated Review Queue" in threshold_text
    boundary_text = Path(boundary["report_path"]).read_text(encoding="utf-8")
    assert "Stage 1 Quality" in boundary_text
    assert "Stage 2 Quality" in boundary_text
    assert "Overall Combined Decision Quality" in boundary_text
    assert boundary["hierarchical_candidate"]["overall_combined_decision_quality"]["decision"] == "candidate_experimental"


def test_benign_recovery_diagnostics_and_final_gap_sample(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "atdr.app.services.active_learning_service.predict_supervised_log",
        lambda _db, log_id, rule_score=0: {
            "predicted_label": "suspicious" if log_id % 4 == 0 else "benign_unusual",
            "confidence": 0.58,
            "class_probabilities": {
                "benign": 0.18 if log_id % 4 == 0 else 0.32,
                "benign_unusual": 0.42,
                "suspicious": 0.38 if log_id % 4 == 0 else 0.12,
                "malicious": 0.04,
                "needs_context": 0.06,
            },
        },
    )
    assert (
        supervised_detector.threshold_decision(
            {"benign": 0.72, "benign_unusual": 0.08, "suspicious": 0.04, "malicious": 0.02, "needs_context": 0.14},
            profile="balanced",
        )
        == "benign"
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 15):
            log = _add_log(db, index, action="allow", app="ssl", app_risk=2, label="benign")
            log.dst_port = 443
        for index in range(15, 25):
            log = _add_log(db, index, action="allow", app="quic-base", app_risk=2, label="benign_unusual")
            log.dst_port = 443
        for index in range(25, 31):
            log = _add_log(db, index, action="allow", app="incomplete", app_risk=3, label="needs_context")
            log.dst_port = 0
        for index in range(31, 43):
            log = _add_log(db, index, action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
            log.dst_port = 995
        for index in range(43, 51):
            log = _add_log(db, index, action="drop", app="unknown-tcp", app_risk=5, label="malicious")
            log.dst_port = 4444
        db.commit()

        debug = write_benign_class_debug_report(db, output_path=tmp_path / "benign-debug.md", split="time", test_size=0.3, min_samples=6)
        raw_debug = build_benign_class_debug_report(db, split="time", test_size=0.3, min_samples=6)
        experiment = run_benign_recovery_experiment(db, output_path=tmp_path / "benign-experiment.md", split="time", test_size=0.3, min_samples=6)
        strategy = write_soc_triage_model_strategy_report(db, output_path=tmp_path / "soc-strategy.md", split="time", test_size=0.3, min_samples=6)
        final_recommendation = write_soc_triage_final_recommendation(
            db,
            output_path=tmp_path / "soc-final.md",
            split="time",
            test_size=0.3,
            min_samples=6,
        )
        csv_text = export_benign_needs_context_final_gap_sample_csv(db, limit=40)
        sample = write_benign_needs_context_final_gap_sample(db, limit=40, output_path=tmp_path / "benign-gap.csv")
        final_csv_text = export_final_small_label_gap_sample_csv(db, limit=24)
        final_sample = write_final_small_label_gap_sample(db, limit=24, output_path=tmp_path / "final-gap.csv")

    rows = list(csv.DictReader(StringIO(csv_text)))
    final_rows = list(csv.DictReader(StringIO(final_csv_text)))
    assert debug["mapping_checks"]["benign_in_model_classes"] is True
    assert raw_debug["mapping_checks"]["threshold_can_output_benign"] is True
    assert "Likely Cause" in Path(debug["report_path"]).read_text(encoding="utf-8")
    assert experiment["production_promoted"] is False
    assert experiment["response_automation_allowed"] is False
    assert any(item["name"] == "binary_benign_like_vs_threat" for item in experiment["variants"])
    assert strategy["production_promoted"] is False
    assert "three_class_soc_triage" in strategy["strategies"]
    assert final_recommendation["production_promoted"] is False
    assert final_recommendation["response_automation_allowed"] is False
    assert final_recommendation["recommended_dashboard_strategy"]["mode"] == "SOC triage decision support"
    assert {item["profile"] for item in final_recommendation["stage1_review_profiles"]}.issuperset({"conservative", "balanced", "recall_high"})
    assert "Recommended AI mode: SOC triage decision support" in Path(final_recommendation["report_path"]).read_text(encoding="utf-8")
    assert sample["rows"] > 0
    assert "benign_probability" in csv_text.splitlines()[0]
    assert {row["current_label"] for row in rows}.isdisjoint({"malicious"})
    assert sample["bucket_distribution"].get("benign_training_candidate", 0) > 0
    assert final_sample["rows"] > 0
    assert final_sample["production_promoted"] is False
    assert final_sample["response_automation_allowed"] is False
    assert {row["current_label"] for row in final_rows}.isdisjoint({"malicious"})
    assert "benign_training_candidate" in final_sample["bucket_distribution"]


def test_label_target_plan_and_split_diagnostics_warn_without_promotion(tmp_path, monkeypatch):
    active_path = tmp_path / "active-supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=active_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 9):
            _add_log(db, index, action="allow", app="ssl", app_risk=2, label="benign")
        for index in range(9, 13):
            _add_log(db, index, action="allow", app="incomplete", app_risk=3, label="needs_context")
        for index in range(13, 21):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(21, 29):
            _add_log(db, index, src_ip="198.51.100.8", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        plan = build_supervised_label_target_plan(
            db,
            split="time",
            test_size=0.3,
            targets={"benign": 12, "benign_unusual": 2, "suspicious": 10, "malicious": 4, "needs_context": 6},
        )
        diagnostics = build_evaluation_split_diagnostics(db, test_size=0.3, min_samples=6)
        written = write_evaluation_split_diagnostics(db, output_path=tmp_path / "split-diagnostics.md", test_size=0.3, min_samples=6)
        grouped = supervised_detector.train_supervised_classifier(
            db,
            actor="tester",
            split="grouped_stratified",
            test_size=0.3,
            min_samples=6,
            model_path=tmp_path / "grouped-diagnostic.joblib",
            save_candidate=True,
        )

    recommendations = " ".join(plan["recommendations"])
    report_text = Path(written["report_path"]).read_text(encoding="utf-8")
    rendered = render_evaluation_split_diagnostics(diagnostics)
    assert "benign" in recommendations
    assert "needs_context" in recommendations
    assert "suspicious" in recommendations
    assert "Stage 1 threat-positive false negatives" in recommendations
    assert "Malicious reviewed target is met" in recommendations
    assert diagnostics["production_promoted"] is False
    assert diagnostics["response_automation_allowed"] is False
    assert "Grouped/stratified split is diagnostic only" in rendered
    assert "Grouped/stratified split is diagnostic only" in report_text
    assert "Grouped/stratified split is diagnostic only" in " ".join(grouped["split_warnings"])
    assert (grouped["promotion_gate"] or {}).get("production_promoted") is False
    assert grouped["response_automation_allowed"] is False


def test_rebuild_clean_registered_baseline_saves_candidate_only(tmp_path, monkeypatch):
    active_path = tmp_path / "active-supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=active_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 9):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(9, 17):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="suspicious")
        for index in range(17, 25):
            _add_log(db, index, src_ip="198.51.100.8", action="drop", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        result = rebuild_clean_registered_baseline(
            db,
            output_root=tmp_path / "recovery",
            split="time",
            test_size=0.3,
            min_samples=6,
            actor="tester",
        )

    assert result["status"] == "completed"
    assert result["decision"] == "candidate_only"
    assert result["response_automation_allowed"] is False
    assert len(result["candidates"]) == 4
    assert all(candidate["model_id"] for candidate in result["candidates"])
    assert all(candidate["readiness_decision"] in {"candidate_only", "eligible_for_analyst_review"} for candidate in result["candidates"])
    assert active_path.exists() is False


def test_legacy_supervised_candidate_cannot_bypass_governed_activation(tmp_path, monkeypatch):
    active_path = tmp_path / "active-supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=active_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 8):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(8, 15):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app="unknown-tcp", app_risk=5, label="malicious")
        db.commit()

        active = supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.3, min_samples=6)
        candidate = supervised_detector.train_supervised_classifier(
            db,
            actor="tester",
            test_size=0.3,
            min_samples=6,
            model_type="extra_trees",
            save_candidate=True,
        )
        registry = list_supervised_models(db)
        candidate_id = next(item["model_id"] for item in registry["models"] if item["model_type"] == "extra_trees")
        activated = activate_supervised_model(db, model_id=candidate_id, actor="tester")
        rolled_back = rollback_supervised_model(db, actor="tester")

    assert active["trained"] is True
    assert candidate["save_candidate"] is True
    assert registry["response_automation_allowed"] is False
    assert activated["status"] == "failed_closed"
    assert activated["production_promoted"] is False
    assert rolled_back["status"] == "inactive"
    assert rolled_back["response_automation_allowed"] is False


def test_supervised_model_registry_marks_unregistered_active_artifact(tmp_path, monkeypatch):
    active_path = tmp_path / "active-supervised.joblib"
    active_path.write_bytes(b"legacy active artifact")
    monkeypatch.setattr(supervised_workflow, "supervised_model_path", lambda: active_path)
    Session = _test_session()
    with Session() as db:
        registry = list_supervised_models(db)

    assert registry["active_artifact_exists"] is False
    assert registry["active_artifact_metadata_unknown"] is False
    assert registry["active_artifact_metadata_status"] == "inactive"
    assert registry["legacy_artifact_exists"] is True
    assert registry["legacy_artifact_selected"] is False
    active = registry["models"][0]
    assert active["model_version"] == "active-unregistered"
    assert active["active_artifact_metadata_unknown"] is True
    assert active["is_active_path"] is False
    assert active["display_model_type"] == "Active artifact metadata unknown"
    assert active["production_promoted"] is False
    assert active["response_automation_allowed"] is False


def test_supervised_training_prediction_and_hybrid_score(tmp_path, monkeypatch):
    model_path = tmp_path / "supervised.joblib"
    monkeypatch.setattr(
        supervised_detector,
        "get_settings",
        lambda: SimpleNamespace(resolved_supervised_model_path=model_path),
    )
    Session = _test_session()
    with Session() as db:
        for index in range(1, 7):
            _add_log(db, index, src_ip="10.0.0.5", action="allow", app_risk=2, label="benign")
        for index in range(7, 13):
            _add_log(db, index, src_ip="198.51.100.7", action="deny", app_risk=5, label="malicious")
        db.commit()

        result = supervised_detector.train_supervised_classifier(db, actor="tester", test_size=0.25, min_samples=6)
        prediction = supervised_detector.predict_supervised_log(db, 1, rule_score=50)
        report_markdown = supervised_detector.supervised_report_markdown(db)
        hybrid = hybrid_risk_score(
            rule_score=70,
            isolation_anomaly_score=-0.2,
            isolation_is_anomaly=True,
            supervised_malicious_probability=0.8,
            asset_context_weight=20,
        )

    assert result["trained"] is True
    assert result["metrics"]["accuracy"] >= 0
    assert model_path.exists()
    assert result["report_path"].endswith(".report.md")
    assert (tmp_path / "supervised.report.md").exists()
    assert "Limitations" in report_markdown
    assert prediction["predicted_label"] in {"benign", "benign_unusual", "suspicious", "malicious", "needs_context"}
    assert 0 <= prediction["malicious_probability"] <= 1
    assert prediction["hybrid_risk"]["decision_support_only"] is True
    assert hybrid["final_risk_score"] > 50


def test_demo_label_generator_creates_safe_synthetic_dataset(monkeypatch):
    Session = _test_session()
    monkeypatch.setattr(seed_demo_labels, "SessionLocal", Session)
    monkeypatch.setattr(seed_demo_labels, "init_db", lambda: None)

    result = seed_demo_labels.seed_demo_labels(actor="tester")
    skipped = seed_demo_labels.seed_demo_labels(actor="tester")

    with Session() as db:
        label_count = int(db.scalar(select(func.count(MLLabel.id))) or 0)
        raw_count = int(db.scalar(select(func.count(RawLog.id))) or 0)

    assert result["status"] == "created"
    assert result["created_labels"] >= 24
    assert result["label_distribution"]["malicious"] > 0
    assert skipped["status"] == "skipped"
    assert label_count == result["created_labels"]
    assert raw_count == result["created_logs"]
