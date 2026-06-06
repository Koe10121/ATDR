import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.benchmarks.readiness import readiness_gate_v3
from atdr.app.db.database import Base
from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
from atdr.app.detection.v13_training import (
    V13_REVIEW_FIELDS,
    analyze_v13_ml_errors,
    audit_training_data_quality,
    export_v13_ai_training_review_sample,
    train_v13_supervised_candidates,
    write_v13_label_target_plan,
)


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def _seed_labels(db: Session, *, rows_per_class: int = 8) -> None:
    labels = ["benign", "benign_unusual", "suspicious", "malicious", "needs_context"]
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    index = 0
    for label in labels:
        for offset in range(rows_per_class):
            timestamp = started + timedelta(minutes=index)
            threat = label in {"suspicious", "malicious"}
            raw = RawLog(raw_line=f"v13 fixture {index}", syslog_timestamp=timestamp)
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                generated_time=timestamp,
                receive_time=timestamp,
                log_type="TRAFFIC",
                src_ip=f"10.0.{index % 4}.{index + 1}",
                dst_ip=f"198.51.100.{index % 8 + 1}",
                src_port=40000 + index,
                dst_port=22 + offset if threat else 443,
                protocol="tcp",
                app="incomplete" if threat else "ssl",
                action="deny" if threat else "allow",
                bytes=100 + index,
                bytes_sent=60 + index,
                bytes_received=40,
                packets=2 + offset,
                app_risk=5 if label == "malicious" else 4 if label == "suspicious" else 2,
                is_anomaly=threat,
                anomaly_score=-0.2 if threat else 0.1,
                parsed_json={},
            )
            db.add(log)
            db.flush()
            db.add(
                MLLabel(
                    log_id=log.id,
                    label=label,
                    attack_type="port_scan" if threat else "normal",
                    confidence=4,
                    reviewer="v13-test",
                    review_note="reviewed fixture",
                    label_source="manual" if offset % 2 == 0 else "assisted_rule",
                    reviewed=offset % 2 == 0,
                )
            )
            index += 1
    db.commit()


def test_v13_audit_and_label_target_plan(tmp_path):
    with _session() as db:
        _seed_labels(db)
        audit = audit_training_data_quality(
            db,
            output_path=tmp_path / "training_data_quality_audit_test.md",
            split="random",
        )
        target = write_v13_label_target_plan(
            db,
            output_path=tmp_path / "v1_3_label_target_plan.md",
            split="random",
        )

    assert audit["ok"] is True
    assert audit["reviewed_label_count"] == 20
    assert "duplicate_summary" in audit
    assert "missing_feature_rates" in audit
    assert Path(audit["report_path"]).exists()
    assert len(target["class_rows"]) == 5
    assert all("better_gap" in row for row in target["class_rows"])
    assert Path(target["report_path"]).exists()


def test_v13_review_sample_has_importable_columns(tmp_path):
    with _session() as db:
        _seed_labels(db)
        result = export_v13_ai_training_review_sample(
            db,
            limit=15,
            focus="balanced",
            output_path=tmp_path / "v1_3_ai_training_review_sample.csv",
        )

    assert result["ok"] is True
    assert result["rows"] > 0
    with Path(result["path"]).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == V13_REVIEW_FIELDS
        first = next(reader)
    assert first["human_review_decision"] == ""
    assert first["log_id"]
    assert result["response_automation_allowed"] is False


def test_readiness_gate_v3_is_conservative():
    result = readiness_gate_v3(
        reviewed_label_count=1200,
        reviewed_label_distribution={
            "benign": 300,
            "benign_unusual": 300,
            "suspicious": 300,
            "malicious": 200,
            "needs_context": 100,
        },
        temporal_class_coverage={
            "suspicious": {"train_count": 200, "test_count": 100},
            "malicious": {"train_count": 100, "test_count": 100},
        },
        metrics={
            "threat_positive": {"f1": 0.9, "recall": 0.9},
            "per_class": {
                "suspicious": {"recall": 0.85, "support": 100},
                "malicious": {"recall": 0.7, "support": 100},
            },
            "false_positive_rate": 0.05,
            "false_negatives": 10,
        },
        benchmark_label_count=200,
        calibration_buckets=[{"accuracy": 0.85, "average_confidence": 0.82}],
    )

    assert result["decision"] == "benchmark_validated_candidate"
    assert result["production_status"] == "not_production_promoted"
    assert result["production_promoted"] is False
    assert result["response_automation_allowed"] is False


def test_v13_candidate_training_and_error_analysis_do_not_activate_model(tmp_path):
    with _session() as db:
        _seed_labels(db, rows_per_class=10)
        candidates = train_v13_supervised_candidates(
            db,
            output_path=tmp_path / "v1_3_supervised_candidate_report_test.md",
            split="random",
            min_samples=6,
        )
        errors = analyze_v13_ml_errors(
            db,
            output_path=tmp_path / "v1_3_ml_error_analysis_test.md",
            split="random",
            min_samples=6,
        )

    assert candidates["ok"] is True
    assert candidates["best_flat_candidate"] is not None
    assert candidates["safety"]["model_artifact_written"] is False
    assert candidates["safety"]["model_activated"] is False
    assert candidates["safety"]["automatic_response_enabled"] is False
    assert candidates["readiness_gate_v3"]["production_promoted"] is False
    assert errors["ok"] is True
    assert "recommended_next_label_focus" in errors
    assert errors["response_automation_allowed"] is False
