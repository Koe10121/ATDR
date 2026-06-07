import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
from atdr.app.detection.v14_false_positive import (
    V14_REVIEW_FIELDS,
    V14_THRESHOLD_PROFILES,
    _v14_threshold_decision,
    run_v14_false_positive_reduction,
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


def _seed_labels(db: Session, *, rows_per_class: int = 10) -> None:
    labels = ["benign", "benign_unusual", "suspicious", "malicious", "needs_context"]
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    index = 0
    for label in labels:
        for offset in range(rows_per_class):
            timestamp = started + timedelta(minutes=index)
            threat = label in {"suspicious", "malicious"}
            raw = RawLog(raw_line=f"v14 fixture {index}", syslog_timestamp=timestamp)
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                generated_time=timestamp,
                receive_time=timestamp,
                log_type="TRAFFIC",
                src_ip=f"10.0.{index % 5}.{index + 1}",
                dst_ip=f"198.51.100.{index % 9 + 1}",
                src_port=40000 + index,
                dst_port=22 + offset if threat else 80 if offset % 2 else 443,
                protocol="tcp",
                app="incomplete" if threat or offset % 3 == 0 else "ssl",
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
                    reviewer="v14-test",
                    review_note="reviewed fixture",
                    label_source="manual" if offset % 2 == 0 else "assisted_rule",
                    reviewed=offset % 2 == 0,
                )
            )
            index += 1
    db.commit()


def test_v14_threshold_gate_cannot_fall_back_to_threat():
    prediction = _v14_threshold_decision(
        {
            "benign": 0.21,
            "benign_unusual": 0.2,
            "needs_context": 0.19,
            "suspicious": 0.22,
            "malicious": 0.18,
        },
        profile="precision_focused",
    )

    assert prediction in {"benign", "benign_unusual", "needs_context"}


def test_v14_workflow_writes_reports_without_activation(tmp_path):
    with _session() as db:
        _seed_labels(db)
        result = run_v14_false_positive_reduction(
            db,
            split="random",
            test_size=0.3,
            min_samples=6,
            review_limit=20,
            output_dir=tmp_path,
        )

    assert result["ok"] is True
    assert set(result["threshold_profiles"]) == set(V14_THRESHOLD_PROFILES)
    assert result["best_strategy"]
    assert result["best_profile"] in V14_THRESHOLD_PROFILES
    assert result["best_calibration"]["buckets"]
    assert result["best_calibration"]["brier_score_threat_positive"] is not None
    assert sum(
        bucket["rows"] for bucket in result["best_calibration"]["buckets"]
    ) == result["best_calibration"]["rows"]
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["model_artifact_written"] is False
    assert result["response_automation_allowed"] is False
    assert result["readiness"]["production_promoted"] is False
    assert Path(result["false_positive_analysis_path"]).exists()
    assert Path(result["threshold_report_path"]).exists()
    assert Path(result["strategy_report_path"]).exists()
    assert Path(result["calibration_report_path"]).exists()
    assert Path(result["report_path"]).exists()

    review_path = Path(result["review_sample"]["path"])
    assert review_path.exists()
    with review_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == V14_REVIEW_FIELDS
        rows = list(reader)
    assert len(rows) <= 20
    if rows:
        assert rows[0]["human_review_decision"] == ""
        assert rows[0]["log_id"]
        assert all(row["label_source"] != "manual" for row in rows)
