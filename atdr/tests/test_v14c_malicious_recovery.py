import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
from atdr.app.detection.v14c_malicious_recovery import (
    V14C_REVIEW_FIELDS,
    _threshold_predictions,
    run_v14c_malicious_recovery,
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


def _seed_labels(db: Session, *, rows_per_class: int = 14) -> None:
    labels = ["benign", "benign_unusual", "suspicious", "malicious", "needs_context"]
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(rows_per_class * len(labels)):
        label_name = labels[index % len(labels)]
        threat = label_name in {"suspicious", "malicious"}
        timestamp = started + timedelta(minutes=index)
        raw = RawLog(raw_line=f"v14c fixture {index}", syslog_timestamp=timestamp)
        db.add(raw)
        db.flush()
        log = NormalizedLog(
            raw_log_id=raw.id,
            generated_time=timestamp,
            receive_time=timestamp,
            log_type="THREAT" if label_name == "malicious" and index % 3 == 0 else "TRAFFIC",
            src_ip=f"10.0.{index % 7}.{index + 1}",
            dst_ip=f"198.51.100.{index % 11 + 1}",
            src_port=40000 + index,
            dst_port=22 + (index % 4) if threat else 443,
            protocol="tcp" if threat else "udp",
            app="incomplete" if threat else "quic-base",
            action="deny" if threat else "allow",
            bytes=1000 + index,
            bytes_sent=700 + index,
            bytes_received=300,
            packets=5 + (index % 8),
            app_risk=5 if label_name == "malicious" else 4 if threat else 2,
            is_anomaly=threat,
            anomaly_score=-0.2 if threat else 0.1,
            parsed_json={},
        )
        db.add(log)
        db.flush()
        db.add(
            MLLabel(
                log_id=log.id,
                label=label_name,
                attack_type="malware_c2" if label_name == "malicious" else "port_scan" if threat else "normal",
                confidence=4,
                reviewer="v14c-test",
                review_note="fixture",
                label_source="manual" if index % 2 == 0 else "assisted_rule",
                reviewed=index % 2 == 0,
            )
        )
    for offset in range(25):
        timestamp = started + timedelta(minutes=1000 + offset)
        raw = RawLog(raw_line=f"v14c actionable {offset}", syslog_timestamp=timestamp)
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=timestamp,
                receive_time=timestamp,
                log_type="TRAFFIC",
                src_ip=f"203.0.113.{offset + 1}",
                dst_ip=f"10.10.0.{offset % 8 + 1}",
                src_port=50000 + offset,
                dst_port=22 if offset % 2 else 445,
                protocol="tcp",
                app="incomplete",
                action="deny",
                bytes=500,
                bytes_sent=400,
                bytes_received=100,
                packets=10,
                app_risk=5,
                is_anomaly=True,
                anomaly_score=-0.3,
                parsed_json={},
            )
        )
    db.commit()


def test_recovery_threshold_keeps_quic_safety_and_strong_threat_evidence():
    safe_quic = type(
        "Log",
        (),
        {
            "app": "quic-base",
            "action": "allow",
            "dst_port": 443,
            "log_type": "TRAFFIC",
            "app_risk": 2,
            "is_anomaly": False,
            "anomaly_score": 0.1,
            "bytes_sent": 500,
        },
    )()
    strong_quic = type(
        "Log",
        (),
        {
            "app": "quic-base",
            "action": "allow",
            "dst_port": 443,
            "log_type": "THREAT",
            "app_risk": 5,
            "is_anomaly": True,
            "anomaly_score": -0.2,
            "bytes_sent": 500,
        },
    )()
    features = {
        "scanning_like_behavior_score": 0,
        "src_ip_15min_unique_dst_ports": 1,
        "src_ip_15min_unique_dst_ips": 1,
        "external_to_internal_flag": 0,
        "repeated_connection_attempts": 1,
        "src_ip_5min_deny_count": 0,
    }
    prepared = {
        "logs": [safe_quic, strong_quic],
        "test_idx": [0, 1],
        "frame": pd.DataFrame([features, features]),
    }
    predictions = _threshold_predictions(
        prepared,
        [[0.05, 0.50, 0.45], [0.05, 0.50, 0.45]],
        ["benign_like", "malicious", "suspicious"],
        threat_threshold=0.56,
        malicious_threshold=0.24,
        malicious_ratio=0.62,
    )

    assert predictions == ["benign_like", "malicious"]


def test_v14c_report_calibration_and_review_export_are_candidate_only(tmp_path):
    with _session() as db:
        _seed_labels(db)
        result = run_v14c_malicious_recovery(
            db,
            split="random",
            test_size=0.3,
            min_samples=6,
            review_limit=10,
            output_dir=tmp_path,
        )

    assert result["ok"] is True
    assert len(result["profiles"]) == 6
    assert Path(result["report_path"]).exists()
    assert Path(result["analysis_report_path"]).exists()
    assert result["calibration"]["selected_method"]
    assert "sigmoid_calibration" in result["calibration"]["candidates"]
    assert "isotonic_calibration" in result["calibration"]["candidates"]
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["model_artifact_written"] is False
    assert result["response_automation_allowed"] is False
    assert result["readiness"]["production_promoted"] is False
    assert "suspicious_pattern_overlap_misses" in result["analysis"]

    review_path = Path(result["review_sample"]["path"])
    with review_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == V14C_REVIEW_FIELDS
        rows = list(reader)
    assert all(row["label_source"] != "manual" for row in rows)


def test_profiles_over_false_positive_budget_are_marked_diagnostic(tmp_path):
    with _session() as db:
        _seed_labels(db)
        result = run_v14c_malicious_recovery(
            db,
            split="random",
            test_size=0.3,
            min_samples=6,
            review_limit=5,
            output_dir=tmp_path,
        )

    for profile in result["profiles"]:
        fpr = float(profile["summary"]["benign_like_false_positive_rate"])
        if fpr > 0.15:
            assert profile["rejected_for_false_positive_budget"] is True
            assert profile["diagnostic_only"] is True
