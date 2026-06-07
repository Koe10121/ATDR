import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
from atdr.app.detection.v14b_false_positive import (
    V14B_REVIEW_FIELDS,
    _mitigation_predictions,
    _review_eligibility,
    _strong_evidence,
    run_v14b_false_positive_mitigation,
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
    for label_name in labels:
        for offset in range(rows_per_class):
            timestamp = started + timedelta(minutes=index)
            threat = label_name in {"suspicious", "malicious"}
            raw = RawLog(raw_line=f"v14b fixture {index}", syslog_timestamp=timestamp)
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
                dst_port=22 + offset if threat else 443,
                protocol="tcp" if threat else "udp",
                app="incomplete" if threat else "quic-base",
                action="deny" if threat else "allow",
                bytes=100 + index,
                bytes_sent=60 + index,
                bytes_received=40,
                packets=2 + offset,
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
                    attack_type="port_scan" if threat else "normal",
                    confidence=4,
                    reviewer="v14b-test",
                    review_note="fixture",
                    label_source="manual" if offset % 2 == 0 else "assisted_rule",
                    reviewed=offset % 2 == 0,
                )
            )
            index += 1
    for offset in range(20):
        timestamp = started + timedelta(minutes=index + offset)
        raw = RawLog(raw_line=f"v14b unlabeled {offset}", syslog_timestamp=timestamp)
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=timestamp,
                receive_time=timestamp,
                log_type="TRAFFIC",
                src_ip=f"10.10.0.{offset + 1}",
                dst_ip="203.0.113.10",
                src_port=50000 + offset,
                dst_port=443,
                protocol="udp",
                app="quic-base",
                action="allow",
                bytes=500,
                bytes_sent=300,
                bytes_received=200,
                packets=4,
                app_risk=2,
                is_anomaly=False,
                anomaly_score=0.1,
                parsed_json={},
            )
        )
    db.commit()


def test_actionable_filter_excludes_manual_and_supports_explicit_opt_in():
    manual = SimpleNamespace(label_source="manual", reviewed=True)
    assisted = SimpleNamespace(label_source="assisted_ml", reviewed=False)

    assert _review_eligibility(
        manual,
        include_manual=False,
        include_reviewed=False,
        only_actionable=True,
    ) == (False, "protected_manual")
    assert _review_eligibility(
        manual,
        include_manual=True,
        include_reviewed=False,
        only_actionable=True,
    ) == (True, "protected_manual_explicitly_included")
    assert _review_eligibility(
        assisted,
        include_manual=False,
        include_reviewed=False,
        only_actionable=True,
    ) == (True, "unreviewed_assisted")


def test_quic_mitigation_preserves_rows_with_strong_threat_evidence():
    safe_log = SimpleNamespace(
        app="quic-base",
        action="allow",
        dst_port=443,
        log_type="TRAFFIC",
        app_risk=2,
        is_anomaly=False,
        anomaly_score=0.1,
        bytes_sent=500,
    )
    threat_log = SimpleNamespace(
        app="quic-base",
        action="allow",
        dst_port=443,
        log_type="THREAT",
        app_risk=5,
        is_anomaly=True,
        anomaly_score=-0.2,
        bytes_sent=500,
    )
    safe_features = {
        "scanning_like_behavior_score": 0,
        "src_ip_15min_unique_dst_ports": 1,
        "src_ip_15min_unique_dst_ips": 1,
        "external_to_internal_flag": 0,
        "repeated_connection_attempts": 1,
        "src_ip_5min_deny_count": 0,
    }
    threat_features = {
        **safe_features,
        "scanning_like_behavior_score": 80,
        "src_ip_15min_unique_dst_ports": 25,
    }
    prepared = {
        "logs": [safe_log, threat_log],
        "test_idx": [0, 1],
        "frame": pd.DataFrame([safe_features, threat_features]),
    }
    strategy = {
        "_probabilities": [
            [0.15, 0.35, 0.50],
            [0.05, 0.55, 0.40],
        ],
        "_classes": ["benign_like", "malicious", "suspicious"],
        "_predictions": {
            "balanced": ["suspicious", "malicious"],
            "low_noise_soc_queue": ["benign_like", "malicious"],
        },
    }

    predictions = _mitigation_predictions(prepared, strategy)

    assert _strong_evidence(safe_log, safe_features) == []
    assert _strong_evidence(threat_log, threat_features)
    assert predictions["three_class_quic_benign_prior"][0] == "benign_like"
    assert predictions["hybrid_quic_adjustment"][0] == "benign_like"
    assert predictions["quic_stronger_evidence_threshold"][0] == "benign_like"
    assert predictions["three_class_quic_benign_prior"][1] == "malicious"
    assert predictions["hybrid_quic_adjustment"][1] == "malicious"
    assert predictions["quic_stronger_evidence_threshold"][1] == "malicious"


def test_v14b_report_and_default_sample_are_candidate_only(tmp_path):
    with _session() as db:
        _seed_labels(db)
        result = run_v14b_false_positive_mitigation(
            db,
            split="random",
            test_size=0.3,
            min_samples=6,
            review_limit=10,
            output_dir=tmp_path,
        )

    assert result["ok"] is True
    assert len(result["strategies"]) == 5
    assert Path(result["report_path"]).exists()
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["model_artifact_written"] is False
    assert result["response_automation_allowed"] is False
    assert result["readiness"]["production_promoted"] is False
    assert result["review_sample"]["protected_manual_rows"] == 0

    review_path = Path(result["review_sample"]["path"])
    with review_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == V14B_REVIEW_FIELDS
        rows = list(reader)
    assert all(row["label_source"] != "manual" for row in rows)
