from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import MLLabel, MLModelRun, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.v331_noise_reduction import (
    V331_PROFILE_ORDER,
    _hard_gate_decision,
    run_v331_noise_reduction_evaluation,
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


def _seed_labels(db: Session, *, rows_per_class: int = 12) -> None:
    labels = ["benign", "benign_unusual", "suspicious", "malicious", "needs_context"]
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    index = 0
    for label in labels:
        for offset in range(rows_per_class):
            timestamp = started + timedelta(minutes=index)
            threat = label in {"suspicious", "malicious"}
            benign_quic = label == "benign" and offset % 2 == 0
            raw = RawLog(raw_line=f"v331 synthetic fixture {index}", syslog_timestamp=timestamp)
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                generated_time=timestamp,
                receive_time=timestamp,
                log_type="TRAFFIC",
                src_ip=f"10.31.{index % 9}.{index + 1}",
                dst_ip=f"198.51.100.{index % 20 + 1}",
                src_zone="outside" if threat else "inside",
                dst_zone="inside" if threat else "outside",
                src_port=40000 + index,
                dst_port=443 if benign_quic else 10000 + offset if threat else 80,
                protocol="udp" if benign_quic else "tcp",
                app="quic-base" if benign_quic else "unknown-udp" if threat else "ssl",
                action="allow" if not threat or offset % 3 else "deny",
                bytes=500 + index,
                bytes_sent=350 + index,
                bytes_received=150,
                packets=4 + offset,
                app_risk=5 if label == "malicious" else 4 if label == "suspicious" else 1,
                is_anomaly=threat and offset % 2 == 0,
                anomaly_score=-0.25 if threat else 0.05,
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
                    reviewer="v331-test",
                    review_note="fixture",
                    label_source="manual" if offset % 2 == 0 else "assisted_rule",
                    reviewed=offset % 2 == 0,
                )
            )
            index += 1
    db.commit()


def test_v331_hard_gate_low_noise_keeps_low_threat_benign_like():
    prediction = _hard_gate_decision(
        {
            "benign": 0.24,
            "benign_unusual": 0.20,
            "needs_context": 0.18,
            "suspicious": 0.26,
            "malicious": 0.12,
        },
        profile="low_noise_soc_queue",
        mode="flat",
    )

    assert prediction in {"benign", "benign_unusual", "needs_context"}


def test_v331_noise_reduction_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v331_noise_reduction_evaluation(
            db,
            split="random",
            test_size=0.3,
            min_samples=6,
            review_limit=8,
            output_dir=tmp_path,
        )
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert result["status"] == "completed"
    assert result["baseline"]["benign_like_false_positive_rate"] >= 0
    assert result["best_candidate"]["profile"] in V331_PROFILE_ORDER
    assert result["best_candidate"]["metrics"]["benign_like_false_positive_rate"] >= 0
    assert result["calibration"]["status"] in {"passed", "weak", "unavailable"}
    assert result["readiness"]["decision"] == "candidate_only"
    assert result["safety"]["production_promoted"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_automation_allowed"] is False
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["report_path"]).exists()
    assert Path(result["summary_path"]).exists()
    assert Path(result["latest_summary_path"]).exists()

    report_text = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "v3.31 Model/Feature/Threshold Noise Reduction" in report_text
    assert "Production promoted: false" in report_text
    assert "Response automation allowed: false" in report_text
