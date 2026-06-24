import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import MLLabel, MLModelRun, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection.v330_detection_ml_quality import (
    REVIEW_FIELDS,
    V330_PROFILE_ORDER,
    _profile_decision,
    run_v330_detection_ml_quality_revalidation,
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
            raw = RawLog(raw_line=f"v330 synthetic fixture {index}", syslog_timestamp=timestamp)
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                generated_time=timestamp,
                receive_time=timestamp,
                log_type="TRAFFIC",
                src_ip=f"10.30.{index % 8}.{index + 1}",
                dst_ip=f"198.51.100.{index % 12 + 1}",
                src_zone="outside" if threat else "inside",
                dst_zone="inside" if threat else "outside",
                src_port=40000 + index,
                dst_port=22 + offset if threat else 443 if offset % 2 else 80,
                protocol="tcp",
                app="incomplete" if threat or offset % 4 == 0 else "ssl",
                action="deny" if threat else "allow",
                bytes=500 + index,
                bytes_sent=350 + index,
                bytes_received=150,
                packets=4 + offset,
                app_risk=5 if label == "malicious" else 4 if label == "suspicious" else 2,
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
                    reviewer="v330-test",
                    review_note="fixture",
                    label_source="manual" if offset % 2 == 0 else "assisted_rule",
                    reviewed=offset % 2 == 0,
                )
            )
            index += 1
    db.commit()


def test_v330_profile_decision_low_noise_does_not_fallback_to_threat():
    prediction = _profile_decision(
        {
            "benign": 0.22,
            "benign_unusual": 0.18,
            "needs_context": 0.14,
            "suspicious": 0.28,
            "malicious": 0.18,
        },
        profile="low_noise_soc_queue",
    )

    assert prediction in {"benign", "benign_unusual", "needs_context"}


def test_v330_revalidation_writes_reports_without_side_effects(tmp_path):
    with _session() as db:
        _seed_labels(db)
        before_runs = db.scalar(select(func.count(MLModelRun.id)))
        before_responses = db.scalar(select(func.count(ResponseAction.id)))
        result = run_v330_detection_ml_quality_revalidation(
            db,
            split="random",
            test_size=0.3,
            min_samples=6,
            review_limit=12,
            output_dir=tmp_path,
        )
        after_runs = db.scalar(select(func.count(MLModelRun.id)))
        after_responses = db.scalar(select(func.count(ResponseAction.id)))

    assert result["ok"] is True
    assert [item["profile"] for item in result["threshold_profiles"]] == V330_PROFILE_ORDER
    assert result["baseline"]["metrics"]["threat_positive"]["f1"] >= 0
    assert result["baseline"]["metrics"]["benign_like_false_positive_rate"] >= 0
    assert result["calibration"]["status"] in {"passed", "weak"}
    assert result["readiness"]["production_promoted"] is False
    assert result["production_promoted"] is False
    assert result["model_activated"] is False
    assert result["model_artifact_written"] is False
    assert result["response_automation_allowed"] is False
    assert before_runs == after_runs == result["safety"]["ml_model_runs_after"]
    assert before_responses == after_responses == result["safety"]["response_actions_after"]
    assert Path(result["analysis_report_path"]).exists()
    assert Path(result["summary_report_path"]).exists()
    assert Path(result["latest_summary_report_path"]).exists()

    review_path = Path(result["review_sample"]["path"])
    assert review_path.exists()
    with review_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == REVIEW_FIELDS
        rows = list(reader)
    assert len(rows) <= 12
    if rows:
        assert rows[0]["human_review_decision"] == ""
        assert "v330 synthetic fixture" not in ",".join(rows[0].values())
        assert "C:\\" not in review_path.read_text(encoding="utf-8")

    report_text = Path(result["analysis_report_path"]).read_text(encoding="utf-8")
    assert "Production promoted: false" in report_text
    assert "Response automation allowed: false" in report_text
    assert "Threshold Profile Comparison" in report_text
