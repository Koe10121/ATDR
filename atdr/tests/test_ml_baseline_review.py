import csv
import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog, NormalizedLog, RawLog
from atdr.app.services.ml_baseline_review_service import build_ml_baseline_review, export_ml_baseline_review


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _add_log(db, index: int, *, action: str = "allow", app_risk: int = 2, is_anomaly: bool = False) -> None:
    raw = RawLog(
        raw_line=f"2026-05-20T13:36:{index:02d}+07:00 lab-fw.example.invalid sample,{index},TRAFFIC,end",
        syslog_timestamp=datetime(2026, 5, 20, 6, 36, index, tzinfo=timezone.utc),
        device_hostname="lab-fw.example.invalid",
    )
    db.add(raw)
    db.flush()
    db.add(
        NormalizedLog(
            raw_log_id=raw.id,
            generated_time=datetime(2026, 5, 20, 6, 36, index, tzinfo=timezone.utc),
            log_type="TRAFFIC",
            subtype="end",
            src_ip=f"10.0.0.{index}",
            dst_ip="203.0.113.10",
            app="ssl",
            src_zone="inside",
            dst_zone="outside",
            src_port=40000 + index,
            dst_port=443,
            protocol="tcp",
            action=action,
            bytes=1000 + index,
            packets=10 + index,
            app_risk=app_risk,
            anomaly_score=-0.2 - index / 100 if is_anomaly else 0.05,
            is_anomaly=is_anomaly,
            parsed_json={},
        )
    )


def test_ml_baseline_review_builds_reviewable_shape():
    Session = _session()
    with Session() as db:
        for index in range(1, 26):
            _add_log(db, index)
        _add_log(db, 26, action="deny", app_risk=5, is_anomaly=True)
        db.commit()

        review = build_ml_baseline_review(db, anomaly_limit=5, baseline_limit=5)

    assert review["ml_assistive_only"] is True
    assert review["baseline_filter"]["exclude_unknown_apps"] is True
    assert review["baseline_readiness"]["baseline_candidate_count"] == 25
    assert review["evaluation_summary"]["anomaly_count"] == 1
    assert len(review["anomaly_review_rows"]) == 1
    assert review["anomaly_review_rows"][0]["review_label"] == ""
    assert "IsolationForest is unsupervised" in review["limitations"][0]


def test_ml_baseline_review_export_writes_files_and_audit(tmp_path):
    Session = _session()
    with Session() as db:
        for index in range(1, 26):
            _add_log(db, index)
        _add_log(db, 26, action="deny", app_risk=5, is_anomaly=True)
        db.commit()

        manifest = export_ml_baseline_review(db, output_dir=tmp_path, anomaly_limit=10, baseline_limit=10, actor="tester")
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "export_ml_baseline_review"))

    assert manifest["ok"] is True
    assert manifest["anomaly_rows"] == 1
    assert manifest["baseline_candidate_rows"] == 10
    assert audit is not None
    assert audit.actor == "tester"

    review_dir = tmp_path / next(tmp_path.iterdir()).name
    summary_path = review_dir / "ml_baseline_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["baseline_readiness"]["baseline_candidate_count"] == 25

    anomaly_csv = review_dir / "anomaly_review.csv"
    rows = list(csv.DictReader(anomaly_csv.open(encoding="utf-8")))
    assert rows[0]["review_label"] == ""
    assert rows[0]["raw_evidence_excerpt"].startswith("2026-05-20T13:36")
