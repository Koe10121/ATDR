from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import MLLabel, NormalizedLog, RawLog
from atdr.app.detection import supervised_detector
from atdr.app.detection.hybrid_scoring import hybrid_risk_score
from atdr.app.main import app
from atdr.app.ml.features import build_log_features
from atdr.app.services.assisted_label_service import export_label_review_sample, generate_assisted_labels
from atdr.app.services.ml_label_service import build_label_review_queue, export_review_queue_csv, import_ml_labels_csv
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
    assert prediction["predicted_label"] in {"benign", "malicious"}
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
