"""The dashboard's view of the behaviour model: read-only, deduplicated, linked to rule alerts, honest about training data."""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.ml.behavior_model import BehaviorModel
from atdr.app.services import behavior_findings_service
from atdr.app.services.behavior_findings_service import alert_opinion, available_windows, latest_window_start, window_findings
from atdr.tests.test_assistant import _client_with_session, _login

START = datetime(2026, 5, 20, 13, 50)


class _PortCounter:
    """Calls a window a port scan when it touches 10 or more ports."""

    classes_ = np.array(["normal", "port_scan"])

    def predict_proba(self, features):
        scan = (features["n_dst_ports"] >= 10).to_numpy()
        return np.column_stack([np.where(scan, 0.01, 0.99), np.where(scan, 0.99, 0.01)])


def _model(trained_from="2026-05-20T13:36:00", trained_to="2026-05-20T13:45:00"):
    quantiles = {"n_dst_ports": {"q001": 1.0, "q01": 1.0, "q10": 1.0, "q90": 2.0, "q99": 4.0, "q999": 10.0}}
    return BehaviorModel(_PortCounter(), 0.9, quantiles, {"version": "test", "trained_from": trained_from, "trained_to": trained_to})


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, future=True)() as session:
        def log(line, seconds, src, dst, port, *, inbound, received):
            raw = RawLog(raw_line=line, raw_line_hash=raw_line_fingerprint(line))
            session.add(raw)
            session.flush()
            row = NormalizedLog(
                raw_log_id=raw.id, generated_time=START + timedelta(seconds=seconds), src_ip=src, dst_ip=dst, dst_port=port,
                src_zone="SG-Outside" if inbound else "WLAN-Inside", dst_zone="WLAN-Inside" if inbound else "SG-Outside",
                action="allow", app="incomplete" if inbound else "ssl", app_risk=2, bytes_sent=60,
                bytes_received=received, packets=1, elapsed_time=0, log_type="TRAFFIC", parsed_json={},
            )
            session.add(row)
            session.flush()
            return row

        scan = [log(f"scan {port}", port, "45.33.32.156", "10.1.0.5", 1000 + port, inbound=True, received=0) for port in range(30)]
        log("scan 0", 40, "45.33.32.156", "10.1.0.5", 1000, inbound=True, received=0)  # imported twice
        for index in range(5):
            log(f"web {index}", index * 9, "10.1.0.6", "142.250.1.1", 443, inbound=False, received=900)
        log("probe", 12, "185.220.101.5", "10.1.0.7", 8081, inbound=True, received=0)
        log("next window", 400, "10.1.0.6", "142.250.1.1", 443, inbound=False, received=900)
        alert = Alert(title="scan", alert_type="possible_port_scan", threat_score=90, severity="Critical", status="open",
                      explanation="x", matched_rules_json=[{"code": "possible_port_scan"}], recommended_response="-", src_ip="45.33.32.156")
        session.add(alert)
        session.flush()
        for row in scan[:3]:
            session.add(AlertEvidence(alert_id=alert.id, normalized_log_id=row.id))
        session.commit()
        yield session
    engine.dispose()


def test_findings_are_deduplicated_linked_to_rule_alerts_and_explained(db):
    before = db.scalar(select(func.count(Alert.id)))
    result = window_findings(db, START, model=_model())

    assert result["window"] == {"start": START.isoformat(), "end": (START + timedelta(minutes=5)).isoformat(), "in_training_data": False}
    assert [finding["source"] for finding in result["findings"]] == ["45.33.32.156"]
    finding = result["findings"][0]
    assert finding["connections"] == 30 and finding["found_by"] == "rules_and_model" and finding["alert_ids"] == [1]
    assert finding["reasons"] == ["30 different destination ports (normal MFU sources: at most 10 in 99.9% of windows)"]
    assert finding["response"]["mitre"]["technique_id"] == "T1046" and finding["response"]["containment"]
    assert finding["status"] == "advisory" and result["model"]["alerting_types"] == []
    assert result["summary"]["background_probing"]["sources"] == 1
    assert result["summary"]["background_probing"]["top_ports"] == [{"port": 8081, "connections": 1}]
    assert db.scalar(select(func.count(Alert.id))) == before


def test_windows_are_whole_five_minutes_and_training_data_is_labelled(db):
    assert available_windows(db) == [
        {"start": "2026-05-20T13:55:00", "logs": 1},
        {"start": "2026-05-20T13:50:00", "logs": 37},
    ]
    inside = window_findings(db, START, model=_model(trained_from="2026-05-20T13:48:00", trained_to="2026-05-20T13:52:00"))
    assert inside["window"]["in_training_data"] is True


def test_the_default_window_skips_a_handful_of_demo_logs(db, monkeypatch):
    assert latest_window_start(db) == datetime(2026, 5, 20, 13, 55), "with no busy window, the newest one is used"
    monkeypatch.setattr(behavior_findings_service, "MIN_DEFAULT_WINDOW_LOGS", 10)
    assert latest_window_start(db) == START


def test_the_model_gives_its_opinion_on_one_alert(db):
    opinion = alert_opinion(db, 1, model=_model())
    assert opinion["attack_type"] == "port_scan" and opinion["flagged"] and opinion["agrees_with_rules"]
    assert opinion["reasons"] and opinion["status"] == "advisory"
    assert alert_opinion(db, 999, model=_model()) is None


def test_the_findings_api_needs_a_login_and_reports_a_missing_model(monkeypatch):
    client, _ = _client_with_session()
    try:
        assert client.get("/api/ml/behavior/findings").status_code == 401
        monkeypatch.setattr(behavior_findings_service, "load_model", lambda *args, **kwargs: None)
        response = client.get("/api/ml/behavior/findings", headers=_login(client))
        missing = client.get("/api/ml/behavior/alerts/1", headers=_login(client))
    finally:
        client.app.dependency_overrides.clear()
    assert response.status_code == 200 and response.json()["model"]["available"] is False
    assert missing.status_code == 404
