"""Experimental alerts from the MFU behaviour model: only where the rules raised none, only for switched-on types."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from atdr.app.core.config import get_settings
from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.models import Alert, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import infer_attack_type_from_rules
from atdr.app.services import behavior_findings_service, model_alert_service
from atdr.app.services.behavior_findings_service import model_status, window_findings
from atdr.app.services.model_alert_service import MODEL_ALERT_CODE, create_model_alerts, set_experimental_alerting
from atdr.tests.test_behavior_findings import START, _model, db  # noqa: F401  (db is a fixture)


def _quiet_scanner(session):
    """A campus device the model calls a port scan: answered, identified traffic, so no rule fires."""

    for port in range(12):
        line = f"quiet scan {port}"
        raw = RawLog(raw_line=line, raw_line_hash=raw_line_fingerprint(line))
        session.add(raw)
        session.flush()
        session.add(NormalizedLog(
            raw_log_id=raw.id, generated_time=START + timedelta(seconds=50 + port), src_ip="10.1.0.20", dst_ip="93.184.216.34",
            dst_port=2000 + port, src_zone="WLAN-Inside", dst_zone="SG-Outside", action="allow", app="ssl", app_risk=2,
            bytes_sent=60, bytes_received=500, packets=2, elapsed_time=1, log_type="TRAFFIC", parsed_json={},
        ))
    session.commit()


def _switched_on(types=("port_scan",)):
    model = _model()
    set_experimental_alerting(model, types=list(types), actor="koe", reason="no more MFU data; run experimentally")
    return model


def _model_alerts(session):
    return list(session.scalars(select(Alert).where(Alert.alert_type == MODEL_ALERT_CODE)))


def test_nothing_is_raised_while_model_alerts_are_off(db):  # noqa: F811
    _quiet_scanner(db)
    assert create_model_alerts(db, windows=[START], model=_model()) == {"enabled": False, "created": 0}
    assert _model_alerts(db) == []


def test_the_model_alerts_where_the_rules_did_not_and_says_it_is_experimental(db):  # noqa: F811
    _quiet_scanner(db)
    model = _switched_on()

    summary = create_model_alerts(db, windows=[START], model=model, actor="koe")

    assert summary["created"] == 1 and summary["created_by_type"] == {"port_scan": 1}
    alert = _model_alerts(db)[0]
    assert alert.src_ip == "10.1.0.20", "the source the rules already alerted on gets no second alert"
    assert alert.title.startswith("Low: Experimental: MFU model sees possible port scan")
    assert "Experimental, low confidence" in alert.explanation and "21-minute MFU export" in alert.explanation
    assert alert.recommended_response.startswith("Experimental model alert: confirm before acting.")
    assert len(alert.evidence) == 12
    assert infer_attack_type_from_rules(alert.matched_rules_json) == "port_scan"
    assert alert.matched_rules_json[0]["experimental"] is True

    again = create_model_alerts(db, windows=[START], model=model)
    assert (again["created"], again["already_raised"]) == (0, 1), "a window is alerted once"

    finding = next(item for item in window_findings(db, START, model=model)["findings"] if item["source"] == "10.1.0.20")
    assert finding["found_by"] == "model_only", "the model's own alert is not a rule alert"
    assert finding["model_alert_ids"] == [alert.id] and finding["status"] == "experimental_alert"


def test_only_switched_on_types_raise_alerts(db):  # noqa: F811
    _quiet_scanner(db)
    assert create_model_alerts(db, windows=[START], model=_switched_on(("malware_c2",)))["created"] == 0
    assert _model_alerts(db) == []


def test_the_status_says_which_types_run_experimentally_and_why(db):  # noqa: F811
    status = model_status(_switched_on())
    assert status["alerting_types"] == ["port_scan"] and status["alerting_mode"] == "experimental"
    assert status["experimental_alerting"]["reason"] == "no more MFU data; run experimentally"
    assert status["experimental_alerting"]["quality_bar_passed"] == []
    assert "21-minute MFU export" in status["data_limit"]
    assert model_status(_model())["alerting_mode"] == "advisory"


def test_detection_raises_model_alerts_for_the_windows_it_checked_but_the_scoreboard_does_not(db, monkeypatch):  # noqa: F811
    from atdr.app.services.detection_scoreboard_service import reset_detection_state, run_all_detection
    from atdr.app.services.detection_service import run_detection

    _quiet_scanner(db)
    monkeypatch.setattr(behavior_findings_service, "load_model", lambda *args, **kwargs: _switched_on())
    monkeypatch.setattr(model_alert_service, "load_model", lambda *args, **kwargs: _switched_on())
    monkeypatch.setenv("ATDR_MODEL_ALERTS", "true")
    get_settings.cache_clear()
    try:
        run_all_detection(db)
        assert _model_alerts(db) == [], "the scoreboard and blind check measure the rules alone"
        reset_detection_state(db)
        result = run_detection(db, limit=5000, use_ml=False, actor="test", only_unchecked=True)
        assert result["model_alerts"]["created"] >= 1
        assert [alert.src_ip for alert in _model_alerts(db)] == ["10.1.0.20"]
    finally:
        monkeypatch.delenv("ATDR_MODEL_ALERTS")
        get_settings.cache_clear()
    assert db.scalar(select(func.count(Alert.id))) >= 1
