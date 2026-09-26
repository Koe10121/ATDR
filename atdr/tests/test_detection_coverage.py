"""Detection must eventually check every log, not only the newest batch.

Each run used to take the newest N logs and remember nothing, so logs that
fell between batches were never evaluated (85,012 of them in the lab data,
including very-high-risk app traffic that the rules would have alerted on).
"""

from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import AlertEvidence, NormalizedLog, RawLog
from atdr.app.detection.explanations import explain_log_triage
from atdr.app.main import app
from atdr.app.services.demo_service import detection_coverage
from atdr.app.services.detection_service import count_unchecked_logs, run_detection
from atdr.tests.test_api import _client, _login


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _add_log(db, index: int, *, risky: bool = False) -> int:
    raw = RawLog(raw_line=f"coverage log {index}")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 5, 20, 13, 0, index),
        log_type="TRAFFIC",
        src_ip=f"10.1.24.{index}",
        dst_ip="34.237.179.253",
        src_zone="WLAN-Inside",
        dst_zone="SG-Outside",
        app="hola-unblocker" if risky else "ssl",
        app_category="networking",
        app_risk=5 if risky else 1,
        app_characteristic="evasive-behavior,able-to-transfer-file" if risky else None,
        dst_port=443,
        action="allow",
        protocol="tcp",
        bytes=9308,
        packets=22,
        parsed_json={},
    )
    db.add(log)
    db.flush()
    return int(log.id)


def _alerted_log_ids(db) -> set[int]:
    return set(db.scalars(select(AlertEvidence.normalized_log_id)))


def test_every_run_records_which_logs_it_checked():
    db = _session()
    ids = [_add_log(db, index) for index in range(3)]
    db.commit()

    result = run_detection(db, limit=None, use_ml=False)

    checked = dict(db.execute(select(NormalizedLog.id, NormalizedLog.last_detection_run_id)).all())
    assert checked == {log_id: result["detection_run_id"] for log_id in ids}
    assert result["remaining_unchecked"] == 0
    assert result["selection"] == "newest"
    assert result["evaluated_log_id_range"] == [ids[0], ids[-1]]


def test_logs_skipped_by_newest_batches_are_found_and_alerted_by_unchecked_mode():
    db = _session()
    risky_id = _add_log(db, 0, risky=True)
    for index in range(1, 7):
        _add_log(db, index)
    db.commit()

    # The old behaviour: a newest-N run never reaches the older risky log.
    newest = run_detection(db, limit=3, use_ml=False)
    assert newest["evaluated"] == 3
    assert risky_id not in _alerted_log_ids(db)
    assert db.get(NormalizedLog, risky_id).last_detection_run_id is None
    assert newest["remaining_unchecked"] == 4

    # Unchecked mode walks the rest oldest-first and never repeats a log.
    evaluated = []
    first = run_detection(db, limit=2, use_ml=False, only_unchecked=True)
    evaluated.append(first["evaluated"])
    assert first["selection"] == "unchecked_oldest_first"
    assert first["evaluated_log_id_range"][0] == risky_id
    assert risky_id in _alerted_log_ids(db)
    remaining = first["remaining_unchecked"]
    for _ in range(5):
        if not remaining:
            break
        step = run_detection(db, limit=2, use_ml=False, only_unchecked=True)
        evaluated.append(step["evaluated"])
        remaining = step["remaining_unchecked"]

    assert remaining == 0
    assert sum(evaluated) == 4
    assert count_unchecked_logs(db) == 0
    assert run_detection(db, limit=2, use_ml=False, only_unchecked=True)["evaluated"] == 0


def test_unchecked_mode_is_rules_only_even_when_ml_is_requested():
    db = _session()
    _add_log(db, 0)
    db.commit()

    result = run_detection(db, limit=5, use_ml=True, only_unchecked=True)

    assert result["use_ml"] is False
    assert result["evaluated"] == 1


def test_why_not_flagged_says_whether_detection_checked_the_log():
    db = _session()
    log_id = _add_log(db, 0)
    db.commit()

    before = explain_log_triage(db.get(NormalizedLog, log_id))
    assert before["status"] == "not_flagged"
    assert before["summary"] == "Detection has not checked this log yet."

    run_id = run_detection(db, limit=None, use_ml=False)["detection_run_id"]
    db.expire_all()
    after = explain_log_triage(db.get(NormalizedLog, log_id))
    assert after["summary"] == f"Detection run #{run_id} checked this log and did not link it to an alert."


def test_coverage_reports_the_exact_logs_each_action_would_use():
    db = _session()
    ids = [_add_log(db, index) for index in range(5)]
    db.commit()
    run_detection(db, limit=2, use_ml=False)

    coverage = detection_coverage(db, limit=3)

    assert coverage["total_logs"] == 5
    assert coverage["checked_logs"] == 2
    assert coverage["unchecked_logs"] == 3
    assert coverage["oldest_unchecked_log_id"] == ids[0]
    assert coverage["newest_log_id_range"] == [ids[2], ids[4]]
    assert detection_coverage(db, limit=None)["newest_log_id_range"] is None


def test_demo_api_checks_unchecked_logs_in_batches_and_reports_coverage():
    client = _client()
    try:
        session_factory = app.dependency_overrides[get_db]
        seed = session_factory()
        db = next(seed)
        risky_id = _add_log(db, 0, risky=True)
        for index in range(1, 4):
            _add_log(db, index)
        db.commit()
        db.close()

        analyst = _login(client, "analyst", "analyst123")
        assert client.get("/api/demo/detection-coverage", headers=analyst).status_code == 403

        admin = _login(client, "admin", "admin123")
        before = client.get("/api/demo/detection-coverage?limit=2", headers=admin).json()
        assert before["unchecked_logs"] == 4
        assert before["newest_log_id_range"] == [risky_id + 2, risky_id + 3]

        batch = client.post(
            "/api/demo/run-detection",
            json={"mode": "unchecked", "limit": 3, "use_ml": True},
            headers=admin,
        )
        assert batch.status_code == 200
        body = batch.json()
        assert body["evaluated"] == 3
        assert body["remaining_unchecked"] == 1
        assert body["use_ml"] is False
        assert body["created_alerts"] >= 1

        last = client.post("/api/demo/run-detection", json={"mode": "unchecked", "limit": 3}, headers=admin).json()
        assert last["evaluated"] == 1
        assert last["remaining_unchecked"] == 0

        after = client.get("/api/demo/detection-coverage", headers=admin).json()
        assert after["unchecked_logs"] == 0
        assert after["checked_logs"] == 4

        invalid = client.post("/api/demo/run-detection", json={"mode": "everything"}, headers=admin)
        assert invalid.status_code == 422
    finally:
        app.dependency_overrides.clear()
