from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import AuditLog, MLLabel, NormalizedLog, RawLog
from atdr.app.services.label_review_service import apply_label_review


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _labeled_log(db, index: int, label: str, attack_type: str) -> int:
    raw = RawLog(raw_line=f"review {index}")
    db.add(raw)
    db.flush()
    log = NormalizedLog(raw_log_id=raw.id, src_ip=f"10.0.0.{index}", parsed_json={})
    db.add(log)
    db.flush()
    db.add(MLLabel(log_id=log.id, label=label, attack_type=attack_type, confidence=3, reviewer="team",
                   label_source="manual", reviewed=True))
    db.flush()
    return int(log.id)


def _decision(log_id: int, decision: str, alert_type: str | None = None) -> dict:
    return {"source_ip": f"src-{log_id}", "pattern": "P01", "decision": decision, "note": "reviewed",
            "log_ids": [log_id], "atdr_alert_type": alert_type}


def _latest(db, log_id: int) -> MLLabel:
    return db.scalars(select(MLLabel).where(MLLabel.log_id == log_id).order_by(MLLabel.id.desc())).first()


def test_review_adds_labels_keeps_history_and_is_idempotent():
    db = _session()
    browsing = _labeled_log(db, 1, "suspicious", "port_scan")        # decided Normal
    sweep = _labeled_log(db, 2, "benign_unusual", "normal")           # decided Real threat
    confirmed = _labeled_log(db, 3, "malicious", "port_scan")         # decided Real threat, already a threat
    undecided = _labeled_log(db, 4, "suspicious", "unknown_anomaly")  # decided Unsure
    same = _labeled_log(db, 5, "benign_unusual", "policy_violation")  # decided Normal but unusual
    unusual = _labeled_log(db, 6, "suspicious", "port_scan")          # decided Normal but unusual
    db.commit()
    decisions = [
        _decision(browsing, "Normal"),
        _decision(sweep, "Real threat", "possible_horizontal_scan"),
        _decision(confirmed, "Real threat", "possible_port_scan"),
        _decision(undecided, "Unsure"),
        _decision(same, "Normal but unusual"),
        _decision(unusual, "Normal but unusual"),
    ]

    plan = apply_label_review(db, decisions, reviewer="Koe team", note_prefix="review 2026-09-26")
    assert plan["applied"] is False
    assert (plan["labels_to_add"], plan["unchanged"], plan["skipped_undecided"]) == (3, 2, 1)
    assert db.scalar(select(AuditLog).where(AuditLog.action == "ml_label_review_imported")) is None

    applied = apply_label_review(db, decisions, reviewer="Koe team", note_prefix="review 2026-09-26", apply=True)
    assert applied["applied"] is True
    assert (_latest(db, browsing).label, _latest(db, browsing).attack_type) == ("benign", "normal")
    assert (_latest(db, sweep).label, _latest(db, sweep).attack_type) == ("suspicious", "port_scan")
    assert _latest(db, browsing).label_source == "reviewed_import"
    assert _latest(db, browsing).reviewer == "Koe team"
    assert _latest(db, undecided).label == "suspicious"
    # "Normal but unusual" keeps what the traffic resembles, as existing labels do.
    assert (_latest(db, unusual).label, _latest(db, unusual).attack_type) == ("benign_unusual", "port_scan")
    assert (_latest(db, same).label, _latest(db, same).attack_type) == ("benign_unusual", "policy_violation")
    assert len(list(db.scalars(select(MLLabel).where(MLLabel.log_id == browsing)))) == 2  # history kept
    assert db.scalar(select(AuditLog).where(AuditLog.action == "ml_label_review_imported")) is not None

    again = apply_label_review(db, decisions, reviewer="Koe team", note_prefix="review 2026-09-26", apply=True)
    assert again["labels_to_add"] == 0


def test_unknown_decisions_are_rejected():
    db = _session()
    log_id = _labeled_log(db, 1, "suspicious", "port_scan")
    db.commit()
    try:
        apply_label_review(db, [_decision(log_id, "Maybe")], reviewer="x", note_prefix="x")
    except ValueError as error:
        assert "Maybe" in str(error)
    else:
        raise AssertionError("an unknown decision must be rejected")


def test_review_can_correct_what_kind_of_threat_a_label_names():
    db = _session()
    miner = _labeled_log(db, 1, "suspicious", "policy_violation")   # firewall names XMRig C2
    right = _labeled_log(db, 2, "malicious", "malware_c2")          # already correct
    harmless = _labeled_log(db, 3, "benign_unusual", "normal")      # a threat the team missed
    db.commit()
    decisions = [{**_decision(log_id, "Real threat"), "attack_type": "malware_c2"} for log_id in (miner, right, harmless)]

    applied = apply_label_review(db, decisions, reviewer="team", note_prefix="pack", apply=True)

    assert (applied["labels_to_add"], applied["unchanged"]) == (2, 1)
    assert (_latest(db, miner).label, _latest(db, miner).attack_type) == ("suspicious", "malware_c2"), "stays a threat, type corrected"
    assert (_latest(db, harmless).label, _latest(db, harmless).attack_type) == ("suspicious", "malware_c2")
    try:
        apply_label_review(db, [{**_decision(miner, "Real threat"), "attack_type": "crypto_mining"}], reviewer="team", note_prefix="pack")
    except ValueError as error:
        assert "crypto_mining" in str(error)
    else:
        raise AssertionError("an unknown attack type must be refused")


def test_a_label_the_evidence_cannot_settle_becomes_needs_context():
    db = _session()
    unresolved = _labeled_log(db, 1, "suspicious", "port_scan")
    db.commit()

    applied = apply_label_review(db, [_decision(unresolved, "Needs context")], reviewer="team", note_prefix="follow-up", apply=True)

    assert applied["labels_to_add"] == 1
    assert (_latest(db, unresolved).label, _latest(db, unresolved).attack_type) == ("needs_context", "port_scan")
    assert apply_label_review(db, [_decision(unresolved, "Needs context")], reviewer="team", note_prefix="again")["unchanged"] == 1
