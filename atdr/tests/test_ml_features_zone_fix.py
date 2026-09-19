from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import NormalizedLog, RawLog
from atdr.app.ml.features import build_log_features


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()


def _log(db, *, src_zone: str, dst_zone: str) -> NormalizedLog:
    raw = RawLog(raw_line="sample")
    db.add(raw)
    db.flush()
    log = NormalizedLog(
        raw_log_id=raw.id,
        generated_time=datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc),
        log_type="TRAFFIC",
        src_ip="203.0.113.50",
        dst_ip="198.51.100.50",
        src_zone=src_zone,
        dst_zone=dst_zone,
        app="ssl",
        dst_port=443,
        action="allow",
        protocol="tcp",
        bytes=1000,
        packets=10,
        parsed_json={},
    )
    db.add(log)
    db.flush()
    return log


def test_ml_feature_direction_flags_are_not_fooled_by_untrust_substring():
    # Regression test: atdr/app/ml/features.py independently reimplemented
    # the same substring-matching zone-classification defect fixed in
    # atdr/app/detection/rules.py ("trust" in "untrust" is True in Python).
    # These flags feed the actual supervised-model feature vector, so this
    # bug would have corrupted training/scoring inputs, not just an
    # explanation or a grouping decision.
    db = _session()
    same_zone = _log(db, src_zone="untrust", dst_zone="untrust")

    features = build_log_features(db, same_zone)

    assert features["external_to_internal_flag"] == 0
    assert features["internal_to_external_flag"] == 0


def test_ml_feature_direction_flags_still_detect_genuine_direction():
    db = _session()
    inbound = _log(db, src_zone="untrust", dst_zone="trust")
    outbound = _log(db, src_zone="trust", dst_zone="untrust")

    inbound_features = build_log_features(db, inbound)
    outbound_features = build_log_features(db, outbound)

    assert inbound_features["external_to_internal_flag"] == 1
    assert inbound_features["internal_to_external_flag"] == 0
    assert outbound_features["external_to_internal_flag"] == 0
    assert outbound_features["internal_to_external_flag"] == 1
