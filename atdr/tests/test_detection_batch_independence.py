"""Detection must give the same answer whatever the batch size.

Correlation context used to be built only from the logs in the current
batch. A batch of 5,000 lab logs is about 43 seconds of traffic, so a port
scan split across batches was counted in pieces that each stayed under the
10-port threshold: recall was 67% at 5,000-log batches and 75% at 20,000.

Now windows sit on two fixed clock grids (the second shifted by half a
window), each batch covers whole five-minute windows, neighbouring logs
complete windows at batch edges, and beacon cadence spans fifteen minutes.
"""

from datetime import datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.detection.rules import (
    WINDOW_OFFSETS,
    build_detection_context,
    correlation_window_start,
    evaluate_rules,
)
from atdr.app.services.detection_service import dataset_outlier_thresholds, run_detection

START = datetime(2026, 5, 20, 13, 36, 0)
# A scan that starts 30 seconds before a window edge and ends after it.
SCAN_START = datetime(2026, 5, 20, 13, 39, 30)


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _add(db, index: int, **fields) -> int:
    raw = RawLog(raw_line=f"batch independence {index}")
    db.add(raw)
    db.flush()
    log = NormalizedLog(raw_log_id=raw.id, parsed_json={}, **fields)
    db.add(log)
    db.flush()
    return int(log.id)


def _scan_between_benign_traffic(db) -> list[int]:
    """A 12-port denied scan across the 13:40 window edge, with benign traffic."""

    scan_ids = []
    for index in range(12):
        at = SCAN_START + timedelta(seconds=5 * index)
        scan_ids.append(
            _add(
                db,
                index,
                generated_time=at,
                log_type="TRAFFIC",
                src_ip="203.0.113.10",
                dst_ip="10.20.30.40",
                src_zone="SG-Outside",
                dst_zone="LAN-Inside",
                app="incomplete",
                dst_port=20000 + index,
                action="deny",
                protocol="tcp",
                bytes=60,
                packets=1,
            )
        )
        for extra in range(3):
            _add(
                db,
                100 + index * 3 + extra,
                generated_time=at + timedelta(seconds=1 + extra),
                log_type="TRAFFIC",
                src_ip=f"10.1.1.{extra + 1}",
                dst_ip="93.184.216.34",
                src_zone="WLAN-Inside",
                dst_zone="SG-Outside",
                app="ssl",
                app_risk=1,
                dst_port=443,
                action="allow",
                protocol="tcp",
                bytes=5000,
                packets=12,
            )
    db.commit()
    return scan_ids


def _detect_everything(db, batch_size: int) -> tuple[set[int], set[str]]:
    for _ in range(100):
        result = run_detection(db, limit=batch_size, use_ml=False, only_unchecked=True)
        if not result["remaining_unchecked"]:
            break
    alerted = set(db.scalars(select(AlertEvidence.normalized_log_id)))
    types = set(db.scalars(select(Alert.alert_type)))
    return alerted, types


def test_scan_split_across_small_batches_is_detected_like_one_big_batch():
    small = _session()
    scan_ids = _scan_between_benign_traffic(small)
    alerted_small, types_small = _detect_everything(small, batch_size=5)

    big = _session()
    _scan_between_benign_traffic(big)
    alerted_big, types_big = _detect_everything(big, batch_size=1000)

    assert set(scan_ids) <= alerted_big
    big_rule_codes = {item["code"] for alert in big.scalars(select(Alert)) for item in alert.matched_rules_json}
    assert "possible_port_scan" in big_rule_codes
    assert alerted_small == alerted_big
    assert types_small == types_big


def test_windows_sit_on_two_fixed_clock_grids():
    shifted = WINDOW_OFFSETS[1]
    assert correlation_window_start(datetime(2026, 5, 20, 13, 39, 59)) == datetime(2026, 5, 20, 13, 35)
    assert correlation_window_start(datetime(2026, 5, 20, 13, 40, 0)) == datetime(2026, 5, 20, 13, 40)
    assert correlation_window_start(datetime(2026, 5, 20, 13, 39, 59), shifted) == datetime(2026, 5, 20, 13, 37, 30)
    assert correlation_window_start(datetime(2026, 5, 20, 13, 37, 29), shifted) == datetime(2026, 5, 20, 13, 32, 30)


def test_a_burst_across_a_window_edge_is_seen_whole_in_the_shifted_window():
    def log(log_id: int, at: datetime, port: int) -> NormalizedLog:
        return NormalizedLog(id=log_id, raw_log_id=log_id, generated_time=at, src_ip="203.0.113.9", dst_port=port, parsed_json={})

    context = build_detection_context(
        [log(1, datetime(2026, 5, 20, 13, 39, 50), 1), log(2, datetime(2026, 5, 20, 13, 40, 10), 2)]
    )
    for log_id in (1, 2):
        assert context.event_correlations[log_id].distinct_ports == frozenset({1, 2})
        assert context.event_correlations[log_id].window_label == "2026-05-20T13:37:30"


def test_one_minute_beacon_across_a_window_edge_is_detected():
    # Six check-ins a minute apart from 13:00:10 put five in the 13:00 window
    # and one in 13:05; cadence over fifteen minutes still sees all six.
    beacons = [
        NormalizedLog(
            id=index + 1,
            raw_log_id=index + 1,
            generated_time=datetime(2026, 5, 20, 13, 0, 10) + timedelta(minutes=index),
            log_type="TRAFFIC",
            src_ip="10.1.5.5",
            dst_ip="198.51.100.77",
            src_zone="LAN-Inside",
            dst_zone="SG-Outside",
            app="unknown-tcp",
            dst_port=4444,
            action="allow",
            protocol="tcp",
            bytes=300,
            packets=4,
            parsed_json={},
        )
        for index in range(6)
    ]
    context = build_detection_context(beacons)
    for beacon in beacons:
        codes = {match.code for match in evaluate_rules(beacon, context)}
        assert "beaconing_like_outbound" in codes


def test_detection_judges_volume_against_the_stored_traffic_threshold(monkeypatch):
    # Detection must use the dataset-wide bar, not one recomputed per batch.
    from atdr.app.services import detection_service

    monkeypatch.setattr(detection_service, "dataset_outlier_thresholds", lambda db: (1_000.0, 50_000.0))
    db = _session()
    _add(db, 1, generated_time=START, log_type="TRAFFIC", src_ip="10.1.2.3", dst_ip="93.184.216.34",
         src_zone="WLAN-Inside", dst_zone="SG-Outside", app="ssl", dst_port=443, action="deny",
         protocol="tcp", bytes=5_000, packets=10)
    db.commit()
    run_detection(db, limit=None, use_ml=False)
    codes = {item["code"] for alert in db.scalars(select(Alert)) for item in alert.matched_rules_json}
    # 5,000 outbound bytes is far below the 10 MB per-batch floor, so only the
    # dataset bar (patched to 1,000) can flag it.
    assert "high_outbound_bytes" in codes


def test_outlier_thresholds_come_from_all_stored_logs_not_the_batch():
    db = _session()
    for index in range(20):
        _add(db, index, generated_time=START, src_ip="10.0.0.1", bytes=1_000 * (index + 1), packets=10)
    db.commit()
    byte_bar, packet_bar = dataset_outlier_thresholds(db)
    # Small lab values keep the safety floors.
    assert byte_bar == 10_000_000.0
    assert packet_bar == 50_000.0

    for index in range(20):
        _add(db, 100 + index, generated_time=START, src_ip="10.0.0.2", bytes=50_000_000 * (index + 1), packets=10)
    db.commit()
    values = [1_000 * (index + 1) for index in range(20)] + [50_000_000 * (index + 1) for index in range(20)]
    mean_value = sum(values) / len(values)
    std_value = (sum((value - mean_value) ** 2 for value in values) / len(values)) ** 0.5
    assert abs(dataset_outlier_thresholds(db)[0] - (mean_value + 3 * std_value)) < 1.0
