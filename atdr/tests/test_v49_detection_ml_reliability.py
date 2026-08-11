from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pandas as pd
from sklearn.dummy import DummyClassifier
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, LogSource, NormalizedLog, RawLog
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.detection import v49_detection_ml_reliability as reliability
from atdr.app.detection.rule_catalog import RULE_CATALOG, RULE_CATALOG_VERSION
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.ml.features import FEATURE_SET_VERSION, build_feature_rows, build_log_features
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.tests.test_parser import THREAT_LINE, TRAFFIC_LINE


def test_calibrator_skips_when_chronological_partition_lacks_model_class():
    frame = pd.DataFrame({"feature": [0, 1, 2, 3, 4, 5]})
    targets = [
        "benign_like",
        "suspicious",
        "malicious",
        "benign_like",
        "suspicious",
        "benign_like",
    ]
    model = DummyClassifier(strategy="prior").fit(
        frame.iloc[:3],
        targets[:3],
    )

    calibrated, method = reliability._fit_frozen_calibrator(
        model,
        frame,
        [3, 4, 5],
        targets,
    )

    assert calibrated is model
    assert method == "skipped_calibration_partition_missing_model_class"


def _session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _transient_log(*, source_id: int, index: int, generated: datetime) -> NormalizedLog:
    return NormalizedLog(
        raw_log=RawLog(source_id=source_id, raw_line=f"source {source_id} event {index}"),
        generated_time=generated,
        src_ip="198.51.100.10",
        dst_ip=f"10.0.{source_id}.{index + 1}",
        dst_port=10_000 + index,
        action="deny",
        src_zone="outside",
        dst_zone="inside",
        app="incomplete",
        packets=1,
        bytes=80,
        parsed_json={},
    )


def test_v49_rule_catalog_covers_runtime_rules_with_evidence_contracts():
    assert RULE_CATALOG_VERSION == "atdr_rule_catalog_v5.31.0"
    assert len(RULE_CATALOG) == 19
    assert all(spec.required_fields for spec in RULE_CATALOG.values())
    assert all(spec.false_positives for spec in RULE_CATALOG.values())
    assert all(spec.references for spec in RULE_CATALOG.values())
    assert all(spec.claim_boundary for spec in RULE_CATALOG.values())


def test_source_scoped_rule_correlation_does_not_mix_registered_sources():
    generated = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)
    source_one = [_transient_log(source_id=1, index=index, generated=generated) for index in range(5)]
    source_two = [_transient_log(source_id=2, index=index + 5, generated=generated) for index in range(5)]

    context = build_detection_context([*source_one, *source_two])
    source_one_codes = {match.code for match in evaluate_rules(source_one[0], context)}
    source_two_codes = {match.code for match in evaluate_rules(source_two[0], context)}

    assert "possible_port_scan" not in source_one_codes
    assert "possible_port_scan" not in source_two_codes


def test_rule_correlation_does_not_merge_events_outside_five_minute_windows():
    generated = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)
    logs = [
        _transient_log(source_id=1, index=index, generated=generated + timedelta(minutes=index))
        for index in range(10)
    ]

    context = build_detection_context(logs)

    assert all("possible_port_scan" not in {match.code for match in evaluate_rules(log, context)} for log in logs)


def test_parser_uses_documented_anchor_when_new_trailing_fields_are_present():
    traffic = parse_log_line(f"{TRAFFIC_LINE},future-field-one,future-field-two")
    threat = parse_log_line(f"{THREAT_LINE},future-field-one,future-field-two")

    assert traffic.normalized["app_risk"] == 2
    assert traffic.normalized["app_category"] == "general-internet"
    assert traffic.parsed_json["app_metadata_mapping"] == "pan_high_res_anchor_traffic"
    assert threat.normalized["app_risk"] == 1
    assert threat.normalized["app_category"] == "networking"
    assert threat.parsed_json["app_metadata_mapping"] == "pan_high_res_anchor_threat"


def test_feature_windows_are_source_scoped_and_do_not_count_future_rows():
    Session = _session_factory()
    generated = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)
    with Session() as db:
        source_one = LogSource(name="source-one", source_type="firewall", parser_profile="palo_alto")
        source_two = LogSource(name="source-two", source_type="firewall", parser_profile="palo_alto")
        db.add_all([source_one, source_two])
        db.flush()

        def add_log(source_id: int, index: int, when: datetime) -> NormalizedLog:
            raw = RawLog(source_id=source_id, raw_line=f"feature event {source_id}-{index}")
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                generated_time=when,
                src_ip="203.0.113.20",
                dst_ip="10.0.0.10",
                dst_port=65_000,
                protocol="udp",
                action="allow",
                app="rare-protocol",
                src_zone="outside",
                dst_zone="inside",
                packets=2,
                bytes=100,
                parsed_json={"parser_profile": "palo_alto", "parser_warnings": []},
            )
            db.add(log)
            db.flush()
            return log

        add_log(source_two.id, 0, generated - timedelta(seconds=10))
        current = add_log(source_one.id, 1, generated)
        for index in range(2, 8):
            add_log(source_one.id, index, generated + timedelta(seconds=index))
        db.commit()

        features = build_log_features(db, current)

    assert FEATURE_SET_VERSION == "behavior_windows_v3_leakage_safe"
    assert features["src_ip_5min_event_count"] == 1
    assert features["rare_dst_port_flag"] == 1
    assert features["rare_app_flag"] == 1
    assert features["parser_confidence_score"] == 1.0


def test_bulk_feature_generation_matches_scalar_causal_features():
    Session = _session_factory()
    generated = datetime(2026, 7, 18, 11, 0, tzinfo=timezone.utc)
    with Session() as db:
        sources = [
            LogSource(name="bulk-source-one", source_type="firewall", parser_profile="palo_alto"),
            LogSource(name="bulk-source-two", source_type="firewall", parser_profile="palo_alto"),
        ]
        db.add_all(sources)
        db.flush()
        logs: list[NormalizedLog] = []
        for index in range(40):
            source = sources[index % 2]
            raw = RawLog(source_id=source.id, raw_line=f"bulk feature event {index}")
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                generated_time=generated + timedelta(seconds=index * 15),
                src_ip="203.0.113.50",
                dst_ip=f"10.0.0.{(index % 6) + 1}",
                dst_port=8_000 + (index % 8),
                protocol="tcp",
                action="deny" if index % 4 == 0 else "allow",
                app="incomplete" if index % 5 == 0 else "ssl",
                app_risk=5 if index % 5 == 0 else 2,
                src_zone="outside",
                dst_zone="inside",
                packets=index + 1,
                bytes=100 + index,
                bytes_sent=60 + index,
                bytes_received=40,
                parsed_json={"parser_profile": "palo_alto", "parser_warnings": []},
            )
            db.add(log)
            db.flush()
            logs.append(log)
        db.commit()

        bulk = build_feature_rows(db, logs)
        scalar = {position: build_log_features(db, logs[position]) for position in (0, 11, 24, 39)}

    for position, expected in scalar.items():
        assert bulk[position] == expected


def test_current_supervised_diagnostic_is_not_claimed_as_alert_creation_evidence():
    Session = _session_factory()
    with Session() as db:
        raw = RawLog(raw_line="rule-only evidence")
        db.add(raw)
        db.flush()
        log = NormalizedLog(
            raw_log_id=raw.id,
            generated_time=datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc),
            src_ip="198.51.100.20",
            dst_ip="10.0.0.20",
            dst_port=22,
            action="deny",
            app="ssh",
            src_zone="outside",
            dst_zone="inside",
            parsed_json={"parser_profile": "palo_alto"},
        )
        db.add(log)
        db.flush()
        alert = Alert(
            title="High: Possible port scan",
            alert_type="possible_port_scan",
            src_ip=log.src_ip,
            dst_ip=log.dst_ip,
            threat_score=75,
            severity="High",
            explanation="Rule-only controlled alert.",
            matched_rules_json=[
                {
                    "code": "possible_port_scan",
                    "title": "Possible port scanning behavior",
                    "score": 25,
                    "explanation": "Observed ten distinct ports.",
                }
            ],
            recommended_response="Investigate source.",
        )
        alert.evidence.append(AlertEvidence(normalized_log_id=log.id))
        db.add(alert)
        db.commit()
        db.refresh(alert)

        summary = build_alert_detection_summary(db, alert)

    assert summary["detection_source"] == ["rule"]
    assert summary["alert_authority"]["layer"] == "deterministic_rules"
    assert summary["anomaly"]["used_for_alert_creation"] is False
    assert summary["ml_evidence"]["used_for_alert_creation"] is False
    assert summary["hybrid_risk"]["used_for_alert_creation"] is False


def test_v49_threshold_selection_never_uses_final_test_labels():
    selected = reliability.select_v49_threshold(
        ["non_threat", "needs_review", "needs_review", "non_threat"],
        [0.05, 0.95, 0.85, 0.10],
    )

    assert selected["selected_on"] == "threshold_selection_partition_only"
    assert selected["used_final_test_labels"] is False
    assert selected["threshold_rows"] == 4


def test_v49_strict_calibration_gate_rejects_excess_confidence_gap():
    result = reliability._strict_calibration(
        {
            "passed": True,
            "expected_calibration_error": 0.08,
            "max_confidence_accuracy_gap": 0.16,
        }
    )

    assert result["legacy_gate_passed"] is True
    assert result["passed"] is False
    assert result["status"] == "weak"


def test_v49_network_zone_holdout_is_group_disjoint():
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = []
    for group in range(4):
        for offset in range(20):
            index = len(rows)
            rows.append(
                {
                    "index": index,
                    "log_id": index + 1,
                    "source_name": "one-physical-firewall",
                    "network_zone_group": f"zone-{group}",
                    "timestamp": started + timedelta(minutes=index),
                    "safe_queue_target": "needs_review" if offset % 2 else "non_threat",
                    "exact_fingerprint": f"exact-{index}",
                    "near_fingerprint": f"near-{index}",
                    "feature_fingerprint": f"feature-{index}",
                    "leakage_group": f"group-{index}",
                }
            )

    partition = reliability.frozen.build_frozen_partition(rows, split_mode="network_zone_holdout")
    audit = reliability.frozen.audit_partition_leakage(rows, partition)
    development = partition["fit_idx"] + partition["calibration_idx"] + partition["threshold_idx"]
    development_groups = {rows[index]["network_zone_group"] for index in development}
    final_groups = {rows[index]["network_zone_group"] for index in partition["final_test_idx"]}

    assert audit["passed"] is True
    assert development_groups.isdisjoint(final_groups)
    assert audit["network_zone_group_overlap_with_final_test"] == 0


def test_v49_runner_is_read_only_and_never_promotes(tmp_path, monkeypatch):
    rows = []
    labels = []
    original_labels = []
    for index in range(20):
        label = "suspicious" if index % 2 else "benign"
        original_labels.append(label)
        labels.append(SimpleNamespace(attack_type="port_scan" if label == "suspicious" else "normal"))
        rows.append(
            {
                "index": index,
                "log_id": index + 1,
                "source_name": "test-source",
                "network_zone_group": f"zone-{index % 4}",
                "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index),
                "safe_queue_target": "needs_review" if label == "suspicious" else "non_threat",
                "exact_fingerprint": f"exact-{index}",
                "near_fingerprint": f"near-{index}",
                "feature_fingerprint": f"feature-{index}",
                "leakage_group": f"group-{index}",
            }
        )
    dataset = {
        "ok": True,
        "rows": rows,
        "labels": labels,
        "logs": [],
        "frame": SimpleNamespace(),
        "imports": (),
        "targets": [row["safe_queue_target"] for row in rows],
        "original_labels": original_labels,
        "feature_generation_seconds": 0.01,
        "feature_meta": {"numeric_features": ["feature"], "categorical_features": [], "excluded_features": []},
        "label_provenance": {
            "reviewed_latest_rows": len(rows),
            "weak_or_unreviewed_latest_rows_excluded": 0,
            "duplicate_normalized_log_ids_in_evaluation": 0,
        },
    }

    def evaluated_split(split_mode: str) -> dict:
        return {
            "split_mode": split_mode,
            "status": "evaluated",
            "partition": {"partition_id": split_mode},
            "partition_sizes": {"fit": 8, "calibration": 4, "threshold": 4, "final_test": 4, "quarantined": 0},
            "partition_target_distributions": {},
            "leakage_audit": {"passed": True, "status": "passed"},
            "strategies": [
                {
                    "name": reliability.PREDECLARED_CANDIDATE,
                    "status": "evaluated",
                    "threshold_selection": {"used_final_test_labels": False},
                    "metrics": {
                        "queue_precision": 0.90,
                        "queue_recall": 0.90,
                        "queue_f1": 0.90,
                        "benign_like_false_positive_rate": 0.05,
                        "macro_f1": 0.90,
                        "weighted_f1": 0.90,
                        "suspicious_recall": 0.90,
                        "malicious_recall": 0.90,
                        "review_queue_rate": 0.50,
                    },
                    "calibration": {
                        "passed": True,
                        "expected_calibration_error": 0.05,
                        "max_confidence_accuracy_gap": 0.10,
                    },
                }
            ],
        }

    monkeypatch.setattr(reliability.frozen, "_build_dataset", lambda db, min_samples: dataset)
    monkeypatch.setattr(reliability, "_run_split", lambda current, split_mode: evaluated_split(split_mode))
    monkeypatch.setattr(
        reliability.frozen,
        "_artifact_state",
        lambda: {"exists": False, "name": "supervised_model.joblib", "size_bytes": None, "modified_ns": None},
    )

    Session = _session_factory()
    with Session() as db:
        before_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
        result = reliability.run_v49_detection_ml_reliability(db, output_dir=tmp_path, min_samples=10)
        after_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)

    assert result["ok"] is True
    assert result["readiness"]["decision"] == "candidate_only"
    assert "locked external benchmark passes strict gates" in result["readiness"]["blockers"]
    assert result["safety"]["database_counts_unchanged"] is True
    assert result["safety"]["active_artifact_unchanged"] is True
    assert result["safety"]["labels_written"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["response_actions_created"] == 0
    assert before_alerts == after_alerts
    assert (tmp_path / reliability.V49_LATEST).exists()
    assert list(tmp_path.glob("v4_9_detection_ml_reliability_*.md"))
    assert list(tmp_path.glob("v4_9_split_stability_*.md"))
    assert "raw_line" not in (tmp_path / reliability.V49_LATEST).read_text(encoding="utf-8")
