from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from atdr.app.detection import v564_window_aware_anomaly as anomaly


def _normalized(index: int, *, source: str = "source-a") -> dict:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index)
    return {
        "receive_time": timestamp,
        "generated_time": timestamp,
        "log_type": "TRAFFIC",
        "subtype": "end",
        "serial": "test",
        "src_ip": source,
        "dst_ip": f"destination-{index % 7}",
        "nat_src_ip": None,
        "nat_dst_ip": None,
        "rule_name": "test",
        "src_user": None,
        "dst_user": None,
        "app": "ssl",
        "vsys": "vsys1",
        "src_zone": "trust",
        "dst_zone": "untrust",
        "inbound_interface": None,
        "outbound_interface": None,
        "log_action": None,
        "session_id": str(index),
        "repeat_count": 1,
        "src_port": 40_000 + index,
        "dst_port": 443 + (index % 5),
        "protocol": "tcp",
        "action": "allow",
        "bytes": 1_000 + index,
        "bytes_sent": 600 + index,
        "bytes_received": 400,
        "packets": 10,
        "start_time": timestamp,
        "elapsed_time": 1,
        "category": None,
        "src_country": None,
        "dst_country": None,
        "packets_sent": 6,
        "packets_received": 4,
        "session_end_reason": "aged-out",
        "device_name": "test-device",
        "action_source": None,
        "rule_uuid": None,
        "high_res_timestamp": timestamp,
        "app_subcategory": "general",
        "app_category": "internet",
        "app_technology": "browser",
        "app_risk": 2,
        "app_characteristic": "pervasive-use",
    }


def _record(index: int, *, source: str = "source-a") -> dict:
    return anomaly._base_record(
        _normalized(index, source=source),
        {"parse_status": "parsed"},
        ordinal=index,
    )


def _private_sample(path: Path, rows: int = 800) -> None:
    root = Path(__file__).resolve().parents[2]
    base = (
        root / "data" / "samples" / "scenarios" / "normal_allowed_traffic.txt"
    ).read_text(encoding="utf-8").splitlines()[0]
    lines = []
    for index in range(rows):
        hour = (index // 3600) % 24
        minute = (index // 60) % 60
        second = index % 60
        slash_time = f"{hour:02d}:{minute:02d}:{second:02d}"
        iso_time = f"{hour:02d}:{minute:02d}:{second:02d}"
        line = base.replace("14:00:00", slash_time).replace(
            "14:00:00.000", f"{iso_time}.000"
        )
        line = line.replace("700000", str(700_000 + index))
        line = line.replace("41000", str(41_000 + index))
        lines.append(line)
    path.write_text("\n".join(lines), encoding="utf-8")


def test_context_features_use_only_chronological_history():
    records = [_record(index) for index in (3, 0, 2, 1)]
    first = anomaly._contextualize(records)
    second = anomaly._contextualize([_record(index) for index in (3, 0, 2, 1)])

    assert [row["_ordinal"] for row in first] == [0, 1, 2, 3]
    assert [row["src_events_5m"] for row in first] == [1, 2, 3, 4]
    assert [row["src_unique_destinations_5m"] for row in first] == [1, 2, 3, 4]
    fields = (
        "src_events_5m",
        "src_unique_destinations_5m",
        "src_unique_ports_5m",
        "source_interarrival_log_seconds",
    )
    assert [[row[field] for field in fields] for row in first] == [
        [row[field] for field in fields] for row in second
    ]


def test_role_partition_quarantines_cross_role_duplicate_families():
    records = anomaly._contextualize([_record(index) for index in range(800)])
    records[440]["_duplicate_family"] = records[439]["_duplicate_family"]
    evidence = anomaly.EvidenceBundle(
        records=tuple(records),
        trainable_indexes=tuple(range(len(records))),
        public={"passed": True},
    )

    roles = anomaly._partition_roles(evidence, minimum_fit_rows=20)

    assert roles.public["passed"] is True
    assert roles.public["duplicate_family_quarantined_rows"] == 1
    role_families = [
        {row["_duplicate_family"] for row in role}
        for role in (
            roles.fit,
            roles.calibration,
            roles.validation,
            roles.untouched_holdout,
        )
    ]
    for index, families in enumerate(role_families):
        assert all(not families.intersection(later) for later in role_families[index + 1 :])


def test_ood_abstention_is_conservative_and_explicit():
    fit = anomaly._contextualize([_record(index) for index in range(120)])
    profile = anomaly._ood_profile(fit)
    missing = dict(fit[0])
    missing["missing_feature_count"] = 3
    extreme = dict(fit[0])
    for feature in list(profile["bounds"])[:4]:
        extreme[feature] = profile["bounds"][feature][1] + 100_000

    assert anomaly._ood_reason(fit[0], profile) is None
    assert anomaly._ood_reason(missing, profile) == "missing_features"
    assert anomaly._ood_reason(extreme, profile) == "numeric_ood"


def test_preflight_redacts_private_evidence_and_writes_no_artifact(tmp_path: Path):
    private_path = tmp_path / "operator-private.log"
    artifact_path = tmp_path / "models" / "isolation_forest.joblib"
    _private_sample(private_path)

    report = anomaly.run_window_aware_anomaly_redesign(
        sample_path=private_path,
        limit=800,
        preflight_only=True,
        artifact_path=artifact_path,
        minimum_fit_rows=20,
    )

    encoded = json.dumps(report)
    assert report["ok"] is True
    assert report["status"] == "preflight_passed"
    assert report["executed"] is False
    assert report["chronological_roles"]["sealed_supervised_evidence_accessed"] is False
    assert report["safety"]["rules_alert_authoritative"] is True
    assert report["safety"]["candidate_installed"] is False
    assert report["safety"]["model_driven_alerts"] == 0
    assert report["safety"]["response_actions_created"] == 0
    assert not artifact_path.exists()
    assert str(private_path) not in encoded
    assert "10.10.10.10" not in encoded
    assert base64_like_secret_absent(encoded)


def base64_like_secret_absent(encoded: str) -> bool:
    return "api_key" not in encoded.lower() and "client_secret" not in encoded.lower()


def test_safe_error_hides_private_exception_details(tmp_path: Path):
    private_path = tmp_path / "sensitive-private.log"
    report = anomaly.safe_window_aware_error(
        RuntimeError(f"failed while reading {private_path}")
    )

    encoded = json.dumps(report)
    assert str(private_path) not in encoded
    assert report["candidate_installed"] is False
    assert report["safety"]["supervised_model_activated"] is False
    assert report["safety"]["automatic_response_enabled"] is False


def test_fixed_protocol_has_no_install_or_authoritative_ml_path():
    protocol = anomaly._protocol()

    assert protocol["locked_before_candidate_comparison"] is True
    assert protocol["selection_uses_untouched_holdout"] is False
    assert protocol["sealed_supervised_evidence_allowed"] is False
    assert protocol["candidate_installation_available"] is False
    assert tuple(protocol["strategies"]) == anomaly.STRATEGY_NAMES
    assert protocol["distinct_strategy_count"] == len(anomaly.STRATEGY_NAMES) - 1
    assert protocol["known_duplicate_strategies"] == {
        "empirical_percentile_calibration": "robust_scaled_global_isolation_forest",
    }


def test_report_discloses_the_known_duplicate_strategy(
    tmp_path: Path,
    monkeypatch,
):
    # "empirical_percentile_calibration" is built from the same model and
    # calibration table as "robust_scaled_global_isolation_forest" and
    # computes identical percentile scores (see _strategy_scores). The report
    # must disclose this explicitly via "duplicate_of_strategy" rather than
    # presenting eight independently distinct candidates.
    private_path = tmp_path / "private-window.log"
    artifact_path = tmp_path / "models" / "isolation_forest.joblib"
    _private_sample(private_path)
    monkeypatch.setattr(anomaly, "N_ESTIMATORS", 20)

    report = anomaly.run_window_aware_anomaly_redesign(
        sample_path=private_path,
        limit=800,
        artifact_path=artifact_path,
        minimum_fit_rows=20,
    )

    by_strategy: dict[str, list[dict]] = {}
    for item in report["candidate_comparison"]:
        by_strategy.setdefault(item["strategy"], []).append(item)

    empirical = by_strategy["empirical_percentile_calibration"]
    robust_global = by_strategy["robust_scaled_global_isolation_forest"]
    assert len(empirical) == len(robust_global) == len(anomaly.QUEUE_TARGETS)
    for entry in empirical:
        assert entry["duplicate_of_strategy"] == "robust_scaled_global_isolation_forest"
    for entry in robust_global + by_strategy["chronological_window_baseline"]:
        assert entry["duplicate_of_strategy"] is None

    empirical_by_target = {item["queue_target"]: item for item in empirical}
    robust_by_target = {item["queue_target"]: item for item in robust_global}
    for target, entry in empirical_by_target.items():
        twin = robust_by_target[target]
        assert entry["controlled"] == twin["controlled"]
        assert entry["private_validation"] == twin["private_validation"]


def test_full_comparison_is_deterministic_and_cannot_install(
    tmp_path: Path,
    monkeypatch,
):
    private_path = tmp_path / "private-window.log"
    artifact_path = tmp_path / "models" / "isolation_forest.joblib"
    _private_sample(private_path)
    monkeypatch.setattr(anomaly, "N_ESTIMATORS", 20)

    first = anomaly.run_window_aware_anomaly_redesign(
        sample_path=private_path,
        limit=800,
        artifact_path=artifact_path,
        minimum_fit_rows=20,
    )
    second = anomaly.run_window_aware_anomaly_redesign(
        sample_path=private_path,
        limit=800,
        artifact_path=artifact_path,
        minimum_fit_rows=20,
    )

    def summary(report: dict) -> list[tuple]:
        return [
            (
                item["name"],
                item["controlled"]["controlled_benign_anomaly_rate"],
                item["controlled"]["controlled_suspicious_scenario_recall"],
                item["controlled"]["controlled_malicious_scenario_recall"],
                item["private_validation"]["queue_rate"],
                item["all_fixed_gates_passed"],
            )
            for item in report["candidate_comparison"]
        ]

    assert first["ok"] is True
    assert summary(first) == summary(second)
    assert first["selection"] == second["selection"]
    assert first["installation"] == {
        "available": False,
        "requested": False,
        "installed": False,
        "reason": "v5.64_is_diagnostic_only",
    }
    assert first["safety"]["current_artifact_unchanged"] is True
    assert first["safety"]["model_driven_alerts"] == 0
    assert first["safety"]["model_driven_suppressions"] == 0
    assert first["safety"]["labels_created"] == 0
    assert first["safety"]["supervised_model_activated"] is False
    assert first["safety"]["response_actions_created"] == 0
    assert not artifact_path.exists()
