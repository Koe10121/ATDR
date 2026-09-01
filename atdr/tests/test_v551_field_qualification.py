from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.parsers.paloalto_parser import parse_log_line
from atdr.app.services import v551_field_qualification_service as qualification


def _panos_line(
    log_type: str,
    *,
    field_count: int,
    event_time: datetime,
) -> str:
    fields = [""] * field_count
    payload_time = event_time.strftime("%Y/%m/%d %H:%M:%S")
    for index, value in {
        0: "1",
        1: payload_time,
        2: "000000000051",
        3: log_type,
        4: "end" if log_type == "TRAFFIC" else "spyware" if log_type == "THREAT" else "general",
        6: payload_time,
    }.items():
        if index < field_count:
            fields[index] = value

    if log_type in {"TRAFFIC", "THREAT"}:
        values = {
            7: "198.51.100.51",
            8: "203.0.113.51",
            11: "Synthetic-v551-policy",
            14: "ssl" if log_type == "TRAFFIC" else "web-browsing",
            15: "vsys1",
            16: "Inside-Lab",
            17: "Outside-Lab",
            18: "ethernet1/1",
            19: "ethernet1/2",
            22: "551",
            23: "1",
            24: "45551",
            25: "443",
            29: "tcp",
            30: "allow" if log_type == "TRAFFIC" else "drop",
        }
        for index, value in values.items():
            if index < field_count:
                fields[index] = value

    if log_type == "TRAFFIC":
        for index, value in {
            31: "1200",
            32: "700",
            33: "500",
            34: "12",
            35: payload_time,
            36: "3",
            41: "Thailand",
            42: "Singapore",
            44: "7",
            45: "5",
            46: "aged-out",
            52: "SYNTHETIC-FW",
            53: "from-policy",
            65: "00000000-0000-4000-8000-000000000051",
            105: event_time.isoformat(),
            108: "encrypted-tunnel",
            109: "networking",
            110: "browser-based",
            111: "2",
            112: "pervasive-use",
        }.items():
            if index < field_count:
                fields[index] = value
    elif log_type == "THREAT":
        for index, value in {
            32: "Synthetic Threat Signature(551)",
            33: "synthetic-category",
            34: "high",
            35: "client-to-server",
            38: "Thailand",
            39: "Singapore",
            59: "SYNTHETIC-FW",
            69: "threat",
            76: "00000000-0000-4000-8000-000000000052",
            110: event_time.isoformat(),
            114: "internet-utility",
            115: "general-internet",
            116: "network-protocol",
            117: "4",
            118: "used-by-malware",
        }.items():
            if index < field_count:
                fields[index] = value
    elif log_type == "SYSTEM":
        for index, value in {
            7: "vsys1",
            8: "auth-success",
            9: "local-admin",
            12: "auth",
            13: "informational",
            14: "Synthetic authentication event",
            22: "SYNTHETIC-FW",
            25: event_time.isoformat(),
        }.items():
            if index < field_count:
                fields[index] = value

    return f"{event_time.isoformat()} synthetic-fw.example.invalid {','.join(fields)}"


def _write_supported_sample(path: Path, *, rows_per_type: int = 2) -> list[str]:
    started = qualification.FRESH_EVIDENCE_NOT_BEFORE + timedelta(days=1)
    lines: list[str] = []
    layouts = (("TRAFFIC", 115), ("THREAT", 121), ("SYSTEM", 26))
    for index, (log_type, field_count) in enumerate(layouts):
        for offset in range(rows_per_type):
            lines.append(
                _panos_line(
                    log_type,
                    field_count=field_count,
                    event_time=started + timedelta(minutes=(index * 10) + offset),
                )
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def test_v551_supported_parser_fixtures_cover_traffic_threat_and_system() -> None:
    event_time = qualification.FRESH_EVIDENCE_NOT_BEFORE + timedelta(days=1)
    traffic = parse_log_line(_panos_line("TRAFFIC", field_count=115, event_time=event_time))
    threat = parse_log_line(_panos_line("THREAT", field_count=121, event_time=event_time))
    system = parse_log_line(_panos_line("SYSTEM", field_count=26, event_time=event_time))

    assert traffic.error is None
    assert traffic.parsed_json["parser_compatibility"]["status"] == "supported_known_layout"
    assert traffic.normalized["app"] == "ssl"
    assert traffic.normalized["dst_port"] == 443
    assert traffic.normalized["app_risk"] == 2
    assert threat.error is None
    assert threat.parsed_json["parser_compatibility"]["status"] == "supported_known_layout"
    assert threat.parsed_json["parsed_threat_severity"] == "high"
    assert threat.normalized["app_risk"] == 4
    assert system.error is None
    assert system.parsed_json["parser_compatibility"]["status"] == "supported_known_layout"
    assert system.parsed_json["system_event_id"] == "auth-success"
    assert system.parsed_json["system_module"] == "auth"


def test_v551_parser_fixture_detects_extended_partial_and_unsupported_layouts() -> None:
    event_time = qualification.FRESH_EVIDENCE_NOT_BEFORE + timedelta(days=1)
    extended = parse_log_line(_panos_line("TRAFFIC", field_count=116, event_time=event_time))
    partial = parse_log_line(_panos_line("TRAFFIC", field_count=30, event_time=event_time))
    unsupported = parse_log_line(_panos_line("CONFIG", field_count=40, event_time=event_time))

    assert extended.parsed_json["parser_compatibility"]["status"] == "supported_extended_layout"
    assert extended.normalized["app_risk"] == 2
    assert partial.parsed_json["parser_compatibility"]["status"] == "partial_layout"
    assert partial.parsed_json["parse_status"] == "partial"
    assert unsupported.parsed_json["parser_compatibility"]["status"] == "unsupported_log_type"
    assert unsupported.parsed_json["parse_status"] == "partial"


def test_v551_field_expectations_are_human_confirmed_and_aggregate_only(tmp_path: Path) -> None:
    sample = tmp_path / "private-field-sample.txt"
    _write_supported_sample(sample, rows_per_type=1)
    analysis = qualification._analyze_sample(sample, max_rows=10, review_limit=0)
    expectations = tmp_path / "private-field-expectations.json"
    expectations.write_text(
        json.dumps(
            {
                "schema_version": "v5.51-field-expectations-v1",
                "source_name": "physical-firewall-a",
                "reviewed_by": "Human Analyst",
                "reviewed_at": "2026-09-02T08:00:00+07:00",
                "independent_human_confirmed": True,
                "rows": [
                    {
                        "line_number": 1,
                        "expected": {
                            "log_type": "TRAFFIC",
                            "app": "ssl",
                            "action": "allow",
                            "protocol": "tcp",
                            "dst_port": 443,
                            "app_risk": 2,
                            "generated_time_present": True,
                            "high_res_timestamp_present": True,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = qualification._validate_field_expectations(
        expectations,
        source_name="physical-firewall-a",
        parsed_by_line=analysis["parsed_by_line"],
    )

    assert result["valid"] is True
    assert result["fields_checked"] == 8
    assert result["fields_mismatched"] == 0
    assert result["accuracy"] == 1.0
    assert result["values_returned"] is False
    assert result["identity_returned"] is False


def test_v551_source_attestation_rejects_ai_and_pre_boundary_claims(tmp_path: Path) -> None:
    path = tmp_path / "attestation.json"
    base = {
        "schema_version": "v5.51-source-attestation-v1",
        "source_name": "physical-firewall-a",
        "source_kind": "firewall",
        "collection_window": "window-a",
        "physical_device_confirmed": True,
        "attested_by": "Human Analyst",
        "attested_at": "2026-09-02T08:00:00+07:00",
        "collection_started_at": "2026-09-02T07:00:00+07:00",
    }
    path.write_text(json.dumps(base), encoding="utf-8")
    assert qualification._validate_source_attestation(
        path,
        source_name="physical-firewall-a",
        collection_window="window-a",
        source_kind="firewall",
    )["valid"] is True

    path.write_text(
        json.dumps({key: value for key, value in base.items() if key != "schema_version"}),
        encoding="utf-8",
    )
    assert qualification._validate_source_attestation(
        path,
        source_name="physical-firewall-a",
        collection_window="window-a",
        source_kind="firewall",
    )["valid"] is False

    path.write_text(json.dumps({**base, "attested_by": "Codex"}), encoding="utf-8")
    assert qualification._validate_source_attestation(
        path,
        source_name="physical-firewall-a",
        collection_window="window-a",
        source_kind="firewall",
    )["valid"] is False

    path.write_text(
        json.dumps({**base, "collection_started_at": "2026-08-31T08:00:00+07:00"}),
        encoding="utf-8",
    )
    assert qualification._validate_source_attestation(
        path,
        source_name="physical-firewall-a",
        collection_window="window-a",
        source_kind="firewall",
    )["valid"] is False


def test_v551_fresh_roles_exclude_old_rows_and_contain_duplicate_families() -> None:
    started = qualification.FRESH_EVIDENCE_NOT_BEFORE + timedelta(hours=1)
    records = [
        {
            "event_time": (started + timedelta(minutes=index)).isoformat(),
            "exact_hash": f"exact-{index}",
            "near_hash": f"near-{index // 3}",
        }
        for index in range(300)
    ]
    records.append(dict(records[0]))
    records.append(
        {
            "event_time": (qualification.FRESH_EVIDENCE_NOT_BEFORE - timedelta(minutes=1)).isoformat(),
            "exact_hash": "protected-era-row",
            "near_hash": "protected-era-family",
        }
    )

    result = qualification.role_partition_for_records(records)

    assert result["protected_v549b_accessed"] is False
    assert result["v549b_overlap_rows_admitted"] == 0
    assert result["temporal_namespace_disjoint"] is True
    assert result["fresh_rows"] == 300
    assert result["exact_duplicate_rows_excluded"] == 1
    assert result["cross_role_exact_duplicate_count"] == 0
    assert result["cross_role_near_duplicate_count"] == 0
    assert result["duplicate_families_contained"] is True
    assert result["roles"]["untouched_future_evaluation"]["labels_opened"] is False
    assert result["future_labels_opened"] is False


def test_v551_prediction_blind_review_yields_metrics_without_import(tmp_path: Path) -> None:
    seals = [
        {
            "review_token": f"review-{index:03d}",
            "rule_alert_eligible": index % 4 in {0, 1},
            "rule_codes": ["synthetic_rule"],
            "rule_score": 50,
        }
        for index in range(40)
    ]
    path = tmp_path / "completed-review.csv"
    fieldnames = [
        "review_token",
        "human_decision",
        "human_confidence",
        "human_rationale",
        "human_attack_type",
        "human_reviewer",
        "human_reviewed_at",
        "independent_human_confirmed",
        "human_must_confirm",
        "human_reviewed",
        "prediction_blind",
        "import_ready",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for index, seal in enumerate(seals):
            threat = index % 4 == 0
            writer.writerow(
                {
                    "review_token": seal["review_token"],
                    "human_decision": "malicious" if threat else "benign",
                    "human_confidence": 90,
                    "human_rationale": "Independent evidence supports this decision.",
                    "human_attack_type": "unknown_anomaly" if threat else "normal",
                    "human_reviewer": "Human Analyst",
                    "human_reviewed_at": "2026-09-03T10:00:00+07:00",
                    "independent_human_confirmed": True,
                    "human_must_confirm": True,
                    "human_reviewed": True,
                    "prediction_blind": True,
                    "import_ready": False,
                }
            )

    result = qualification._validate_rule_review(path, seals=seals)

    assert result["complete"] is True
    assert result["reviewed_rows"] == 40
    assert result["metrics_available"] is True
    assert result["true_positives"] == 10
    assert result["false_positives"] == 10
    assert result["false_negatives"] == 0
    assert result["predictions_exposed"] is False


def test_v551_threat_review_requires_attack_type(tmp_path: Path) -> None:
    seals = [
        {
            "review_token": f"review-{index:03d}",
            "rule_alert_eligible": True,
            "rule_codes": ["synthetic_rule"],
            "rule_score": 50,
        }
        for index in range(40)
    ]
    path = tmp_path / "invalid-threat-review.csv"
    fieldnames = [
        "review_token",
        "human_decision",
        "human_confidence",
        "human_rationale",
        "human_attack_type",
        "human_reviewer",
        "human_reviewed_at",
        "independent_human_confirmed",
        "human_must_confirm",
        "human_reviewed",
        "prediction_blind",
        "import_ready",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for seal in seals:
            writer.writerow(
                {
                    "review_token": seal["review_token"],
                    "human_decision": "suspicious",
                    "human_confidence": 90,
                    "human_rationale": "Independent evidence supports this decision.",
                    "human_attack_type": "",
                    "human_reviewer": "Human Analyst",
                    "human_reviewed_at": "2026-09-03T10:00:00+07:00",
                    "independent_human_confirmed": True,
                    "human_must_confirm": True,
                    "human_reviewed": True,
                    "prediction_blind": True,
                    "import_ready": False,
                }
            )

    result = qualification._validate_rule_review(path, seals=seals)

    assert result["complete"] is False
    assert result["reviewed_rows"] == 0
    assert result["invalid_rows"] == 40
    assert result["metrics_available"] is False


def test_v551_preflight_and_local_run_are_redacted_and_conservative(
    tmp_path: Path,
    monkeypatch,
) -> None:
    sample = tmp_path / "private-campus-firewall.txt"
    _write_supported_sample(sample, rows_per_type=2)
    configured_database = tmp_path / "configured.sqlite3"
    sentinel = b"v551-configured-database-sentinel"
    configured_database.write_bytes(sentinel)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{configured_database.as_posix()}")
    get_settings.cache_clear()
    try:
        preflight = qualification.run_v551_field_qualification(
            use_temp_db=True,
            sample_path=sample,
            preflight_only=True,
            output_dir=tmp_path / "preflight-output",
            write_output=False,
        )
        result = qualification.run_v551_field_qualification(
            use_temp_db=True,
            sample_path=sample,
            max_rows=20,
            review_limit=6,
            output_dir=tmp_path / "output",
            write_output=True,
        )
    finally:
        get_settings.cache_clear()

    serialized = json.dumps({"preflight": preflight, "result": result})
    assert preflight["ok"] is True
    assert preflight["status"] == "hardware_required"
    assert result["ok"] is True
    assert result["status"] == "hardware_required"
    assert result["parser"]["log_type_counts"] == {"SYSTEM": 2, "THREAT": 2, "TRAFFIC": 2}
    assert result["parser"]["rows_accounted"] is True
    assert result["rule_review"]["pack_created"] is True
    assert result["rule_review"]["import_ready"] is False
    assert result["fresh_evidence"]["protected_v549b_accessed"] is False
    assert result["configured_database_modified"] is False
    assert result["labels_written"] == 0
    assert result["alerts_written"] == 0
    assert result["detection_runs_written"] == 0
    assert result["response_actions_written"] == 0
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert configured_database.read_bytes() == sentinel
    assert str(sample) not in serialized
    assert sample.name not in serialized
    assert "198.51.100.51" not in serialized
    assert "203.0.113.51" not in serialized
    assert "raw_line" not in serialized
    assert "exact_hash" not in serialized
    assert result["private_paths_exposed"] is False
    assert result["ip_addresses_exposed"] is False
    assert result["fingerprints_exposed"] is False
    assert result["secrets_exposed"] is False


def test_v551_public_status_default_is_safe_and_hardware_required(tmp_path: Path) -> None:
    result = qualification.get_public_v551_status(output_dir=tmp_path)

    assert result["status"] == "hardware_required"
    assert result["fresh_evidence"]["protected_v549b_accessed"] is False
    assert result["model_activated"] is False
    assert result["response_automation_allowed"] is False
    assert result["raw_logs_exposed"] is False
    assert result["private_paths_exposed"] is False
