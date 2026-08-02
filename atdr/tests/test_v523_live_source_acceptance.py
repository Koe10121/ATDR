from __future__ import annotations

import json
from pathlib import Path

from atdr.app.core.config import get_settings
from atdr.app.services import v523_live_source_acceptance_service as acceptance


SCENARIO_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "samples"
    / "scenarios"
    / "port_scan_like_traffic.txt"
)


def test_v523_requires_disposable_database_and_external_attestation() -> None:
    without_temp = acceptance.run_v523_live_source_acceptance(
        use_temp_db=False,
        write_output=False,
    )
    without_attestation = acceptance.run_v523_live_source_acceptance(
        use_temp_db=True,
        transport_mode="external_sender",
        external_sender_kind=None,
        write_output=False,
    )

    assert without_temp["ok"] is False
    assert without_temp["status"] == "explicit_temp_database_required"
    assert without_temp["configured_database_modified"] is False
    assert without_attestation["ok"] is False
    assert without_attestation["status"] == "external_sender_attestation_required"
    assert without_attestation["real_device_validated"] is False


def test_v523_preflight_redacts_private_sample_path(tmp_path: Path) -> None:
    private_sample = tmp_path / "private-campus-firewall.log"
    private_sample.write_bytes(SCENARIO_PATH.read_bytes())

    result = acceptance.run_v523_live_source_acceptance(
        use_temp_db=True,
        sample_path=private_sample,
        preflight_only=True,
        write_output=False,
    )
    serialized = json.dumps(result)

    assert result["ok"] is True
    assert result["status"] == "preflight_passed"
    assert result["preflight"]["private_sample_supplied"] is True
    assert str(private_sample) not in serialized
    assert private_sample.name not in serialized
    assert result["private_path_returned"] is False
    assert result["raw_evidence_returned"] is False
    assert result["secrets_exposed"] is False


def test_v523_local_acceptance_covers_channels_and_preserves_configured_database(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configured_database = tmp_path / "configured.sqlite3"
    sentinel = b"v523-configured-database-sentinel"
    configured_database.write_bytes(sentinel)
    private_sample = tmp_path / "private-panos-evidence.log"
    private_sample.write_bytes(SCENARIO_PATH.read_bytes())
    report_dir = tmp_path / "reports"
    monkeypatch.setenv(
        "DATABASE_URL",
        f"sqlite:///{configured_database.as_posix()}",
    )
    get_settings.cache_clear()
    try:
        result = acceptance.run_v523_live_source_acceptance(
            use_temp_db=True,
            sample_path=private_sample,
            transport_mode="local_loopback",
            message_count=5,
            timeout_seconds=10,
            temp_parent=tmp_path,
            output_dir=report_dir,
            write_output=True,
        )
    finally:
        get_settings.cache_clear()

    serialized = json.dumps(result, sort_keys=True)
    report = json.loads(
        (report_dir / acceptance.V523_LATEST).read_text(encoding="utf-8")
    )

    assert result["ok"] is True
    assert result["failed_checks"] == []
    assert all(result["checks"].values())
    assert result["channels"]["file_import"]["raw_logs_imported"] == 20
    assert result["channels"]["api_upload"]["raw_logs_imported"] == 5
    assert result["channels"]["resumable_import"]["backpressure_enforced"] is True
    assert result["channels"]["resumable_import"]["resume_completed"] is True
    assert result["channels"]["replay_udp"]["messages_received"] == 5
    assert result["scope"]["local_loopback_transport_validated"] is True
    assert result["scope"]["second_laptop_transport_validated"] is False
    assert result["phase_complete"] is False
    assert result["external_transport_gate"]["satisfied"] is False
    assert result["real_device_validated"] is False

    assert result["detection"]["rules_alert_authoritative"] is True
    assert result["detection"]["ml_alert_authority"] is False
    assert result["detection"]["first_created"] == 1
    assert result["detection"]["second_deduplicated"] == 1
    assert result["detection"]["occurrence_count"] >= 20
    assert result["detection"]["related_log_count"] >= 20
    assert all(result["investigation"].values())
    assert result["audit"]["required_actions_present"] is True

    counts = result["counts"]
    assert counts["response_actions"] == 0
    assert counts["labels"] == 0
    assert counts["model_runs"] == 0
    assert counts["users"] == 0
    assert result["response_automation_allowed"] is False
    assert result["real_firewall_blocking_enabled"] is False
    assert result["configured_database_modified"] is False
    assert configured_database.read_bytes() == sentinel
    assert result["temporary_artifacts_removed"] is True

    assert report["status"] == result["status"]
    assert report["failed_checks"] == []
    assert str(private_sample) not in serialized
    assert private_sample.name not in serialized
    assert "203.0.113.44" not in serialized
    assert "198.51.100." not in serialized
    assert "raw_line" not in serialized
    assert result["private_path_returned"] is False
    assert result["raw_evidence_returned"] is False
    assert result["sender_addresses_returned"] is False
    assert result["secrets_exposed"] is False


def test_v523_external_sender_classification_never_overclaims_device_validation(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        acceptance,
        "run_udp_syslog_receiver",
        lambda **_kwargs: {
            "received": 5,
            "parsed": 5,
            "failed": 0,
            "timed_out": False,
            "sender_count": 1,
            "non_loopback_sender_observed": True,
        },
    )

    laptop = acceptance._run_udp_transport(
        session_factory=lambda: None,
        sample_path=SCENARIO_PATH,
        transport_mode="external_sender",
        bind_host="0.0.0.0",
        port=5515,
        message_count=5,
        timeout_seconds=1,
        external_sender_kind="second_laptop",
    )
    firewall = acceptance._run_udp_transport(
        session_factory=lambda: None,
        sample_path=SCENARIO_PATH,
        transport_mode="external_sender",
        bind_host="0.0.0.0",
        port=5515,
        message_count=5,
        timeout_seconds=1,
        external_sender_kind="firewall",
    )

    assert laptop["passed"] is True
    assert laptop["second_laptop_transport_validated"] is True
    assert laptop["real_device_validated"] is False
    assert firewall["passed"] is True
    assert firewall["second_laptop_transport_validated"] is False
    assert firewall["real_device_validated"] is True
    assert firewall["sender_addresses_returned"] is False
