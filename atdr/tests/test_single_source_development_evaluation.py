from pathlib import Path

import pytest

from atdr.app.detection import single_source_development_evaluation as sse
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.detection import v563_fresh_evidence_expansion as v563
from atdr.app.detection import v565_extended_evidence_expansion as v565
from atdr.app.detection import v567_signal_concentrated_evidence_expansion as v567


def _row(
    *,
    role: str,
    event_time: str,
    reviewed: bool,
    decision: str = "",
    source_zone: str = "untrust",
    destination_zone: str = "trust",
    source_port: str = "40000",
    destination_port: str = "443",
    application: str = "ssl",
) -> dict:
    return {
        "evidence_role": role,
        "event_time_utc": event_time,
        "log_type": "TRAFFIC",
        "subtype": "end",
        "application": application,
        "action": "allow",
        "protocol": "tcp",
        "source_port": source_port,
        "destination_port": destination_port,
        "source_zone": source_zone,
        "destination_zone": destination_zone,
        "bytes": "1000",
        "packets": "10",
        "elapsed_time": "1",
        "application_risk": "2",
        "threat_severity": "",
        "session_end_reason": "aged-out",
        "parser_error": "",
        "parser_warning_count": "0",
        "required_missing_count": "0",
        "schema_bucket": "structured",
        "group_size": "1",
        "source_event_count": "5",
        "source_deny_count": "0",
        "source_unique_destinations": "2",
        "source_unique_ports": "2",
        "source_unknown_app_count": "0",
        "source_high_risk_app_count": "0",
        "destination_repeat_count": "1",
        "human_reviewed": "true" if reviewed else "false",
        "human_decision": decision,
    }


def _write_working_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    v562._atomic_write_csv(path, rows)


@pytest.fixture(autouse=True)
def _bypass_lock_file_validation(monkeypatch):
    # These tests exercise the actual row-loading/feature/training logic
    # against a synthetic working CSV, without replicating the full
    # protocol-lock-file machinery, which is already covered by v562/v563's
    # own test suites.
    monkeypatch.setattr(v562, "validate_campaign_protocol", lambda *_a, **_k: {})
    monkeypatch.setattr(v563, "validate_expansion_protocol", lambda *_a, **_k: {})
    monkeypatch.setattr(v565, "validate_extended_protocol", lambda *_a, **_k: {})
    monkeypatch.setattr(v567, "validate_signal_protocol", lambda *_a, **_k: {})


def test_status_reports_insufficient_data_when_nothing_reviewed(tmp_path):
    v562_dir = tmp_path / "v562"
    _write_working_csv(
        v562_dir / v562.V562_WORKING_COPY,
        [_row(role="development_fit", event_time="2026-05-01T00:00:00Z", reviewed=False)],
    )

    status = sse.evaluation_status(
        v562_output_dir=v562_dir,
        v563_output_dir=tmp_path / "v563",
        v565_output_dir=tmp_path / "v565",
        v567_output_dir=tmp_path / "v567",
    )

    assert status["readiness"]["ready"] is False
    assert status["counts"]["total_reviewed_development_rows"] == 0
    assert status["qualification_decision"] is False
    assert status["single_source_only"] is True


def test_sealed_evaluation_role_is_never_loaded_even_if_marked_reviewed(tmp_path):
    # Defense in depth: even if a sealed row were somehow marked reviewed
    # (which the official service should never allow), this module must
    # still refuse to load it.
    v562_dir = tmp_path / "v562"
    _write_working_csv(
        v562_dir / v562.V562_WORKING_COPY,
        [
            _row(
                role="untouched_future_evaluation",
                event_time="2026-05-01T00:00:00Z",
                reviewed=True,
                decision="malicious",
            )
        ],
    )

    status = sse.evaluation_status(
        v562_output_dir=v562_dir,
        v563_output_dir=tmp_path / "v563",
        v565_output_dir=tmp_path / "v565",
        v567_output_dir=tmp_path / "v567",
    )

    assert status["counts"]["total_reviewed_development_rows"] == 0
    assert status["sealed_evaluation_role_accessed"] is False


def test_run_refuses_without_use_temp_db_acknowledgement():
    with pytest.raises(sse.SingleSourceDevelopmentEvaluationError) as excinfo:
        sse.run_single_source_development_evaluation(use_temp_db=False)
    assert excinfo.value.code == "disposable_acknowledgement_required"


def _synthetic_reviewed_rows() -> list[dict]:
    rows = []
    # development_fit: training rows, chronologically first.
    for index in range(16):
        rows.append(
            _row(
                role="development_fit",
                event_time=f"2026-05-01T00:{index:02d}:00Z",
                reviewed=True,
                decision="benign" if index % 2 == 0 else "malicious",
                source_zone="untrust" if index % 2 else "trust",
                destination_zone="trust" if index % 2 else "untrust",
                destination_port="443" if index % 2 == 0 else "4444",
                application="ssl" if index % 2 == 0 else "unknown",
            )
        )
    # calibration + threshold_selection: development-test rows, later in time.
    for index in range(10):
        role = "calibration" if index % 2 == 0 else "threshold_selection"
        rows.append(
            _row(
                role=role,
                event_time=f"2026-05-02T00:{index:02d}:00Z",
                reviewed=True,
                decision="benign" if index % 2 == 0 else "malicious",
                source_zone="untrust" if index % 2 else "trust",
                destination_zone="trust" if index % 2 else "untrust",
                destination_port="443" if index % 2 == 0 else "4444",
                application="ssl" if index % 2 == 0 else "unknown",
            )
        )
    # A sealed row that must never influence anything.
    rows.append(
        _row(
            role="untouched_future_evaluation",
            event_time="2026-05-03T00:00:00Z",
            reviewed=True,
            decision="malicious",
        )
    )
    return rows


def test_run_produces_honest_development_signal_and_never_touches_sealed_role(tmp_path):
    v562_dir = tmp_path / "v562"
    _write_working_csv(v562_dir / v562.V562_WORKING_COPY, _synthetic_reviewed_rows())

    result = sse.run_single_source_development_evaluation(
        use_temp_db=True,
        v562_output_dir=v562_dir,
        v563_output_dir=tmp_path / "v563",
        v565_output_dir=tmp_path / "v565",
        v567_output_dir=tmp_path / "v567",
    )

    assert result["status"] == "development_signal_measured"
    assert result["executed"] is True
    # 26 reviewed development rows total, none from the sealed role.
    assert result["counts"]["total_reviewed_development_rows"] == 26
    assert result["split"]["train_role"] == "development_fit"
    assert result["split"]["train_rows"] == 16
    assert result["split"]["test_rows"] == 10
    assert set(result["split"]["test_roles"]) <= {"calibration", "threshold_selection"}
    assert "development_metrics" in result
    assert result["development_metrics"]["labels"] == ["benign_like", "threat_positive"]

    # The mandatory, structural disclosure fields -- these must never be
    # something a result can suppress or override.
    assert result["qualification_decision"] is False
    assert result["single_source_only"] is True
    assert result["cross_device_generalization_established"] is False
    assert result["sealed_evaluation_role_accessed"] is False
    assert result["database_writes"] == 0
    assert result["model_artifact_written"] is False
    assert result["model_activated"] is False


def test_v565_reviewed_rows_are_included_in_the_combined_development_pool(tmp_path):
    v562_dir = tmp_path / "v562"
    v565_dir = tmp_path / "v565"
    _write_working_csv(
        v562_dir / v562.V562_WORKING_COPY,
        [_row(role="development_fit", event_time="2026-05-01T00:00:00Z", reviewed=True, decision="benign")],
    )
    _write_working_csv(
        v565_dir / v565.V565_WORKING_COPY,
        [
            _row(role="development_fit", event_time="2026-05-04T00:00:00Z", reviewed=True, decision="malicious"),
            _row(role="calibration", event_time="2026-05-05T00:00:00Z", reviewed=True, decision="benign"),
        ],
    )

    status = sse.evaluation_status(
        v562_output_dir=v562_dir,
        v563_output_dir=tmp_path / "v563",
        v565_output_dir=v565_dir,
        v567_output_dir=tmp_path / "v567",
    )

    assert status["counts"]["total_reviewed_development_rows"] == 3
    assert status["counts"]["benign_like"] == 2
    assert status["counts"]["threat_positive"] == 1


def test_v567_reviewed_rows_are_included_in_the_combined_development_pool(tmp_path):
    v562_dir = tmp_path / "v562"
    v567_dir = tmp_path / "v567"
    _write_working_csv(
        v562_dir / v562.V562_WORKING_COPY,
        [_row(role="development_fit", event_time="2026-05-01T00:00:00Z", reviewed=True, decision="benign")],
    )
    _write_working_csv(
        v567_dir / v567.V567_WORKING_COPY,
        [
            _row(role="development_fit", event_time="2026-06-01T00:00:00Z", reviewed=True, decision="suspicious"),
            _row(role="calibration", event_time="2026-06-02T00:00:00Z", reviewed=True, decision="benign"),
        ],
    )

    status = sse.evaluation_status(
        v562_output_dir=v562_dir,
        v563_output_dir=tmp_path / "v563",
        v565_output_dir=tmp_path / "v565",
        v567_output_dir=v567_dir,
    )

    assert status["counts"]["total_reviewed_development_rows"] == 3
    assert status["counts"]["benign_like"] == 2
    assert status["counts"]["threat_positive"] == 1


def test_run_reports_insufficient_role_split_when_all_reviews_are_in_one_role(tmp_path):
    v562_dir = tmp_path / "v562"
    rows = [
        _row(role="development_fit", event_time=f"2026-05-01T00:{i:02d}:00Z", reviewed=True, decision="benign")
        for i in range(10)
    ] + [
        _row(role="development_fit", event_time=f"2026-05-01T01:{i:02d}:00Z", reviewed=True, decision="malicious")
        for i in range(10)
    ]
    _write_working_csv(v562_dir / v562.V562_WORKING_COPY, rows)

    result = sse.run_single_source_development_evaluation(
        use_temp_db=True,
        v562_output_dir=v562_dir,
        v563_output_dir=tmp_path / "v563",
        v565_output_dir=tmp_path / "v565",
        v567_output_dir=tmp_path / "v567",
    )

    assert result["status"] == "insufficient_role_split"
    assert result["executed"] is False
