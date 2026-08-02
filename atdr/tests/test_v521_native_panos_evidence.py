from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from atdr.app.detection import v521_native_panos_evidence as evidence


def _chronological_sample(path: Path, *, rows: int = 96) -> None:
    template = Path("data/samples/paloalto-demo.txt").read_text(
        encoding="utf-8"
    ).splitlines()[0]
    started = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
    output: list[str] = []
    for index in range(rows):
        value = started + timedelta(minutes=index)
        syslog = value.isoformat()
        payload_time = value.strftime("%Y/%m/%d %H:%M:%S")
        _, hostname, payload = template.split(" ", 2)
        fields = payload.split(",")
        fields[1] = payload_time
        fields[6] = payload_time
        fields[7] = f"198.51.100.{(index % 200) + 1}"
        fields[8] = f"203.0.113.{(index % 200) + 1}"
        output.append(f"{syslog} {hostname} {','.join(fields)}")
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def _csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def test_official_field_contract_uses_primary_vendor_sources() -> None:
    contract = evidence.official_panos_field_contract()

    assert contract["source_type"] == "official_vendor_documentation"
    assert len(contract["primary_sources"]) >= 3
    assert all(
        item["url"].startswith("https://docs.paloaltonetworks.com/")
        for item in contract["primary_sources"]
    )
    assert "not malicious ground truth" in contract["traffic"]["semantic_limit"]
    assert "analyst context" in contract["threat"]["semantic_limit"]


def test_runner_fails_closed_without_disposable_acknowledgement(tmp_path: Path) -> None:
    sample = tmp_path / "private.log"
    _chronological_sample(sample)

    result = evidence.run_v521_native_panos_evidence(
        sample_path=sample,
        use_temp_db=False,
        output_dir=tmp_path / "outputs",
    )

    serialized = json.dumps(result)
    assert result["ok"] is False
    assert result["status"] == "failed_closed_temp_db_acknowledgement_required"
    assert result["configured_database_accessed"] is False
    assert str(sample) not in serialized


def test_native_roles_and_review_packs_are_private_and_non_importable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sample = tmp_path / "private.log"
    output = tmp_path / "ignored-output"
    _chronological_sample(sample)
    configured_path_requests: list[str | None] = []

    def _configured_path_guard(database_url: str | None = None):
        configured_path_requests.append(database_url)
        assert database_url == "sqlite:///:memory:"
        return None

    monkeypatch.setattr(
        evidence.v56,
        "_configured_sqlite_path",
        _configured_path_guard,
    )

    result = evidence.run_v521_native_panos_evidence(
        sample_path=sample,
        use_temp_db=True,
        review_limit=48,
        output_dir=output,
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["status"] == "native_panos_evidence_roles_locked"
    assert result["source_evidence"]["rows_processed"] == 96
    assert result["source_evidence"]["configured_database_overlap_rows"] == 0
    assert result["source_evidence"]["configured_database_overlap_checked"] is False
    assert configured_path_requests == ["sqlite:///:memory:"]
    assert result["duplicate_families_contained"] is True
    assert result["exact_family_cross_role_count"] == 0
    assert result["near_family_cross_role_count"] == 0
    assert result["quarantine"]["raw_evidence_included"] is False
    assert result["quarantine"]["private_identifiers_included"] is False
    assert sum(
        item["rows"] for item in result["quarantine"]["reasons"]
    ) == result["quarantine"]["rows"]
    assert all(
        result["evidence_roles"][role]["rows"] > 0
        for role in (
            "development_fit",
            "calibration",
            "threshold",
            "untouched_future_validation",
        )
    )
    assert result["safety"]["configured_database_accessed"] is False
    assert result["safety"]["configured_database_written"] is False
    assert result["safety"]["labels_written"] == 0
    assert result["safety"]["model_artifact_written"] is False
    assert result["safety"]["model_activated"] is False
    assert result["safety"]["response_actions_created"] == 0
    assert str(sample) not in serialized
    assert sample.name not in serialized
    assert "198.51.100." not in serialized
    assert "203.0.113." not in serialized
    assert "source_file_sha256" not in serialized

    development = _csv_rows(output / evidence.V521_DEVELOPMENT_PACK)
    blind = _csv_rows(output / evidence.V521_BLIND_PACK)
    assert development
    assert blind
    assert all(row["suggestion_is_weak"] == "True" for row in development)
    assert all(row["human_reviewed"] == "False" for row in development)
    assert all(row["human_must_confirm"] == "True" for row in development)
    assert all(row["import_ready"] == "False" for row in development)
    assert all(row["evidence_role_is_blind"] == "False" for row in development)
    assert all(
        row["evidence_role"] != "untouched_future_validation"
        for row in development
    )

    suggestion_fields = (
        "assisted_suggestion",
        "assisted_attack_type",
        "assisted_confidence",
        "assisted_reason",
        "assisted_provenance",
        "rule_codes",
        "rule_score",
    )
    assert all(row["blind_suggestion_suppressed"] == "True" for row in blind)
    assert all(row["human_reviewed"] == "False" for row in blind)
    assert all(row["human_must_confirm"] == "True" for row in blind)
    assert all(row["import_ready"] == "False" for row in blind)
    assert all(
        row["evidence_role"] == "untouched_future_validation"
        for row in blind
    )
    assert all(not row[field] for row in blind for field in suggestion_fields)

    forbidden_columns = {
        "raw_line",
        "raw_log",
        "src_ip",
        "dst_ip",
        "source_ip",
        "destination_ip",
        "sample_path",
        "source_path",
        "exact_hash",
        "propagation_hash",
    }
    assert forbidden_columns.isdisjoint(development[0])
    assert forbidden_columns.isdisjoint(blind[0])

    manifest_path = output / evidence.V521_MANIFEST_LATEST
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert manifest["source_path_recorded"] is False
    assert manifest["source_file_name_recorded"] is False
    assert manifest["blind_suggestions_generated"] is False
    assert manifest["blind_decisions_opened"] is False
    assert manifest["human_reviewed_rows_created"] == 0
    assert manifest["configured_database_accessed"] is False
    assert str(sample) not in manifest_text
    assert sample.name not in manifest_text
    assert "198.51.100." not in manifest_text


def test_preflight_writes_no_review_pack_or_human_label(tmp_path: Path) -> None:
    sample = tmp_path / "private.log"
    output = tmp_path / "ignored-output"
    _chronological_sample(sample)

    result = evidence.run_v521_native_panos_evidence(
        sample_path=sample,
        use_temp_db=True,
        preflight_only=True,
        output_dir=output,
    )

    assert result["ok"] is True
    assert result["status"] == "native_panos_preflight_complete"
    assert result["review_packs"]["development_rows"] == 0
    assert result["review_packs"]["blind_rows"] == 0
    assert result["review_packs"]["human_reviewed_rows_created"] == 0
    assert not (output / evidence.V521_DEVELOPMENT_PACK).exists()
    assert not (output / evidence.V521_BLIND_PACK).exists()
    assert result["evidence_sufficiency"]["enough_for_activation_or_production_claim"] is False


def test_missing_private_file_returns_redacted_failure(tmp_path: Path) -> None:
    missing = tmp_path / "secret-private-file.log"

    result = evidence.run_v521_native_panos_evidence(
        sample_path=missing,
        use_temp_db=True,
        output_dir=tmp_path / "outputs",
    )

    serialized = json.dumps(result)
    assert result["ok"] is False
    assert result["status"] == "private_evidence_unavailable"
    assert str(missing) not in serialized
    assert missing.name not in serialized
    assert result["configured_database_accessed"] is False
