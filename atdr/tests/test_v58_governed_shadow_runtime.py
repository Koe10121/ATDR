from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import joblib
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    AlertEvidence,
    DetectionRun,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    RawLog,
    ResponseAction,
)
from atdr.app.detection import v56_private_panos_model_repair as v56
from atdr.app.detection import v57_independent_shadow_revalidation as v57
from atdr.app.services import v58_shadow_scoring_service as v58


class HistGradientBoostingClassifier:
    pass


class _FrozenCandidatePipeline:
    method = "sigmoid"
    classes_ = ["needs_review", "non_threat"]
    feature_names_in_ = [
        *v56.V56_NUMERIC_FEATURES,
        *v56.V56_CATEGORICAL_FEATURES,
    ]
    estimator = SimpleNamespace(
        steps=[
            ("preprocess", SimpleNamespace()),
            ("model", HistGradientBoostingClassifier()),
        ]
    )

    def predict_proba(self, frame):
        return [[0.8, 0.2] for _ in range(len(frame))]


def _session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )


@pytest.fixture(autouse=True)
def _reset_runtime_state():
    get_settings.cache_clear()
    v58.clear_shadow_runtime_cache()
    yield
    get_settings.cache_clear()
    v58.clear_shadow_runtime_cache()


def _configure_shadow(monkeypatch, *, enabled: bool = True) -> None:
    monkeypatch.setenv(
        "GOVERNED_SHADOW_SCORING_ENABLED",
        "true" if enabled else "false",
    )
    monkeypatch.setenv("GOVERNED_SHADOW_BATCH_SIZE", "20")
    monkeypatch.setenv("GOVERNED_SHADOW_MAX_BATCH_SIZE", "25")
    monkeypatch.setenv("GOVERNED_SHADOW_TIMEOUT_SECONDS", "10")
    monkeypatch.setenv("GOVERNED_SHADOW_CACHE_SECONDS", "60")
    get_settings.cache_clear()


def _write_candidate_contract(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    pipeline = _FrozenCandidatePipeline()
    artifact_name = "v58-test-candidate.joblib"
    artifact_path = output_dir / artifact_name
    joblib.dump(
        {
            "pipeline": pipeline,
            "candidate_name": "calibrated_hist_gradient_boosting",
            "version": v56.V56_VERSION,
            "threshold": 0.3,
            "active": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
        artifact_path,
    )
    manifest = {
        "manifest_version": v57.V57_VERSION,
        "candidate_name": "calibrated_hist_gradient_boosting",
        "candidate_version": v56.V56_VERSION,
        "artifact_name": artifact_name,
        "artifact_sha256": v57._file_sha256(artifact_path),
        "code_contract_fingerprint": v57._code_contract_fingerprint(),
        "pipeline": v57._artifact_pipeline_details(pipeline),
        "threshold": 0.3,
        "post_prediction_decision_policy": (
            "calibrated_threshold_only"
        ),
        "post_prediction_guard_used": False,
        "active": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "rules_alert_authoritative": True,
    }
    (output_dir / v57.V57_CANDIDATE_FREEZE).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (output_dir / v57.V57_LATEST).write_text(
        json.dumps(
            {
                "independent_evidence": {
                    "status": "independent_evidence_required",
                    "eligible_for_predictions": False,
                    "source_device_count": 1,
                    "independent_time_window_count": 1,
                },
                "blind_validation": {
                    "status": (
                        "not_run_independent_evidence_required"
                    )
                },
            }
        ),
        encoding="utf-8",
    )
    (output_dir / v56.V56_LATEST).write_text(
        json.dumps(
            {
                "drift_profile": {
                    "role_distributions": {
                        "development_fit": {
                            "quality": {
                                "rows": 100,
                                "parser_error_rate": 0.0,
                                "parser_warning_per_row": 0.0,
                                "required_missing_per_row": 0.0,
                                "unknown_app_rate": 0.0,
                            },
                            "application": [
                                {"value": "ssl", "count": 100}
                            ],
                            "schema": [
                                {
                                    "value": "traffic:full",
                                    "count": 100,
                                }
                            ],
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def _add_logs(db, *, count: int = 3) -> None:
    for index in range(count):
        raw = RawLog(
            raw_line=(
                f"private 198.51.100.{index + 1} -> "
                f"10.0.0.{index + 1}"
            ),
            raw_line_hash=f"{index + 1:064x}",
        )
        db.add(raw)
        db.flush()
        db.add(
            NormalizedLog(
                raw_log_id=raw.id,
                generated_time=datetime(
                    2026,
                    7,
                    1,
                    0,
                    index,
                ),
                src_ip=f"198.51.100.{index + 1}",
                dst_ip=f"10.0.0.{index + 1}",
                src_port=41000 + index,
                dst_port=443,
                protocol="tcp",
                action="allow",
                app="ssl",
                src_zone="outside",
                dst_zone="inside",
                bytes=800,
                packets=8,
                app_risk=2,
                is_anomaly=index == 0,
                anomaly_score=0.75 if index == 0 else 0.10,
                parsed_json={
                    "parser_profile": "palo_alto",
                    "parse_status": "parsed",
                    "field_count": 110,
                },
            )
        )
    db.commit()


def _authoritative_counts(db) -> dict[str, int]:
    models = {
        "raw": RawLog,
        "normalized": NormalizedLog,
        "alerts": Alert,
        "evidence": AlertEvidence,
        "labels": MLLabel,
        "models": MLModelRun,
        "runs": DetectionRun,
        "responses": ResponseAction,
    }
    return {
        name: int(
            db.scalar(select(func.count()).select_from(model)) or 0
        )
        for name, model in models.items()
    }


def test_shadow_runtime_is_disabled_by_default_and_safe(tmp_path):
    Session = _session_factory()
    _write_candidate_contract(tmp_path)
    with Session() as db:
        result = v58.governed_shadow_runtime_status(
            db,
            output_dir=tmp_path,
        )

    assert result["ok"] is True
    assert result["enabled"] is False
    assert result["status"] == "disabled_by_configuration"
    assert result["candidate_contract_matched"] is True
    assert result["lifecycle_state"] == "shadow_observation"
    assert result["rules_alert_authoritative"] is True
    assert result["response_automation_allowed"] is False
    assert result["fallback_model_used"] is False


def test_contract_mismatch_fails_closed_without_fallback(
    tmp_path,
    monkeypatch,
):
    _configure_shadow(monkeypatch)
    Session = _session_factory()
    _write_candidate_contract(tmp_path)
    manifest_path = tmp_path / v57.V57_CANDIDATE_FREEZE
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["pipeline"]["feature_count"] = 39
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with Session() as db:
        result = v58.governed_shadow_runtime_status(
            db,
            output_dir=tmp_path,
        )

    assert result["ok"] is False
    assert result["status"] == (
        "failed_closed_candidate_contract_mismatch"
    )
    assert result["candidate_contract_matched"] is False
    assert result["fallback_model_used"] is False
    assert result["model_activated"] is False


def test_shadow_scoring_is_aggregate_idempotent_and_mutation_free(
    tmp_path,
    monkeypatch,
):
    _configure_shadow(monkeypatch)
    Session = _session_factory()
    _write_candidate_contract(tmp_path)
    with Session() as db:
        _add_logs(db)
        before = _authoritative_counts(db)
        first = v58.governed_shadow_runtime_status(
            db,
            output_dir=tmp_path,
            limit=3,
        )
        second = v58.governed_shadow_runtime_status(
            db,
            output_dir=tmp_path,
            limit=3,
        )
        after = _authoritative_counts(db)

    assert first["ok"] is True
    assert first["status"] == "evaluated_shadow_read_only"
    assert first["telemetry"]["rows_evaluated"] == 3
    assert first["telemetry"]["queue_count"] == 3
    assert first["telemetry"]["queue_rate"] == 1.0
    assert first["telemetry"]["accuracy_metrics_calculated"] is False
    assert first["telemetry"]["labels_accessed"] is False
    assert first["telemetry"]["rule_shadow_agreement"][
        "rules_alert_authoritative"
    ] is True
    assert first["telemetry"]["isolation_forest"][
        "new_isolation_scoring_performed"
    ] is False
    assert first["telemetry"]["isolation_forest"][
        "advisory_only"
    ] is True
    assert first["idempotency"]["cache_hit"] is False
    assert second["idempotency"]["cache_hit"] is True
    assert second["telemetry"] == first["telemetry"]
    assert before == after
    assert first["safety"]["configured_database_unchanged"] is True
    assert first["safety"]["alerts_created"] == 0
    assert first["safety"]["labels_created"] == 0
    assert first["safety"]["model_runs_created"] == 0
    assert first["safety"]["detection_runs_created"] == 0
    assert first["safety"]["response_actions_created"] == 0

    serialized = json.dumps(first, default=str)
    assert "198.51.100." not in serialized
    assert "10.0.0." not in serialized
    assert "private 198" not in serialized
    assert str(tmp_path) not in serialized


def test_shadow_scoring_enforces_batch_bound(tmp_path, monkeypatch):
    _configure_shadow(monkeypatch)
    Session = _session_factory()
    _write_candidate_contract(tmp_path)
    with Session() as db:
        result = v58.governed_shadow_runtime_status(
            db,
            output_dir=tmp_path,
            limit=26,
        )

    assert result["ok"] is False
    assert result["status"] == "failed_closed_invalid_batch_limit"
    assert result["operational_controls"]["maximum_batch_size"] == 25
    assert "telemetry" not in result


def test_governed_intake_rejects_reused_evidence_without_metrics(
    tmp_path,
    monkeypatch,
):
    Session = _session_factory()
    sample = tmp_path / "candidate.log"
    sample.write_text("safe synthetic row\n", encoding="utf-8")
    sample_sha = v57._file_sha256(sample)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    (tmp_path / v57.V57_PREDICTION_FREEZE).write_text(
        json.dumps({"sample_sha256": sample_sha}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        v57,
        "run_v57_independent_shadow_revalidation",
        lambda *args, **kwargs: {
            "ok": True,
            "sample_profile": {
                "status": "parsed",
                "rows_processed": 100,
                "parser_successes": 100,
                "parser_failures": 0,
                "configured_database_overlap_rows": 0,
                "exact_duplicate_rows": 0,
                "near_duplicate_rows": 0,
                "matches_reused_v56_evidence": True,
            },
            "independent_evidence": {
                "eligible_for_predictions": True,
                "source_device_count": 2,
                "independent_time_window_count": 2,
                "checks": {
                    "manifest_present": True,
                    "schema_valid": True,
                    "chronology_valid": True,
                },
            },
        },
    )

    with Session() as db:
        before = _authoritative_counts(db)
        result = v58.governed_evidence_intake_preflight(
            db,
            sample_path=sample,
            evidence_manifest_path=manifest,
            output_dir=tmp_path,
        )
        after = _authoritative_counts(db)

    assert result["eligible_for_prediction_freeze"] is False
    assert result["status"] == "independent_evidence_required"
    assert result["checks"][
        "not_reused_v57_prediction_evidence"
    ] is False
    assert result["reused_v5_7_prediction_evidence_rejected"] is False
    assert result["blind_metrics_calculated"] is False
    assert result["labels_accessed"] is False
    assert result["predictions_written"] is False
    assert before == after
    assert result["safety"]["configured_database_unchanged"] is True
    assert result["safety"]["response_actions_created"] == 0
