from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import get_settings
from atdr.app.db.models import OperationJob
from atdr.app.detection.supervised_detector import train_supervised_classifier
from atdr.app.services.demo_service import export_demo_bundle
from atdr.app.services.detection_service import run_detection
from atdr.app.services.job_service import JOB_TYPES
from atdr.app.services.ml_service import apply_anomaly_scoring, train_anomaly_model
from atdr.app.services.source_service import PARSER_PROFILES, SOURCE_TYPES
from atdr.app.services.staging_service import (
    STAGING_ROOT,
    cleanup_staged_payload,
    stage_upload_for_job,
    staged_payload_fields,
)


__all__ = ["STAGING_ROOT", "cleanup_staged_payload", "stage_upload_for_job", "staged_payload_fields"]

MAX_QUEUE_LIMIT = 100_000
QUEUEABLE_JOB_TYPES = {
    "import_logs",
    "replay_logs",
    "run_detection",
    "train_ml",
    "apply_ml_scoring",
    "shadow_observation",
    "shadow_monitoring_cycle",
    "export_report",
}
ANALYST_QUEUEABLE_JOB_TYPES = {"import_logs", "replay_logs", "run_detection"}
ADMIN_QUEUEABLE_JOB_TYPES = QUEUEABLE_JOB_TYPES - ANALYST_QUEUEABLE_JOB_TYPES


class CooperativeShadowObservationCancelled(RuntimeError):
    """Raised before an aggregate shadow observation is persisted."""


def _as_optional_int(value: Any, *, field: str, minimum: int = 1, maximum: int = MAX_QUEUE_LIMIT) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a number.") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}.")
    return parsed


def _as_bool(value: Any, *, field: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    raise ValueError(f"{field} must be true or false.")


def _as_choice(value: Any, *, field: str, choices: set[str], default: str) -> str:
    candidate = str(value or default).strip().lower()
    if candidate not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(sorted(choices))}.")
    return candidate


def _as_optional_datetime(value: Any, *, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{field} must be an ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _stored_datetime(value: Any) -> datetime | None:
    serialized = _as_optional_datetime(value, field="time boundary")
    return datetime.fromisoformat(serialized) if serialized else None


def validate_job_submission(job_type: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Validate public JSON job requests before storing private worker payloads."""

    if job_type not in JOB_TYPES or job_type not in QUEUEABLE_JOB_TYPES:
        raise ValueError("This operation cannot be queued.")
    data = dict(payload or {})
    if job_type in {"import_logs", "replay_logs"}:
        raise ValueError("Queued file import requires the multipart /api/jobs/import endpoint.")
    if job_type == "run_detection":
        return {
            "limit": _as_optional_int(data.get("limit"), field="limit"),
            "use_ml": _as_bool(data.get("use_ml"), field="use_ml", default=True),
            "source_id": _as_optional_int(data.get("source_id"), field="source_id", maximum=2_147_483_647),
        }
    if job_type == "train_ml":
        operation = _as_choice(
            data.get("operation"),
            field="operation",
            choices={"anomaly_train", "supervised_train"},
            default="anomaly_train",
        )
        if operation == "anomaly_train":
            return {
                "operation": operation,
                "limit": _as_optional_int(data.get("limit"), field="limit"),
                "baseline_only": _as_bool(data.get("baseline_only"), field="baseline_only", default=False),
                "max_app_risk": _as_optional_int(data.get("max_app_risk", 3), field="max_app_risk", minimum=1, maximum=5),
                "exclude_unknown_apps": _as_bool(data.get("exclude_unknown_apps"), field="exclude_unknown_apps", default=True),
                "exclude_existing_anomalies": _as_bool(
                    data.get("exclude_existing_anomalies"),
                    field="exclude_existing_anomalies",
                    default=True,
                ),
            }
        return {
            "operation": operation,
            "test_size": float(data.get("test_size", 0.3)),
            "min_samples": _as_optional_int(data.get("min_samples", 6), field="min_samples", minimum=2),
            "split": _as_choice(
                data.get("split"),
                field="split",
                choices={"random", "time", "grouped_stratified"},
                default="random",
            ),
            "model_type": _as_choice(
                data.get("model_type"),
                field="model_type",
                choices={"random_forest", "hist_gradient_boosting", "logistic_regression", "extra_trees"},
                default="random_forest",
            ),
            "threshold_profile": _as_choice(
                data.get("threshold_profile"),
                field="threshold_profile",
                choices={"conservative", "balanced", "aggressive", "suspicious_recall", "malicious_recall", "threat_positive"},
                default="balanced",
            ),
        }
    if job_type == "apply_ml_scoring":
        return {"limit": _as_optional_int(data.get("limit"), field="limit")}
    if job_type == "shadow_observation":
        settings = get_settings()
        if not settings.governed_shadow_observation_enabled:
            raise ValueError(
                "Longitudinal shadow observation is disabled by configuration."
            )
        if not settings.governed_shadow_scoring_enabled:
            raise ValueError(
                "Governed shadow scoring is disabled by configuration."
            )
        start_at = _as_optional_datetime(
            data.get("start_at"),
            field="start_at",
        )
        end_at = _as_optional_datetime(
            data.get("end_at"),
            field="end_at",
        )
        if (
            start_at is not None
            and end_at is not None
            and datetime.fromisoformat(start_at)
            > datetime.fromisoformat(end_at)
        ):
            raise ValueError("start_at must not be later than end_at.")
        return {
            "source_id": _as_optional_int(
                data.get("source_id"),
                field="source_id",
                maximum=2_147_483_647,
            ),
            "start_at": start_at,
            "end_at": end_at,
            "limit": _as_optional_int(
                data.get("limit"),
                field="limit",
                maximum=int(settings.governed_shadow_max_batch_size),
            ),
        }
    if job_type == "shadow_monitoring_cycle":
        settings = get_settings()
        if not settings.governed_shadow_monitoring_enabled:
            raise ValueError(
                "Durable shadow monitoring is disabled by configuration."
            )
        if not settings.governed_shadow_observation_enabled:
            raise ValueError(
                "Longitudinal shadow observation is disabled by configuration."
            )
        if not settings.governed_shadow_scoring_enabled:
            raise ValueError(
                "Governed shadow scoring is disabled by configuration."
            )
        maximum_sources = _as_optional_int(
            data.get(
                "maximum_sources",
                settings.governed_shadow_monitoring_max_sources,
            ),
            field="maximum_sources",
            maximum=int(settings.governed_shadow_monitoring_max_sources),
        )
        maximum_windows = _as_optional_int(
            data.get(
                "maximum_windows_per_source",
                settings.governed_shadow_monitoring_max_windows_per_source,
            ),
            field="maximum_windows_per_source",
            maximum=int(
                settings.governed_shadow_monitoring_max_windows_per_source
            ),
        )
        minimum_rows = _as_optional_int(
            data.get(
                "minimum_rows",
                settings.governed_shadow_monitoring_min_rows,
            ),
            field="minimum_rows",
            maximum=10_000,
        )
        batch_limit = _as_optional_int(
            data.get(
                "batch_limit",
                settings.governed_shadow_monitoring_batch_limit,
            ),
            field="batch_limit",
            maximum=min(
                int(settings.governed_shadow_monitoring_batch_limit),
                int(settings.governed_shadow_max_batch_size),
            ),
        )
        return {
            "maximum_sources": maximum_sources,
            "maximum_windows_per_source": maximum_windows,
            "minimum_rows": max(
                int(minimum_rows or 1),
                int(settings.governed_shadow_monitoring_min_rows),
            ),
            "batch_limit": batch_limit,
        }
    if job_type == "export_report":
        return {
            "alert_id": _as_optional_int(data.get("alert_id"), field="alert_id", maximum=2_147_483_647),
            "top_alert_limit": _as_optional_int(data.get("top_alert_limit", 10), field="top_alert_limit", maximum=100),
            "audit_limit": _as_optional_int(data.get("audit_limit", 50), field="audit_limit", maximum=500),
        }
    raise ValueError("This operation cannot be queued.")


def validate_file_import_request(
    *,
    job_type: str,
    source_type: str | None,
    parser_profile: str | None,
    limit: int | None,
    source_id: int | None,
) -> dict[str, Any]:
    if job_type not in {"import_logs", "replay_logs"}:
        raise ValueError("Queued upload job type must be import_logs or replay_logs.")
    normalized_source_type = _as_choice(
        source_type,
        field="source_type",
        choices=SOURCE_TYPES,
        default="replay" if job_type == "replay_logs" else "file_import",
    )
    normalized_profile = _as_choice(
        parser_profile,
        field="parser_profile",
        choices=PARSER_PROFILES,
        default="palo_alto",
    )
    return {
        "source_type": normalized_source_type,
        "parser_profile": normalized_profile,
        "limit": _as_optional_int(limit, field="limit"),
        "source_id": _as_optional_int(source_id, field="source_id", maximum=2_147_483_647),
    }


def execute_operation_job(
    db: Session,
    *,
    job_type: str,
    payload: dict[str, Any],
    actor: str,
    job_id: int | None = None,
    worker_id: str | None = None,
    lease_token: str | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run a whitelisted job. No response, account, model activation, or external-provider action is dispatchable."""

    if job_type in {"import_logs", "replay_logs"}:
        if job_id is None or not worker_id or not lease_token:
            raise ValueError("Queued resumable import requires an operation job and worker lease.")
        from atdr.app.services.resumable_ingestion_service import run_resumable_import

        return run_resumable_import(
            db,
            job_id=job_id,
            worker_id=worker_id,
            lease_token=lease_token,
            payload=payload,
            actor=actor,
            should_stop=should_stop,
        )
    if job_type == "run_detection":
        return run_detection(
            db,
            limit=payload.get("limit"),
            use_ml=bool(payload.get("use_ml", True)),
            actor=actor,
            source_id=payload.get("source_id"),
        )
    if job_type == "train_ml":
        operation = str(payload.get("operation") or "anomaly_train")
        if operation == "anomaly_train":
            return train_anomaly_model(
                db,
                limit=payload.get("limit"),
                actor=actor,
                baseline_only=bool(payload.get("baseline_only", False)),
                max_app_risk=int(payload.get("max_app_risk") or 3),
                exclude_unknown_apps=bool(payload.get("exclude_unknown_apps", True)),
                exclude_existing_anomalies=bool(payload.get("exclude_existing_anomalies", True)),
            )
        if operation == "supervised_train":
            # Candidate-only keeps worker training from selecting or promoting a model.
            return train_supervised_classifier(
                db,
                actor=actor,
                test_size=float(payload.get("test_size") or 0.3),
                min_samples=int(payload.get("min_samples") or 6),
                split=str(payload.get("split") or "random"),
                model_type=str(payload.get("model_type") or "random_forest"),
                threshold_profile=str(payload.get("threshold_profile") or "balanced"),
                save_candidate=True,
                training_command="operation-worker candidate-only supervised training",
            )
        raise ValueError("Unsupported queued ML operation.")
    if job_type == "apply_ml_scoring":
        return apply_anomaly_scoring(db, limit=payload.get("limit"), actor=actor)
    if job_type == "shadow_observation":
        from atdr.app.services.v59_shadow_observation_service import (
            record_governed_shadow_observation,
        )

        def cancellation_requested() -> bool:
            if job_id is None:
                return False
            db.expire_all()
            current = db.get(OperationJob, job_id)
            return bool(
                current is not None
                and current.status == "cancel_requested"
            )

        result = record_governed_shadow_observation(
            db,
            actor=actor,
            source_id=payload.get("source_id"),
            start_at=_stored_datetime(payload.get("start_at")),
            end_at=_stored_datetime(payload.get("end_at")),
            limit=payload.get("limit"),
            should_stop=cancellation_requested,
        )
        if str(result.get("status") or "").startswith("cancelled_"):
            raise CooperativeShadowObservationCancelled(job_id)
        return result
    if job_type == "shadow_monitoring_cycle":
        from atdr.app.services.v510_detection_operations_service import (
            run_historical_shadow_observations,
        )

        result = run_historical_shadow_observations(
            db,
            actor=actor,
            maximum_sources=int(payload.get("maximum_sources") or 1),
            maximum_windows_per_source=int(
                payload.get("maximum_windows_per_source") or 1
            ),
            minimum_rows=int(payload.get("minimum_rows") or 50),
            batch_limit=payload.get("batch_limit"),
            should_stop=should_stop,
        )
        if str(result.get("status") or "").startswith("cancelled_"):
            raise CooperativeShadowObservationCancelled(job_id)
        return result
    if job_type == "export_report":
        return export_demo_bundle(
            db,
            actor=actor,
            alert_id=payload.get("alert_id"),
            top_alert_limit=int(payload.get("top_alert_limit") or 10),
            audit_limit=int(payload.get("audit_limit") or 50),
        )
    raise ValueError("Unsupported queued operation.")


def related_run_ids(result: dict[str, Any]) -> dict[str, int | None]:
    return {
        "related_ingestion_run_id": result.get("run_id") if "raw_logs_imported" in result else None,
        "related_detection_run_id": result.get("detection_run_id"),
        "related_ml_model_run_id": result.get("run_id") if "raw_logs_imported" not in result and "detection_run_id" not in result else None,
    }
