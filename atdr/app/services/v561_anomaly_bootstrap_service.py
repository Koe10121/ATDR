from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.database import Base
from atdr.app.db.models import (
    Alert,
    DetectionRun,
    MLLabel,
    MLModelRun,
    NormalizedLog,
    ResponseAction,
)
from atdr.app.detection.ml_detector import (
    FEATURE_COLUMNS,
    apply_model_to_db,
    train_model,
)
from atdr.app.detection.rules import build_detection_context, evaluate_rules
from atdr.app.detection.runtime_contract import (
    anomaly_runtime_status,
    detection_layer_contract,
)
from atdr.app.parsers.paloalto_parser import ParsedPaloAltoLog, parse_log_line
from atdr.app.services.detection_service import _alert_authoritative_matches
from atdr.app.services.log_service import import_log_file


VERSION = "v5.61-governed-anomaly-bootstrap-v1"
RELIABILITY_PROTOCOL_VERSION = "v5.63.1-advisor-demo-anomaly-reliability-v1"
EXECUTION_CONFIRMATION = "GOVERNED_ADVISORY_ANOMALY_BOOTSTRAP"
MINIMUM_ELIGIBLE_ROWS = 20
MINIMUM_PARSE_RATE = 0.95
MINIMUM_SCHEMA_RATE = 0.95
MAXIMUM_DUPLICATE_RATE = 0.20
DEFAULT_EVIDENCE_LIMIT = 50_000
CORRECTIVE_COMMAND = (
    ".\\scripts\\bootstrap_advisory_anomaly.cmd "
    "-UseCommittedSyntheticSample"
)
EXECUTION_COMMAND = (
    f"{CORRECTIVE_COMMAND} -Execute -Confirm "
    f"{EXECUTION_CONFIRMATION}"
)
MANIFEST_SUFFIX = ".bootstrap.json"
SUPPORTED_SUFFIXES = frozenset({".log", ".txt", ".csv"})
UNRESOLVED_APPS = frozenset(
    {"", "unknown", "unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "not-applicable"}
)
COMMITTED_SYNTHETIC_FILES = (
    "benign_dns_web_traffic.txt",
    "benign_high_volume_single_service.txt",
    "benign_incomplete_allow_noise.txt",
    "benign_repeated_internal_service.txt",
    "normal_allowed_traffic.txt",
    "normal_high_volume_but_allowed_traffic.txt",
    "normal_repeated_same_service_traffic.txt",
    "normal_web_dns_quic_traffic.txt",
)


class AnomalyBootstrapError(RuntimeError):
    """Expected, privacy-safe operator error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EvidenceInspection:
    files: tuple[Path, ...]
    parsed_rows: tuple[ParsedPaloAltoLog, ...]
    eligible_indexes: tuple[int, ...]
    source_role: str
    public: dict[str, Any]


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def anomaly_manifest_path(artifact_path: Path) -> Path:
    return artifact_path.with_suffix(MANIFEST_SUFFIX)


def _manifest_is_valid(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    evidence = payload.get("evidence")
    training = payload.get("training")
    validation = payload.get("validation")
    governance = payload.get("governance")
    privacy = payload.get("privacy")
    protocol_version = payload.get("protocol_version")
    base_valid = bool(
        protocol_version in {VERSION, RELIABILITY_PROTOCOL_VERSION}
        and payload.get("model_family") == "IsolationForest"
        and payload.get("capability_role") == "advisory_anomaly_scoring"
        and isinstance(evidence, dict)
        and _is_number(evidence.get("eligible_baseline_rows"))
        and evidence["eligible_baseline_rows"] >= MINIMUM_ELIGIBLE_ROWS
        and _is_number(evidence.get("parse_rate"))
        and evidence["parse_rate"] >= MINIMUM_PARSE_RATE
        and _is_number(evidence.get("schema_complete_rate"))
        and evidence["schema_complete_rate"] >= MINIMUM_SCHEMA_RATE
        and _is_number(evidence.get("duplicate_rate"))
        and evidence["duplicate_rate"] <= MAXIMUM_DUPLICATE_RATE
        and isinstance(training, dict)
        and training.get("random_state") == 42
        and training.get("n_estimators") == 150
        and training.get("feature_columns") == list(FEATURE_COLUMNS)
        and _is_number(training.get("contamination"))
        and 0.0 < training["contamination"] <= 0.5
        and isinstance(validation, dict)
        and validation.get("evidence_gates_passed") is True
        and validation.get("training_completed") is True
        and validation.get("advisory_scoring_passed") is True
        and _is_number(validation.get("rows_scored"))
        and validation["rows_scored"] >= MINIMUM_ELIGIBLE_ROWS
        and validation.get("model_driven_alerts") == 0
        and validation.get("model_driven_suppressions") == 0
        and validation.get("labels_created") == 0
        and validation.get("model_runs_created") == 0
        and validation.get("detection_runs_created") == 0
        and validation.get("response_actions_created") == 0
        and validation.get("rules_alert_authoritative") is True
        and validation.get("supervised_state") == "unqualified"
        and validation.get("response_state") == "simulation_only"
        and isinstance(governance, dict)
        and governance.get("decision_support_only") is True
        and governance.get("rules_alert_authoritative") is True
        and governance.get("threat_accuracy_validated") is False
        and governance.get("supervised_model_activated") is False
        and governance.get("response_automation_allowed") is False
        and isinstance(privacy, dict)
        and privacy.get("source_paths_recorded") is False
        and privacy.get("raw_logs_recorded") is False
        and privacy.get("network_addresses_recorded") is False
        and privacy.get("row_fingerprints_recorded") is False
    )
    if not base_valid:
        return False
    if protocol_version == VERSION:
        return True
    reliability = payload.get("reliability")
    return bool(
        isinstance(reliability, dict)
        and reliability.get("fixed_gates_passed") is True
        and reliability.get("development_only") is True
        and reliability.get("independent_accuracy_validated") is False
        and _is_number(reliability.get("controlled_benign_anomaly_rate"))
        and _is_number(reliability.get("controlled_suspicious_scenario_recall"))
        and _is_number(reliability.get("controlled_malicious_scenario_recall"))
        and _is_number(reliability.get("private_holdout_queue_rate"))
    )


def anomaly_manifest_is_valid(payload: object) -> bool:
    """Validate a public, sanitized anomaly capability manifest."""

    return _manifest_is_valid(payload)


def _read_manifest(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def anomaly_bootstrap_status(
    *,
    project_root: Path = PROJECT_ROOT,
    artifact_path: Path | None = None,
) -> dict[str, Any]:
    root = project_root.resolve()
    configured_artifact = (artifact_path or get_settings().resolved_model_path).resolve()
    manifest_path = anomaly_manifest_path(configured_artifact)
    artifact_exists = configured_artifact.is_file()
    manifest = _read_manifest(manifest_path) if manifest_path.is_file() else None
    manifest_valid = _manifest_is_valid(manifest)
    if artifact_exists and manifest_valid:
        state = "governed_advisory_ready"
    elif artifact_exists:
        state = "legacy_artifact_advisory_only"
    else:
        state = "unavailable"
    return {
        "state": state,
        "label": (
            "Advisory anomaly model available"
            if artifact_exists
            else "Advisory anomaly model unavailable"
        ),
        "artifact_exists": artifact_exists,
        "governed_manifest_exists": manifest_path.is_file(),
        "governed_manifest_valid": manifest_valid,
        "bootstrap_required": not (artifact_exists and manifest_valid),
        "preflight_command": CORRECTIVE_COMMAND,
        "execution_command": EXECUTION_COMMAND,
        "decision_support_only": True,
        "rules_alert_authoritative": True,
        "threat_accuracy_validated": False,
        "supervised_model_activated": False,
        "response_automation_allowed": False,
        "source_paths_exposed": False,
        "secrets_exposed": False,
        "project_root_valid": root.is_dir(),
    }


def _evidence_files(
    *,
    project_root: Path,
    evidence_path: Path | None,
    use_committed_synthetic_sample: bool,
) -> tuple[tuple[Path, ...], str]:
    if evidence_path is not None and use_committed_synthetic_sample:
        raise AnomalyBootstrapError(
            "evidence_source_conflict",
            "Choose either operator evidence or the committed synthetic sample, not both.",
        )
    if use_committed_synthetic_sample:
        sample_root = project_root / "data" / "samples" / "scenarios"
        files = tuple(sample_root / name for name in COMMITTED_SYNTHETIC_FILES)
        if not all(path.is_file() for path in files):
            raise AnomalyBootstrapError(
                "committed_sample_incomplete",
                "The committed synthetic capability sample is incomplete.",
            )
        return files, "committed_synthetic"
    if evidence_path is None:
        raise AnomalyBootstrapError(
            "evidence_source_required",
            "Provide --evidence-path or select --use-committed-synthetic-sample.",
        )
    candidate = evidence_path.expanduser().resolve()
    if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
        return (candidate,), "operator_supplied_private"
    if candidate.is_dir():
        files = tuple(
            sorted(
                path
                for path in candidate.iterdir()
                if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
            )
        )
        if files:
            return files, "operator_supplied_private"
    raise AnomalyBootstrapError(
        "evidence_source_unavailable",
        "The evidence source is unavailable or has no supported log files.",
    )


def _schema_complete(parsed: ParsedPaloAltoLog) -> bool:
    normalized = parsed.normalized
    return bool(
        parsed.error is None
        and normalized.get("log_type") == "TRAFFIC"
        and normalized.get("action")
        and normalized.get("app")
        and normalized.get("protocol")
        and normalized.get("src_port") is not None
        and normalized.get("dst_port") is not None
    )


def _baseline_eligible(parsed: ParsedPaloAltoLog) -> tuple[bool, str | None]:
    normalized = parsed.normalized
    if parsed.error is not None:
        return False, "parser_failure"
    if normalized.get("log_type") != "TRAFFIC":
        return False, "non_traffic_record"
    if not _schema_complete(parsed):
        return False, "incomplete_feature_schema"
    if str(normalized.get("action") or "").strip().lower() != "allow":
        return False, "non_allow_action"
    app = str(normalized.get("app") or "").strip().lower()
    if app in UNRESOLVED_APPS:
        return False, "unresolved_application"
    app_risk = normalized.get("app_risk")
    if app_risk is not None and int(app_risk) > 3:
        return False, "high_risk_application"
    return True, None


def _iter_nonblank_lines(files: Iterable[Path], *, limit: int) -> Iterable[str]:
    observed = 0
    for path in files:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for line in stream:
                if not line.strip():
                    continue
                if observed >= limit:
                    return
                observed += 1
                yield line.rstrip("\r\n")


def inspect_anomaly_evidence(
    *,
    project_root: Path = PROJECT_ROOT,
    evidence_path: Path | None = None,
    use_committed_synthetic_sample: bool = False,
    limit: int = DEFAULT_EVIDENCE_LIMIT,
) -> EvidenceInspection:
    if limit < MINIMUM_ELIGIBLE_ROWS or limit > DEFAULT_EVIDENCE_LIMIT:
        raise AnomalyBootstrapError(
            "invalid_evidence_limit",
            f"Evidence limit must be between {MINIMUM_ELIGIBLE_ROWS} and {DEFAULT_EVIDENCE_LIMIT}.",
        )
    files, source_role = _evidence_files(
        project_root=project_root.resolve(),
        evidence_path=evidence_path,
        use_committed_synthetic_sample=use_committed_synthetic_sample,
    )
    parsed_rows: list[ParsedPaloAltoLog] = []
    eligible_indexes: list[int] = []
    exclusion_reasons: dict[str, int] = {}
    seen: set[bytes] = set()
    duplicate_rows = 0
    parsed_successfully = 0
    schema_complete_rows = 0

    for raw_line in _iter_nonblank_lines(files, limit=limit):
        fingerprint = hashlib.sha256(raw_line.encode("utf-8", errors="replace")).digest()
        if fingerprint in seen:
            duplicate_rows += 1
            continue
        seen.add(fingerprint)
        parsed = parse_log_line(raw_line)
        row_index = len(parsed_rows)
        parsed_rows.append(parsed)
        if parsed.error is None and parsed.parsed_json.get("parse_status") == "parsed":
            parsed_successfully += 1
        if _schema_complete(parsed):
            schema_complete_rows += 1
        eligible, reason = _baseline_eligible(parsed)
        if eligible:
            eligible_indexes.append(row_index)
        elif reason:
            exclusion_reasons[reason] = exclusion_reasons.get(reason, 0) + 1

    unique_rows = len(parsed_rows)
    observed_rows = unique_rows + duplicate_rows
    parse_rate = parsed_successfully / unique_rows if unique_rows else 0.0
    schema_rate = schema_complete_rows / unique_rows if unique_rows else 0.0
    duplicate_rate = duplicate_rows / observed_rows if observed_rows else 0.0
    gates = {
        "minimum_eligible_rows": len(eligible_indexes) >= MINIMUM_ELIGIBLE_ROWS,
        "parser_quality": parse_rate >= MINIMUM_PARSE_RATE,
        "schema_completeness": schema_rate >= MINIMUM_SCHEMA_RATE,
        "duplicate_containment": duplicate_rate <= MAXIMUM_DUPLICATE_RATE,
    }
    public = {
        "source_role": source_role,
        "file_count": len(files),
        "observed_rows": observed_rows,
        "unique_rows": unique_rows,
        "duplicate_rows": duplicate_rows,
        "duplicate_rate": round(duplicate_rate, 4),
        "parsed_rows": parsed_successfully,
        "parse_rate": round(parse_rate, 4),
        "schema_complete_rows": schema_complete_rows,
        "schema_complete_rate": round(schema_rate, 4),
        "eligible_baseline_rows": len(eligible_indexes),
        "excluded_rows": unique_rows - len(eligible_indexes),
        "exclusion_reasons": dict(sorted(exclusion_reasons.items())),
        "limit": limit,
        "limit_reached": observed_rows >= limit,
        "gates": gates,
        "passed": all(gates.values()),
        "source_paths_exposed": False,
        "raw_logs_exposed": False,
        "network_addresses_exposed": False,
        "fingerprints_exposed": False,
    }
    return EvidenceInspection(
        files=files,
        parsed_rows=tuple(parsed_rows),
        eligible_indexes=tuple(eligible_indexes),
        source_role=source_role,
        public=public,
    )


def _path_is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _git_ignored(path: Path, *, project_root: Path) -> bool:
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(project_root),
                "check-ignore",
                "--no-index",
                "--quiet",
                "--",
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _validate_artifact_destination(*, project_root: Path, artifact_path: Path) -> dict[str, bool]:
    manifest_path = anomaly_manifest_path(artifact_path)
    pending_artifact = artifact_path.with_name(f".pending-{artifact_path.name}")
    pending_manifest = manifest_path.with_name(f".pending-{manifest_path.name}")
    backup_artifact = artifact_path.with_name(f".backup-{artifact_path.name}")
    backup_manifest = manifest_path.with_name(f".backup-{manifest_path.name}")
    result = {
        "artifact_inside_project": _path_is_inside(artifact_path, project_root),
        "manifest_inside_project": _path_is_inside(manifest_path, project_root),
        "artifact_ignored": _git_ignored(artifact_path, project_root=project_root),
        "manifest_ignored": _git_ignored(manifest_path, project_root=project_root),
        "pending_outputs_ignored": all(
            _git_ignored(path, project_root=project_root)
            for path in (pending_artifact, pending_manifest)
        ),
        "rollback_outputs_ignored": all(
            _git_ignored(path, project_root=project_root)
            for path in (backup_artifact, backup_manifest)
        ),
    }
    if not all(result.values()):
        raise AnomalyBootstrapError(
            "unsafe_artifact_destination",
            "The configured artifact and provenance manifest must stay inside the project and be Git-ignored.",
        )
    return result


def _deterministic_manifest(
    inspection: EvidenceInspection,
    *,
    contamination: float,
    acceptance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "protocol_version": VERSION,
        "model_family": "IsolationForest",
        "capability_role": "advisory_anomaly_scoring",
        "evidence": {
            "source_role": inspection.source_role,
            "observed_rows": inspection.public["observed_rows"],
            "unique_rows": inspection.public["unique_rows"],
            "eligible_baseline_rows": inspection.public["eligible_baseline_rows"],
            "excluded_rows": inspection.public["excluded_rows"],
            "parse_rate": inspection.public["parse_rate"],
            "schema_complete_rate": inspection.public["schema_complete_rate"],
            "duplicate_rate": inspection.public["duplicate_rate"],
        },
        "training": {
            "random_state": 42,
            "n_estimators": 150,
            "contamination": float(contamination),
            "feature_columns": list(FEATURE_COLUMNS),
        },
        "validation": {
            "evidence_gates_passed": inspection.public["passed"],
            "training_completed": True,
            "advisory_scoring_passed": acceptance["anomaly_state"] == "active_advisory",
            "rows_scored": acceptance["rows_scored"],
            "model_driven_alerts": acceptance["model_driven_alerts"],
            "model_driven_suppressions": acceptance["model_driven_suppressions"],
            "labels_created": acceptance["labels_created"],
            "model_runs_created": acceptance["model_runs_created"],
            "detection_runs_created": acceptance["detection_runs_created"],
            "response_actions_created": acceptance["response_actions_created"],
            "rules_alert_authoritative": acceptance["rules_alert_authoritative"],
            "supervised_state": acceptance["supervised_state"],
            "response_state": acceptance["response_state"],
        },
        "governance": {
            "decision_support_only": True,
            "rules_alert_authoritative": True,
            "threat_accuracy_validated": False,
            "supervised_model_activated": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_allowed": False,
        },
        "privacy": {
            "source_paths_recorded": False,
            "raw_logs_recorded": False,
            "network_addresses_recorded": False,
            "row_fingerprints_recorded": False,
            "secrets_recorded": False,
        },
    }


def _count(db: Session, model: type) -> int:
    return int(db.scalar(select(func.count()).select_from(model)) or 0)


def _safety_counts(db: Session) -> dict[str, int]:
    return {
        "alerts": _count(db, Alert),
        "detection_runs": _count(db, DetectionRun),
        "labels": _count(db, MLLabel),
        "model_runs": _count(db, MLModelRun),
        "response_actions": _count(db, ResponseAction),
    }


def _advisory_acceptance(db: Session, *, artifact_path: Path) -> dict[str, Any]:
    scored = apply_model_to_db(db, model_path=artifact_path)
    db.flush()
    logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id.asc())))
    context = build_detection_context(logs)
    anomalies = 0
    advisory_signals = 0
    authoritative_signals = 0
    for log in logs:
        matches = evaluate_rules(log, context)
        anomalies += int(bool(log.is_anomaly))
        advisory_signals += sum(match.code == "ml_anomaly_detected" for match in matches)
        authoritative_signals += len(_alert_authoritative_matches(matches))

    anomaly_status = anomaly_runtime_status(
        requested=True,
        artifact_available=True,
        rows_scored=len(scored),
        anomaly_count=anomalies,
        error_type=None,
        score_values=(
            float(item["anomaly_score"])
            for item in scored.values()
            if item.get("anomaly_score") is not None
        ),
    )
    layers = detection_layer_contract(
        rules_evaluated=len(logs),
        authoritative_rule_signals=authoritative_signals,
        anomaly=anomaly_status,
        supervised={
            "state": "unqualified",
            "reason_code": "no_qualified_runtime_candidate",
            "artifact_available": False,
            "rows_scored": 0,
            "queue_count": 0,
            "decision_support_only": True,
            "used_for_alert_creation": False,
            "used_for_severity": False,
            "used_for_suppression": False,
            "production_promoted": False,
            "response_automation_allowed": False,
        },
        response_simulation=True,
        matched_rule_ids={"ml_anomaly_detected"} if advisory_signals else set(),
        authoritative_matched_rule_ids=set(),
        candidate_logs=0,
        alerts_created=0,
        alerts_updated=0,
    )
    anomaly_layer = layers.get("anomaly") or {}
    supervised_layer = layers.get("supervised") or {}
    hybrid_layer = layers.get("hybrid") or {}
    response_layer = layers.get("response") or {}
    if not (
        anomaly_status.get("state") == "active_advisory"
        and layers.get("rule_detection_authoritative") is True
        and layers.get("model_only_alert_creation_allowed") is False
        and layers.get("production_promoted") is False
        and layers.get("response_automation_allowed") is False
        and anomaly_layer.get("used_for_alert_creation") is False
        and anomaly_layer.get("used_for_severity") is False
        and anomaly_layer.get("used_for_suppression") is False
        and supervised_layer.get("state") == "unqualified"
        and supervised_layer.get("used_for_alert_creation") is False
        and supervised_layer.get("used_for_severity") is False
        and supervised_layer.get("used_for_suppression") is False
        and hybrid_layer.get("decision_support_only") is True
        and hybrid_layer.get("used_for_alert_creation") is False
        and hybrid_layer.get("used_for_severity") is False
        and hybrid_layer.get("used_for_suppression") is False
        and response_layer.get("state") == "simulation_only"
        and response_layer.get("automatic_response_enabled") is False
        and response_layer.get("real_firewall_blocking_enabled") is False
    ):
        raise AnomalyBootstrapError(
            "advisory_contract_failed",
            "The advisory anomaly runtime contract did not pass.",
        )
    counts = _safety_counts(db)
    if any(counts.values()):
        raise AnomalyBootstrapError(
            "unexpected_authoritative_write",
            "Disposable advisory acceptance observed an unexpected authoritative write.",
        )
    return {
        "rows_scored": len(scored),
        "anomaly_signals": anomalies,
        "advisory_rule_signals": advisory_signals,
        "model_driven_alerts": 0,
        "model_driven_suppressions": 0,
        "labels_created": counts["labels"],
        "model_runs_created": counts["model_runs"],
        "detection_runs_created": counts["detection_runs"],
        "response_actions_created": counts["response_actions"],
        "rules_alert_authoritative": True,
        "anomaly_state": "active_advisory",
        "hybrid_state": hybrid_layer.get("state"),
        "hybrid_decision_support_only": True,
        "model_only_alert_creation_allowed": False,
        "supervised_state": "unqualified",
        "supervised_model_activated": False,
        "response_state": "simulation_only",
        "real_firewall_blocking_enabled": False,
    }


def _import_evidence_into_disposable_db(
    db: Session,
    inspection: EvidenceInspection,
    *,
    limit: int,
) -> list[NormalizedLog]:
    remaining = limit
    for index, path in enumerate(inspection.files, start=1):
        if remaining <= 0:
            break
        result = import_log_file(
            db,
            path,
            limit=remaining,
            actor="v561_disposable_bootstrap",
            source_type="v561_disposable_evidence",
        )
        remaining -= int(result.get("imported") or 0)
    logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id.asc())))
    eligible: list[NormalizedLog] = []
    seen_raw: set[str] = set()
    for log in logs:
        raw_line_hash = str(getattr(log.raw_log, "raw_line_hash", "") or "")
        if raw_line_hash in seen_raw:
            continue
        seen_raw.add(raw_line_hash)
        app = str(log.app or "").strip().lower()
        if not (
            log.log_type == "TRAFFIC"
            and str(log.action or "").strip().lower() == "allow"
            and app not in UNRESOLVED_APPS
            and (log.app_risk is None or log.app_risk <= 3)
            and log.protocol
            and log.src_port is not None
            and log.dst_port is not None
        ):
            continue
        eligible.append(log)
    return eligible


def _atomic_install(
    *,
    pending_artifact: Path,
    artifact_path: Path,
    pending_manifest: Path,
    manifest_path: Path,
    replace_existing: bool,
) -> None:
    artifact_backup = artifact_path.with_name(f".backup-{artifact_path.name}")
    manifest_backup = manifest_path.with_name(f".backup-{manifest_path.name}")
    had_artifact = artifact_path.exists()
    had_manifest = manifest_path.exists()
    if (had_artifact or had_manifest) and not replace_existing:
        raise AnomalyBootstrapError(
            "existing_artifact_protected",
            "An anomaly artifact already exists. Use --replace-existing only after reviewing the current state.",
        )
    for backup in (artifact_backup, manifest_backup):
        backup.unlink(missing_ok=True)
    try:
        if had_artifact:
            os.replace(artifact_path, artifact_backup)
        if had_manifest:
            os.replace(manifest_path, manifest_backup)
        os.replace(pending_artifact, artifact_path)
        os.replace(pending_manifest, manifest_path)
    except Exception:
        artifact_path.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        if artifact_backup.exists():
            os.replace(artifact_backup, artifact_path)
        if manifest_backup.exists():
            os.replace(manifest_backup, manifest_path)
        raise
    finally:
        artifact_backup.unlink(missing_ok=True)
        manifest_backup.unlink(missing_ok=True)
        pending_artifact.unlink(missing_ok=True)
        pending_manifest.unlink(missing_ok=True)


def install_anomaly_artifact_atomically(
    *,
    pending_artifact: Path,
    artifact_path: Path,
    pending_manifest: Path,
    manifest_path: Path,
    replace_existing: bool,
) -> None:
    """Install an ignored advisory artifact with rollback-safe replacement."""

    _atomic_install(
        pending_artifact=pending_artifact,
        artifact_path=artifact_path,
        pending_manifest=pending_manifest,
        manifest_path=manifest_path,
        replace_existing=replace_existing,
    )


def run_governed_anomaly_bootstrap(
    *,
    project_root: Path = PROJECT_ROOT,
    evidence_path: Path | None = None,
    use_committed_synthetic_sample: bool = False,
    limit: int = DEFAULT_EVIDENCE_LIMIT,
    execute: bool = False,
    confirmation: str = "",
    replace_existing: bool = False,
    artifact_path: Path | None = None,
) -> dict[str, Any]:
    root = project_root.resolve()
    configured_artifact = (artifact_path or get_settings().resolved_model_path).resolve()
    manifest_path = anomaly_manifest_path(configured_artifact)
    inspection = inspect_anomaly_evidence(
        project_root=root,
        evidence_path=evidence_path,
        use_committed_synthetic_sample=use_committed_synthetic_sample,
        limit=limit,
    )
    destination = _validate_artifact_destination(
        project_root=root,
        artifact_path=configured_artifact,
    )
    preflight = {
        "version": VERSION,
        "ok": inspection.public["passed"],
        "status": (
            "ready_for_explicit_bootstrap"
            if inspection.public["passed"]
            else "evidence_preflight_failed"
        ),
        "mode": "preflight",
        "executed": False,
        "evidence": inspection.public,
        "destination": destination,
        "current_capability": anomaly_bootstrap_status(
            project_root=root,
            artifact_path=configured_artifact,
        ),
        "required_confirmation": EXECUTION_CONFIRMATION,
        "governance": {
            "decision_support_only": True,
            "rules_alert_authoritative": True,
            "threat_accuracy_validated": False,
            "supervised_model_activated": False,
            "automatic_response_enabled": False,
            "response_mode": "simulation_only",
            "real_firewall_blocking_enabled": False,
        },
        "privacy": {
            "source_paths_exposed": False,
            "raw_logs_exposed": False,
            "network_addresses_exposed": False,
            "fingerprints_exposed": False,
            "secrets_exposed": False,
        },
    }
    if not execute or not inspection.public["passed"]:
        return preflight
    if confirmation != EXECUTION_CONFIRMATION:
        return {
            **preflight,
            "ok": False,
            "status": "execution_confirmation_required",
            "required_confirmation": EXECUTION_CONFIRMATION,
        }
    if (configured_artifact.exists() or manifest_path.exists()) and not replace_existing:
        raise AnomalyBootstrapError(
            "existing_artifact_protected",
            "An anomaly artifact already exists. Use --replace-existing only after reviewing the current state.",
        )

    configured_artifact.parent.mkdir(parents=True, exist_ok=True)
    pending_artifact = configured_artifact.with_name(f".pending-{configured_artifact.name}")
    pending_manifest = manifest_path.with_name(f".pending-{manifest_path.name}")
    pending_artifact.unlink(missing_ok=True)
    pending_manifest.unlink(missing_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix="atdr-v561-"))
    engine = create_engine(f"sqlite:///{(temp_root / 'bootstrap.db').as_posix()}", future=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    try:
        from atdr.app.db import models  # noqa: F401

        Base.metadata.create_all(engine)
        with session_factory() as db:
            eligible_logs = _import_evidence_into_disposable_db(
                db,
                inspection,
                limit=limit,
            )
            if len(eligible_logs) != inspection.public["eligible_baseline_rows"]:
                raise AnomalyBootstrapError(
                    "evidence_revalidation_mismatch",
                    "Disposable evidence revalidation did not match preflight.",
                )
            training = train_model(
                db,
                model_path=pending_artifact,
                logs=eligible_logs,
            )
            if training.get("trained") is not True or not pending_artifact.is_file():
                raise AnomalyBootstrapError(
                    "model_training_failed",
                    "The advisory anomaly model could not be trained from eligible evidence.",
                )
            acceptance = _advisory_acceptance(db, artifact_path=pending_artifact)
        manifest = _deterministic_manifest(
            inspection,
            contamination=get_settings().ml_contamination,
            acceptance=acceptance,
        )
        pending_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not _manifest_is_valid(_read_manifest(pending_manifest)):
            raise AnomalyBootstrapError(
                "manifest_validation_failed",
                "The sanitized bootstrap manifest did not validate.",
            )
        _atomic_install(
            pending_artifact=pending_artifact,
            artifact_path=configured_artifact,
            pending_manifest=pending_manifest,
            manifest_path=manifest_path,
            replace_existing=replace_existing,
        )
    finally:
        engine.dispose()
        pending_artifact.unlink(missing_ok=True)
        pending_manifest.unlink(missing_ok=True)
        shutil.rmtree(temp_root, ignore_errors=True)

    capability = anomaly_bootstrap_status(
        project_root=root,
        artifact_path=configured_artifact,
    )
    if capability["state"] != "governed_advisory_ready":
        raise AnomalyBootstrapError(
            "post_bootstrap_status_failed",
            "The anomaly artifact was created but did not pass governed status validation.",
        )
    return {
        **preflight,
        "ok": True,
        "status": "governed_advisory_anomaly_bootstrap_complete",
        "mode": "execute",
        "executed": True,
        "current_capability": capability,
        "acceptance": acceptance,
        "artifact_written_to_ignored_configured_location": True,
        "manifest_written_to_ignored_configured_location": True,
        "temporary_storage_cleaned": not temp_root.exists(),
    }


def safe_bootstrap_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, AnomalyBootstrapError):
        code = exc.code
        message = str(exc)
    else:
        code = "bootstrap_failed_safely"
        message = "The advisory anomaly bootstrap failed safely. No source details were exposed."
    return {
        "version": VERSION,
        "ok": False,
        "status": code,
        "message": message,
        "executed": False,
        "source_paths_exposed": False,
        "raw_logs_exposed": False,
        "network_addresses_exposed": False,
        "fingerprints_exposed": False,
        "secrets_exposed": False,
        "model_activated": False,
        "response_actions_created": 0,
    }
