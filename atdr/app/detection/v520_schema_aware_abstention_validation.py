from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection.v519_independent_labeled_validation import (
    V519_LATEST,
    V519_STATE,
    V519_VERSION,
)
from atdr.app.detection.v520_schema_aware_abstention import (
    V520_VERSION,
    public_schema_abstention_policy,
)


OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V520_LATEST = "v5_20_schema_aware_abstention_latest.json"
V520_LOCK_RECORD = "v5_20_v519_terminal_lock.json"
V520_REPORT_PREFIX = "v5_20_schema_aware_abstention"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def audit_v519_terminal_lock(*, output_dir: Path = OUTPUT_DIR) -> tuple[dict[str, Any], dict[str, Any]]:
    state_path = output_dir / V519_STATE
    result_path = output_dir / V519_LATEST
    state = _safe_json(state_path)
    result = _safe_json(result_path)
    checks = {
        "state_available": bool(state),
        "state_version_matches": state.get("version") == V519_VERSION,
        "evaluation_completed": state.get("evaluation_completed") is True,
        "adapter_recovery_completed": state.get("adapter_recovery_completed") is True,
        "labels_revealed": state.get("labels_revealed") is True,
        "predictions_frozen_before_labels": state.get("predictions_frozen_before_labels") is True,
        "no_post_reveal_candidate_changes": state.get("post_reveal_candidate_changes") is False,
        "labels_not_used_for_features": state.get("labels_used_for_features") is False,
        "labels_not_used_for_prediction": state.get("labels_used_for_prediction") is False,
        "labels_not_used_for_sampling": state.get("labels_used_for_sampling") is False,
        "labels_not_used_for_tuning": state.get("labels_used_for_tuning") is False,
        "result_available": bool(result),
        "result_version_matches": result.get("version") == V519_VERSION,
    }
    locked = all(checks.values())
    private_record = {
        "schema_version": "atdr-v5.20-v5.19-terminal-lock-v1",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "terminal_state": locked,
        "files": {
            V519_STATE: {
                "sha256": _sha256(state_path) if state_path.is_file() else None,
                "size_bytes": state_path.stat().st_size if state_path.is_file() else None,
            },
            V519_LATEST: {
                "sha256": _sha256(result_path) if result_path.is_file() else None,
                "size_bytes": result_path.stat().st_size if result_path.is_file() else None,
            },
        },
        "checks": checks,
        "labels_opened": False,
        "prediction_rows_opened": False,
        "private_paths_included": False,
        "raw_rows_included": False,
    }
    public = {
        "locked": locked,
        "status": "terminal_evidence_locked" if locked else "terminal_evidence_lock_unavailable",
        "checks": checks,
        "locked_artifact_count": sum(1 for row in private_record["files"].values() if row["sha256"]),
        "lock_record_name": V520_LOCK_RECORD,
        "fingerprints_exposed": False,
        "labels_opened": False,
        "prediction_rows_opened": False,
        "private_paths_included": False,
    }
    return public, private_record


def _render_markdown(result: dict[str, Any]) -> str:
    lock = result["v519_terminal_lock"]
    policy = result["schema_aware_abstention"]
    return "\n".join(
        [
            "# v5.20 Schema-Aware Abstention Validation",
            "",
            f"- Status: `{result['status']}`",
            f"- v5.19 terminal evidence locked: `{lock['locked']}`",
            f"- Locked artifact count: `{lock['locked_artifact_count']}`",
            f"- Expected supervised schema: `{policy['expected_schema_id']}`",
            f"- Fail closed: `{policy['fail_closed']}`",
            f"- Incompatible evidence scored: `{policy['incompatible_evidence_scored']}`",
            "- Fingerprints exposed: `false`",
            "- Labels opened: `false`",
            "- Prediction rows opened: `false`",
            "- Model activated: `false`",
            "- Production promoted: `false`",
            "- Response automation allowed: `false`",
            "",
            "## Decision",
            "",
            "Governed supervised inference is allowed only for evidence that satisfies the native PAN-OS schema contract. Incompatible, unknown, parser-failed, or incomplete evidence receives an explicit abstention; deterministic rules continue as the alert authority.",
            "",
        ]
    )


def run_v520_schema_aware_abstention_validation(
    *,
    output_dir: Path = OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    public_lock, private_lock = audit_v519_terminal_lock(output_dir=output_dir)
    result = {
        "ok": bool(public_lock["locked"]),
        "version": V520_VERSION,
        "status": "validated" if public_lock["locked"] else "failed_closed_v519_lock_unavailable",
        "v519_terminal_lock": public_lock,
        "schema_aware_abstention": public_schema_abstention_policy(),
        "lifecycle_state": "shadow_observation",
        "model_activated": False,
        "production_promoted": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
        "configured_database_accessed": False,
        "labels_opened": False,
        "prediction_rows_opened": False,
        "raw_logs_included": False,
        "private_paths_included": False,
        "fingerprints_exposed": False,
        "secrets_exposed": False,
    }
    if write_output:
        _write_json(output_dir / V520_LOCK_RECORD, private_lock)
        _write_json(output_dir / V520_LATEST, result)
        report_name = f"{V520_REPORT_PREFIX}_{_stamp()}.md"
        (output_dir / report_name).write_text(_render_markdown(result), encoding="utf-8")
        result["report_name"] = report_name
    return result
