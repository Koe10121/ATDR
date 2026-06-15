import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.detection_reliability_common import json_default
from atdr.scripts.run_v17_external_generalization import (
    _latest_report_path,
    _load_json,
)
from atdr.scripts.run_v18_external_benchmark_finalization import (
    PROFILE_THRESHOLDS,
)


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
CANDIDATE_NAME = "independent_fpr_stabilized"
CALIBRATION_METHOD = "raw_confidence"
FROZEN_CANDIDATE_CONFIG = {
    "candidate_name": CANDIDATE_NAME,
    "base_profile": "external_recall_plus",
    "base_thresholds": {
        "threat_probability": PROFILE_THRESHOLDS["external_recall_plus"][0],
        "malicious_probability": PROFILE_THRESHOLDS["external_recall_plus"][1],
        "suspicious_probability": PROFILE_THRESHOLDS["external_recall_plus"][2],
    },
    "strong_rule_threshold": 0.68,
    "behavior_window_evidence_preserved": True,
    "identity_inputs_allowed": False,
    "review_boundary": {
        "app": "unknown-tcp",
        "action": "allow",
        "minimum_destination_port": 1024,
        "maximum_threat_probability": 0.60,
        "requires_no_behavior_evidence": True,
        "requires_no_threat_rule": True,
        "outcome": "analyst_review_boundary",
    },
    "calibration_method": CALIBRATION_METHOD,
    "production_promoted": False,
    "model_activated": False,
    "response_automation_allowed": False,
    "real_firewall_blocking_enabled": False,
}
FROZEN_SOURCE_PATHS = (
    PROJECT_ROOT / "atdr" / "scripts" / "run_v18_external_benchmark_finalization.py",
    PROJECT_ROOT / "atdr" / "scripts" / "run_v19b_independent_fpr_stabilization.py",
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _candidate_hash() -> tuple[str, dict[str, str]]:
    source_hashes = {}
    digest = hashlib.sha256()
    canonical = json.dumps(
        FROZEN_CANDIDATE_CONFIG,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest.update(canonical)
    for path in FROZEN_SOURCE_PATHS:
        content = path.read_bytes()
        source_hash = hashlib.sha256(content).hexdigest()
        source_hashes[str(path.relative_to(PROJECT_ROOT))] = source_hash
        digest.update(str(path.relative_to(PROJECT_ROOT)).encode("utf-8"))
        digest.update(content)
    return digest.hexdigest(), source_hashes


def _render_report(report: dict[str, Any]) -> str:
    config = report["candidate_config"]
    thresholds = config["base_thresholds"]
    boundary = config["review_boundary"]
    return "\n".join(
        [
            "# ATDR v2.0 Candidate Lock",
            "",
            f"- Generated: {report['generated_at']}",
            f"- Candidate: {report['candidate_name']}",
            f"- Candidate hash: `{report['candidate_hash']}`",
            f"- Source v1.9b report: {report['source_report_name'] or 'missing'}",
            "- Lock purpose: fresh blind validation only",
            "",
            "## Frozen Classification Configuration",
            "",
            f"- Base profile: `{config['base_profile']}`",
            f"- Threat threshold: `{thresholds['threat_probability']}`",
            f"- Malicious threshold: `{thresholds['malicious_probability']}`",
            f"- Suspicious threshold: `{thresholds['suspicious_probability']}`",
            f"- Strong rule threshold: `{config['strong_rule_threshold']}`",
            f"- Calibration method: `{config['calibration_method']}`",
            "- Behavior-window evidence: preserved",
            "- Source/scenario identity inputs: prohibited",
            "",
            "## Frozen Analyst-Review Boundary",
            "",
            f"- App/action: `{boundary['app']}` / `{boundary['action']}`",
            f"- Minimum destination port: `{boundary['minimum_destination_port']}`",
            f"- Maximum threat probability: `{boundary['maximum_threat_probability']}`",
            "- Requires no threat rule and no behavior-window evidence",
            "- Outcome: analyst review boundary, not an automatic benign verdict",
            "",
            "## Safety Lock",
            "",
            "- Production promoted: false",
            "- Model activated: false",
            "- Response automation: disabled",
            "- Real firewall blocking: disabled",
            "",
            "This lock is validation metadata, not a deployable model artifact.",
        ]
    )


def lock_v20_candidate(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    candidate_hash, source_hashes = _candidate_hash()
    source_report = _load_json(
        _latest_report_path(
            output_dir,
            "v1_9b_independent_fpr_stabilization_*.json",
        )
    )
    source_best = source_report.get("best_profile") or {}
    source_name = str(source_best.get("profile") or "")
    lock_matches_selected_candidate = source_name == CANDIDATE_NAME
    report = {
        "ok": lock_matches_selected_candidate,
        "status": (
            "locked" if lock_matches_selected_candidate else "source_mismatch"
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidate_name": CANDIDATE_NAME,
        "candidate_hash": candidate_hash,
        "candidate_config": FROZEN_CANDIDATE_CONFIG,
        "source_hashes": source_hashes,
        "source_report_name": (
            Path(
                str((source_report.get("paths") or {}).get("json"))
            ).name
            if (source_report.get("paths") or {}).get("json")
            else None
        ),
        "source_selected_profile": source_name or None,
        "source_metrics": source_best.get("metrics") or {},
        "source_validation_calibration_method": (
            source_best.get("calibration_method") or "none"
        ),
        "calibration_note": (
            "v1.9b calibration remains prior validation evidence. The v2.0 "
            "blind holdout evaluates raw frozen confidence because no portable "
            "calibrator artifact was locked before blind evaluation."
        ),
        "lock_matches_selected_candidate": lock_matches_selected_candidate,
        "threshold_tuning_allowed": False,
        "holdout_tuning_allowed": False,
        "production_promoted": False,
        "model_activated": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = _stamp()
        json_path = output_dir / f"v2_0_candidate_lock_{stamp}.json"
        markdown_path = output_dir / f"v2_0_candidate_lock_{stamp}.md"
        json_path.write_text(
            json.dumps(report, indent=2, default=json_default),
            encoding="utf-8",
        )
        markdown_path.write_text(_render_report(report), encoding="utf-8")
        report["paths"] = {
            "json": str(json_path),
            "markdown": str(markdown_path),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Freeze the v1.9b candidate for v2.0 blind validation."
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = lock_v20_candidate(
        output_dir=Path(args.output_dir),
        write_output=not args.no_report,
    )
    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=json_default,
        )
    )
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
