from __future__ import annotations

import json

from atdr.app.main import app
from atdr.app.services import ml_evidence_snapshot_service
from atdr.tests.test_api import _client, _login


def _report() -> dict:
    return {
        "version": "v4.1",
        "status": "completed_candidate_only",
        "generated_at": "2026-07-14T06:02:49+00:00",
        "development_evidence": {
            "development_only": True,
            "manifest_hash": "a" * 64,
            "files": [{"file_name": "safe-development.csv"}],
            "dataset": {
                "dataset_id": "controlled-development",
                "title": "Controlled development evidence",
                "publisher": "Test publisher",
                "role": "development_only_not_final_external_evidence",
                "human_reviewed": False,
            },
        },
        "development_sample": {
            "accepted_rows": 100,
            "sample_sha256": "b" * 64,
            "label_integrity": {"provider_ground_truth": True},
        },
        "diagnostic_selection": {
            "best_overall_development_diagnostic": {
                "name": "diagnostic_extra_trees",
                "selection_scope": "development_only_not_activation",
                "evaluated_splits": 3,
                "calibration_passed_splits": 0,
                "metric_ranges": {
                    "queue_f1": {"min": 0.81, "max": 0.88},
                    "benign_like_false_positive_rate": {"min": 0.08, "max": 0.17},
                },
            }
        },
        "worst_cross_schema_split": {
            "split_mode": "source_holdout",
            "metrics": {"queue_f1": 0.81, "benign_like_false_positive_rate": 0.17},
            "calibration": {
                "status": "weak",
                "passed": False,
                "brier_score": 0.2,
                "expected_calibration_error": 0.17,
                "max_confidence_accuracy_gap": 0.4,
            },
        },
        "readiness": {
            "decision": "candidate_only",
            "model_activated": False,
            "model_artifact_written": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
        },
        "safety": {"database_counts_unchanged": True},
    }


def test_evidence_snapshot_is_authenticated_and_has_single_provenance(tmp_path, monkeypatch):
    report_path = tmp_path / "v4_1_schema_aware_soc_queue_latest.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    monkeypatch.setattr(ml_evidence_snapshot_service, "CANONICAL_EVIDENCE_PATH", report_path)
    client = _client()
    try:
        assert client.get("/api/ml/evidence-snapshot").status_code == 401
        headers = _login(client, "analyst", "analyst123")
        response = client.get("/api/ml/evidence-snapshot", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        evidence = payload["canonical_evidence"]
        assert evidence["available"] is True
        assert evidence["version"] == "v4.1"
        assert evidence["snapshot_id"].startswith("v41-")
        assert evidence["selected_strategy"] == "diagnostic_extra_trees"
        assert evidence["metric_ranges"]["queue_f1"] == {"min": 0.81, "max": 0.88}
        assert evidence["readiness_decision"] == "candidate_only"
        assert evidence["safety"]["model_activated"] is False
        encoded = json.dumps(payload)
        assert str(tmp_path) not in encoded
        assert "model_path" not in encoded
        assert payload["safety"]["secrets_exposed"] is False
        assert payload["safety"]["response_automation_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_evidence_snapshot_never_falls_back_when_canonical_report_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ml_evidence_snapshot_service,
        "CANONICAL_EVIDENCE_PATH",
        tmp_path / "missing-v4_1-report.json",
    )
    client = _client()
    try:
        headers = _login(client, "admin", "admin123")
        payload = client.get("/api/ml/evidence-snapshot", headers=headers).json()
        evidence = payload["canonical_evidence"]
        assert evidence["available"] is False
        assert evidence["status"] == "not_available"
        assert evidence["metrics"] is None
        assert "v4.1" in evidence["reason"]
        assert payload["safety"]["production_promoted"] is False
    finally:
        app.dependency_overrides.clear()
