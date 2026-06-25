from collections.abc import Generator
import asyncio
import json
import shutil
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert
from atdr.app.main import app, database_operational_exception_handler
from atdr.app.routers import dashboard as dashboard_router
from atdr.app.services.user_service import create_user
from atdr.tests.test_parser import TRAFFIC_LINE


def _client() -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    with testing_session() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        db.add(
            Alert(
                title="Medium: API test alert",
                alert_type="api_test",
                src_ip="203.0.113.50",
                dst_ip="10.0.0.5",
                threat_score=45,
                severity="Medium",
                status="open",
                explanation="API test alert.",
                matched_rules_json=[],
                recommended_response="Investigate.",
            )
        )
        db.commit()

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_login_and_me_api():
    client = _client()
    try:
        health = client.get("/health", headers={"X-Request-ID": "health-test-id"})
        assert health.status_code == 200
        assert health.headers["X-Request-ID"] == "health-test-id"
        assert health.headers["X-Content-Type-Options"] == "nosniff"
        assert health.headers["X-Frame-Options"] == "DENY"
        assert health.json()["status"] == "ok"
        assert health.json()["checks"]["database"]["status"] == "ok"
        headers = _login(client, "admin", "admin123")

        me = client.get("/api/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["username"] == "admin"
        assert me.json()["role"] == "admin"
    finally:
        app.dependency_overrides.clear()


def test_database_operational_error_returns_clear_503():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/login",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
        }
    )
    response = asyncio.run(
        database_operational_exception_handler(
            request,
            OperationalError("SELECT 1", {}, Exception("database unavailable")),
        )
    )
    payload = json.loads(response.body)

    assert response.status_code == 503
    assert "Database unavailable" in payload["detail"]
    assert "DATABASE_URL" in payload["detail"]
    assert "postgres" not in payload["detail"].lower()


def test_oidc_status_is_authenticated_and_does_not_expose_secret(monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("OIDC_PROVIDER_NAME", "")
    monkeypatch.setenv("OIDC_CLIENT_ID", "")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "secret-that-must-not-leak")
    monkeypatch.setenv("OIDC_ISSUER_URL", "")
    monkeypatch.setenv("OIDC_ALLOWED_DOMAINS", "")
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "analyst")
    get_settings.cache_clear()
    client = _client()
    try:
        unauthorized = client.get("/api/auth/oidc/status")
        assert unauthorized.status_code == 401

        headers = _login(client, "analyst", "analyst123")
        response = client.get("/api/auth/oidc/status", headers=headers)
        assert response.status_code == 200
        payload = response.json()

        assert payload["enabled"] is False
        assert payload["mode"] == "local_login_only"
        assert payload["default_role"] == "analyst"
        assert payload["local_email_login_enabled"] is True
        assert payload["smtp_enabled"] is False
        assert payload["school_email_domains"] == []
        assert "client_secret" not in payload
        assert "OIDC_CLIENT_SECRET" not in str(payload)
        assert "SMTP_PASSWORD" not in str(payload)
    finally:
        app.dependency_overrides.clear()


def test_mfu_iam_status_is_authenticated_disabled_by_default_and_hides_secrets(monkeypatch):
    monkeypatch.setenv("MFU_IAM_ENABLED", "false")
    monkeypatch.setenv("MFU_IAM_BASE_URL", "")
    monkeypatch.setenv("MFU_IAM_CLIENT_ID", "")
    monkeypatch.setenv("MFU_IAM_CLIENT_SECRET", "mfu-secret-that-must-not-leak")
    monkeypatch.setenv("MFU_IAM_AUDIENCE", "")
    monkeypatch.setenv("MFU_IAM_SCOPE", "")
    monkeypatch.setenv("MFU_IAM_TOKEN_PATH", "/api/v1/b2b/token")
    monkeypatch.setenv("MFU_IAM_INTROSPECT_PATH", "/api/v1/b2b/introspect")
    monkeypatch.setenv("MFU_IAM_PROFILE_PATH", "/api/v1/b2b/me")
    monkeypatch.setenv("MFU_IAM_ADMIN_BASE_PATH", "/api/v1")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "")
    monkeypatch.setenv("MFU_IAM_DEFAULT_ROLE", "analyst")
    monkeypatch.setenv("GOOGLE_SSO_ENABLED", "false")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "google-client-id-that-must-not-leak")
    get_settings.cache_clear()
    client = _client()
    try:
        unauthorized = client.get("/api/auth/mfu-iam/status")
        assert unauthorized.status_code == 401

        headers = _login(client, "analyst", "analyst123")
        response = client.get("/api/auth/mfu-iam/status", headers=headers)
        assert response.status_code == 200
        payload = response.json()

        assert payload["enabled"] is False
        assert payload["mode"] == "local_login_only"
        assert payload["base_url_configured"] is False
        assert payload["client_id_configured"] is False
        assert payload["client_secret_configured"] is True
        assert payload["audience_configured"] is False
        assert payload["scope_configured"] is False
        assert payload["token_path_configured"] is True
        assert payload["introspect_path_configured"] is True
        assert payload["profile_path_configured"] is True
        assert payload["admin_base_path_configured"] is True
        assert payload["admin_secret_configured"] is False
        assert payload["b2b_ready"] is False
        assert payload["allowed_domains"] == []
        assert payload["default_role"] == "analyst"
        assert payload["google_sso_enabled"] is False
        assert payload["google_client_id_configured"] is True
        assert payload["secrets_exposed"] is False
        assert "mfu-secret-that-must-not-leak" not in str(payload)
        assert "google-client-id-that-must-not-leak" not in str(payload)
        assert "MFU_IAM_CLIENT_SECRET" not in str(payload)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_mfu_iam_status_accepts_supervisor_template_env_names_and_hides_secrets(monkeypatch):
    monkeypatch.setenv("MFU_IAM_ENABLED", "true")
    monkeypatch.setenv("IAM_SDK_BASE_URL", "https://iam.mfu.ac.th")
    monkeypatch.setenv("IAM_SDK_CLIENT_ID", "template-local-client")
    monkeypatch.setenv("IAM_SDK_CLIENT_SECRET", "template-client-secret-that-must-not-leak")
    monkeypatch.setenv("IAM_SDK_AUDIENCE", "mfu-ai-driven-log-based-threat-detection-and-response-api")
    monkeypatch.setenv("IAM_SDK_SCOPE", "read write")
    monkeypatch.setenv("IAM_SDK_TIMEOUT_MS", "5000")
    monkeypatch.setenv("IAM_SDK_TOKEN_PATH", "/api/v1/b2b/token")
    monkeypatch.setenv("IAM_SDK_INTROSPECT_PATH", "/api/v1/b2b/introspect")
    monkeypatch.setenv("IAM_SDK_PROFILE_PATH", "/api/v1/b2b/clients/me")
    monkeypatch.setenv("IAM_SDK_ADMIN_BASE_PATH", "/api/v1/b2b/admin")
    monkeypatch.setenv("IAM_ADMIN_CLIENT_ID", "admin-client")
    monkeypatch.setenv("IAM_ADMIN_CLIENT_SECRET", "admin-secret-that-must-not-leak")
    monkeypatch.setenv("IAM_ADMIN_AUDIENCE", "iam-admin-api")
    monkeypatch.setenv("IAM_ADMIN_SCOPE", "iam.security.read")
    monkeypatch.setenv("IAM_COMPAT_PROFILE", "b2b-admin-v1")
    monkeypatch.setenv("MFU_IAM_ALLOWED_DOMAINS", "lamduan.mfu.ac.th")
    monkeypatch.setenv("PROJECT_PERMISSION_SOURCE", "iam")
    monkeypatch.setenv("PROJECT_PERMISSION_BOOTSTRAP_MODE", "iam")
    monkeypatch.setenv("PROJECT_PERMISSION_ROOT_PATH", "/mfu-ai-driven-log-based-threat-detection-and-response/security/permission")
    monkeypatch.setenv("PROJECT_PERMISSION_PATHS", "/dashboard,/security/audit")
    monkeypatch.setenv("PROJECT_PERMISSION_ACCOUNT_EMAIL", "6631501139@lamduan.mfu.ac.th")
    monkeypatch.setenv("PROJECT_AUTH_REQUIRE_2FA", "true")
    monkeypatch.setenv("PROJECT_AUDIT_RETENTION_DAYS", "90")
    monkeypatch.setenv("PROJECT_IAM_MANAGED_CLIENT_ID", "managed-client")
    monkeypatch.setenv("PROJECT_IAM_MANAGED_CLIENT_ENDPOINT", "http://127.0.0.1:8214")
    monkeypatch.setenv("PROJECT_IAM_MANAGED_CLIENT_OWNER_EMAIL", "6631501139@lamduan.mfu.ac.th")
    monkeypatch.setenv("PROJECT_IAM_MANAGED_CLIENT_ALLOWED_SCOPES", "read write")
    monkeypatch.setenv("PROJECT_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES", "mfu-api")
    monkeypatch.setenv("PROJECT_INIT_ADMIN_EMAILS", "6631501139@lamduan.mfu.ac.th")
    monkeypatch.setenv("PROJECT_INIT_SEED_ADMIN_EMAIL", "6631501139@lamduan.mfu.ac.th")
    get_settings.cache_clear()
    client = _client()
    try:
        headers = _login(client, "admin", "admin123")
        response = client.get("/api/auth/mfu-iam/status", headers=headers)
        assert response.status_code == 200
        payload = response.json()

        assert payload["enabled"] is True
        assert payload["base_url_configured"] is True
        assert payload["client_id_configured"] is True
        assert payload["client_secret_configured"] is True
        assert payload["audience_configured"] is True
        assert payload["scope_configured"] is True
        assert payload["timeout_ms"] == 5000
        assert payload["profile_path_configured"] is True
        assert payload["admin_client_configured"] is True
        assert payload["admin_secret_configured"] is True
        assert payload["admin_api_ready"] is True
        assert payload["b2b_ready"] is True
        assert payload["permission_source"] == "iam"
        assert payload["permission_bootstrap_ready"] is True
        assert payload["permission_paths_count"] == 2
        assert payload["auth_require_2fa"] is True
        assert payload["allowed_domains"] == ["lamduan.mfu.ac.th"]
        assert payload["domain_hints"] == ["lamduan.mfu.ac.th"]
        assert payload["managed_client_configured"] is True
        assert payload["init_admin_emails_configured"] is True
        assert payload["secrets_exposed"] is False
        assert "template-client-secret-that-must-not-leak" not in str(payload)
        assert "admin-secret-that-must-not-leak" not in str(payload)
        assert "IAM_ADMIN_CLIENT_SECRET" not in str(payload)
        assert "IAM_SDK_CLIENT_SECRET" not in str(payload)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_mfu_iam_disabled_does_not_change_local_login(monkeypatch):
    monkeypatch.setenv("MFU_IAM_ENABLED", "false")
    monkeypatch.setenv("GOOGLE_SSO_ENABLED", "false")
    get_settings.cache_clear()
    client = _client()
    try:
        response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        assert response.status_code == 200
        assert response.json()["role"] == "admin"
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_dashboard_validation_summary_reports_latest_file_without_private_paths(monkeypatch):
    report_dir = Path(".pytest_tmp") / "dashboard_validation_summary" / "detection_validation"
    generalization_dir = Path(".pytest_tmp") / "dashboard_validation_summary" / "detection_generalization"
    layered_dir = Path(".pytest_tmp") / "dashboard_validation_summary" / "layered_detection"
    e2e_dir = Path(".pytest_tmp") / "dashboard_validation_summary" / "e2e_validation"
    reliability_dir = Path(".pytest_tmp") / "dashboard_validation_summary" / "detection_reliability"
    shutil.rmtree(report_dir.parent, ignore_errors=True)
    report_dir.mkdir(parents=True)
    generalization_dir.mkdir(parents=True)
    layered_dir.mkdir(parents=True)
    e2e_dir.mkdir(parents=True)
    reliability_dir.mkdir(parents=True)
    report_path = report_dir / "detection_validation_20260604T110000Z.json"
    generalization_path = generalization_dir / "detection_generalization_20260605T010000Z.json"
    layered_path = layered_dir / "layered_detection_20260605T014000Z.json"
    e2e_path = e2e_dir / "e2e_workflow_validation_20260605T020000Z.json"
    reliability_path = reliability_dir / "detection_reliability_baseline_20260605T030000Z.json"
    benchmark_path = reliability_dir / "benchmark_evaluation_20260605T031000Z.json"
    drift_path = reliability_dir / "drift_report_20260605T032000Z.json"
    v13_audit_path = reliability_dir / "training_data_quality_audit_20260605T033000Z.json"
    v13_target_path = reliability_dir / "v1_3_label_target_plan.json"
    v13_candidate_path = reliability_dir / "v1_3_supervised_candidate_report_20260605T034000Z.json"
    v14_candidate_path = reliability_dir / "v1_4_false_positive_reduction_20260605T035000Z.json"
    v14b_candidate_path = reliability_dir / "v1_4b_quic_false_positive_mitigation.json"
    v14c_candidate_path = reliability_dir / "v1_4c_malicious_recall_recovery.json"
    v15_candidate_path = reliability_dir / "final_ai_readiness_report_20260605T041000Z.json"
    v16_candidate_path = reliability_dir / "external_benchmark_validation_20260605T042000Z.json"
    v355_queue_path = reliability_dir / "v3_55_severity_target_policy_reframing_latest.json"
    v357_agreement_path = reliability_dir / "v3_57_queue_rule_hybrid_agreement_latest.json"
    v359_policy_path = reliability_dir / "v3_59_supervised_output_policy_contract_latest.json"
    report_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-04T11:00:00+00:00",
                "validation_scope": "controlled small-subnet / lab-scale threat detection validation",
                "scenario_count": 14,
                "passed_count": 14,
                "scenarios": [{"scenario": "port_scan_like_traffic", "passed": True}],
                "safety": {
                    "response_mode": "simulated analyst-approved only",
                    "production_readiness_claim": False,
                },
                "paths": {
                    "json": str(report_path),
                    "markdown": str(report_dir / "detection_validation_20260604T110000Z.md"),
                    "risk_calibration": str(report_dir / "detection_validation_20260604T110000Z_risk_calibration.md"),
                },
            }
        ),
        encoding="utf-8",
    )
    generalization_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T01:00:00+00:00",
                "validation_scope": "controlled synthetic detection generalization validation",
                "scenario_count": 14,
                "variant_count": 70,
                "passed_count": 70,
                "failed_count": 0,
                "false_positive_count": 0,
                "false_negative_count": 0,
                "families": [{"scenario": "port_scan_like_traffic", "failed_count": 0}],
                "safety": {
                    "response_mode": "simulated analyst-approved only",
                    "production_readiness_claim": False,
                    "synthetic_variants_only": True,
                },
                "paths": {
                    "json": str(generalization_path),
                    "markdown": str(generalization_dir / "detection_generalization_20260605T010000Z.md"),
                },
            }
        ),
        encoding="utf-8",
    )
    layered_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T01:40:00+00:00",
                "validation_scope": "controlled layered detection contribution validation",
                "scenario_count": 14,
                "variant_count": 42,
                "mode_count": 4,
                "mode_run_count": 168,
                "passed_count": 168,
                "failed_count": 0,
                "false_positive_count": 0,
                "false_negative_count": 0,
                "mode_summary": [{"mode": "rules_only", "tests": 42, "passed_count": 42}],
                "safety": {
                    "response_mode": "simulated analyst-approved only",
                    "production_readiness_claim": False,
                },
                "paths": {
                    "json": str(layered_path),
                    "markdown": str(layered_dir / "layered_detection_20260605T014000Z.md"),
                },
            }
        ),
        encoding="utf-8",
    )
    e2e_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T02:00:00+00:00",
                "validation_scope": "controlled end-to-end ATDR workflow validation",
                "scenario_count": 3,
                "passed_count": 3,
                "failed_count": 0,
                "simulate_response": True,
                "scenarios": [
                    {
                        "alert_count": 2,
                        "case_count": 1,
                        "audit_summary": {"response_actions_created": 3},
                    }
                ],
                "safety": {
                    "response_mode": "simulated analyst-approved only",
                    "production_readiness_claim": False,
                },
                "paths": {
                    "json": str(e2e_path),
                    "markdown": str(e2e_dir / "e2e_workflow_validation_20260605T020000Z.md"),
                },
            }
        ),
        encoding="utf-8",
    )
    reliability_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:00:00+00:00",
                "validation_scope": "controlled detection reliability baseline",
                "scenario_validation": {"scenario_count": 14, "passed_count": 14},
                "generalization_validation": {"variant_count": 70, "passed_count": 70},
                "layered_validation": {"mode_run_count": 168, "passed_count": 168},
                "e2e_workflow_validation": {"scenario_count": 3, "passed_count": 3},
                "false_positive_count": 0,
                "false_negative_count": 0,
                "alert_volume": 18,
                "safety": {"production_readiness_claim": False},
                "paths": {"markdown": str(reliability_dir / "detection_reliability_baseline_20260605T030000Z.md")},
            }
        ),
        encoding="utf-8",
    )
    benchmark_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:10:00+00:00",
                "validation_scope": "generic external/public-style benchmark adapter",
                "detection_mode": "hybrid",
                "dataset": {"csv_name": "benchmark_snapshot_demo", "snapshot_id": "demo1234"},
                "total_rows": 10,
                "rows_mapped": 10,
                "alert_volume": 1,
                "metrics": {
                    "precision": 1,
                    "recall": 1,
                    "f1": 1,
                    "threat_positive_f1": 1,
                    "false_positives": 0,
                    "false_negatives": 0,
                },
                "readiness_gate_v2": {"decision": "candidate_only", "production_promoted": False},
                "safety": {"production_readiness_claim": False},
                "paths": {"markdown": str(reliability_dir / "benchmark_evaluation_20260605T031000Z.md")},
            }
        ),
        encoding="utf-8",
    )
    drift_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:20:00+00:00",
                "validation_scope": "lightweight detection drift monitoring groundwork",
                "recent_rows": 1000,
                "baseline_rows": 5000,
                "unknown_app_rate": 0.05,
                "parse_failure_rate": 0,
                "alert_rate": 0.02,
                "warnings": [],
                "safety": {"production_readiness_claim": False},
                "paths": {"markdown": str(reliability_dir / "drift_report_20260605T032000Z.md")},
            }
        ),
        encoding="utf-8",
    )
    v13_audit_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:30:00+00:00",
                "reviewed_label_count": 1528,
                "weak_label_count": 437,
                "training_readiness": {
                    "minimum_target_classes_met": 3,
                    "minimum_target_class_count": 5,
                },
            }
        ),
        encoding="utf-8",
    )
    v13_target_path.write_text(
        json.dumps(
            {
                "ok": True,
                "class_rows": [
                    {"label": "benign", "minimum_gap": 34},
                    {"label": "needs_context", "minimum_gap": 10},
                ],
            }
        ),
        encoding="utf-8",
    )
    v13_candidate_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:40:00+00:00",
                "best_flat_candidate": {
                    "name": "extra_trees",
                    "metrics": {
                        "threat_positive": {"f1": 0.91},
                        "per_class": {
                            "suspicious": {"recall": 0.75},
                            "malicious": {"recall": 0.6},
                        },
                    },
                },
                "readiness_gate_v3": {
                    "decision": "analyst_review_eligible",
                    "production_status": "not_production_promoted",
                },
            }
        ),
        encoding="utf-8",
    )
    v14_candidate_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:50:00+00:00",
                "best_strategy": "flat_extra_trees_strong_benign",
                "best_profile": "precision_focused",
                "best_metrics": {
                    "threat_positive_precision": 0.9,
                    "threat_positive_recall": 0.82,
                    "threat_positive_f1": 0.858,
                    "benign_like_false_positive_rate": 0.12,
                    "suspicious_recall": 0.71,
                    "malicious_recall": 0.68,
                },
                "calibration_status": "weak",
                "readiness": {"decision": "analyst_review_eligible"},
                "production_promoted": False,
                "response_automation_allowed": False,
                "report_path": str(
                    reliability_dir
                    / "v1_4_false_positive_reduction_20260605T035000Z.md"
                ),
            }
        ),
        encoding="utf-8",
    )
    v14b_candidate_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T03:55:00+00:00",
                "analysis": {"quic_false_positive_count": 42},
                "review_sample": {
                    "rows": 200,
                    "protected_manual_rows": 0,
                },
                "production_promoted": False,
                "response_automation_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    v14c_candidate_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T04:00:00+00:00",
                "best_profile": "calibrated_low_noise",
                "best_metrics": {
                    "threat_positive_precision": 0.91,
                    "threat_positive_recall": 0.92,
                    "threat_positive_f1": 0.915,
                    "benign_like_false_positive_rate": 0.06,
                    "suspicious_recall": 0.95,
                    "malicious_recall": 0.7,
                },
                "selected_calibration": {"status": "passed"},
                "readiness": {"decision": "analyst_review_eligible"},
                "review_sample": {"rows": 150, "protected_manual_rows": 0},
                "production_promoted": False,
                "model_activated": False,
                "response_automation_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    v15_candidate_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T04:10:00+00:00",
                "benchmark": {
                    "row_count": 240,
                    "target_met": True,
                },
                "best_benchmark_candidate": {
                    "candidate_name": "hierarchical_two_stage_extra_trees",
                    "metrics": {
                        "threat_positive_f1": 0.91,
                        "threat_positive_recall": 0.92,
                        "benign_false_positive_rate": 0.08,
                        "per_class": {
                            "suspicious": {"recall": 0.9},
                            "malicious": {"recall": 0.66},
                        },
                    },
                },
                "current_v14c": {
                    "best_profile": "malicious_recall_recovery",
                    "selected_calibration": {"status": "passed"},
                },
                "readiness_gate_v4": {
                    "decision": "benchmark_validated_candidate",
                    "passed": 8,
                    "total": 8,
                },
                "production_promoted": False,
                "model_activated": False,
                "response_automation_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    v16_candidate_path.write_text(
        json.dumps(
            {
                "ok": True,
                "generated_at": "2026-06-05T04:20:00+00:00",
                "external_snapshot": {
                    "benchmark_label_count": 320,
                    "preferred_target_met": True,
                    "profile": {
                        "source_count": 5,
                        "scenario_count": 14,
                    },
                },
                "cross_dataset_candidate": {
                    "candidate_name": "v1_5_random_forest_three_class_transfer",
                    "metrics": {
                        "threat_positive_f1": 0.7278,
                        "threat_positive_recall": 0.7471,
                        "benign_false_positive_rate": 0.3467,
                        "per_class": {
                            "suspicious": {"recall": 0.35},
                            "malicious": {"recall": 0.8889},
                        },
                    },
                    "calibration": {"status": "weak"},
                },
                "overfitting_check": {
                    "status": "significant_generalization_gap",
                    "overfitting_warning": True,
                    "metric_gaps": {
                        "threat_positive_f1": {"gap": 0.2722}
                    },
                },
                "readiness_gate_v5": {
                    "decision": "internal_benchmark_validated_candidate",
                    "passed": 4,
                    "total": 8,
                    "external_benchmark_validated": False,
                },
                "production_promoted": False,
                "model_activated": False,
                "response_automation_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    v355_queue_path.write_text(
        json.dumps(
            {
                "ok": True,
                "phase": "v3.55",
                "generated_at": "2026-06-23T17:00:00+00:00",
                "best_strategy": "binary_review_queue_queue_only",
                "strategy_comparison": {
                    "binary_review_queue_queue_only": {
                        "policy_name": "binary_review_queue",
                        "policy": {
                            "description": "Only model whether a row enters the SOC review queue.",
                        },
                        "stability": {
                            "evaluated_splits": 5,
                            "passing_splits": 5,
                            "passed": True,
                            "metric_ranges": {
                                "queue_f1": {"min": 0.9725, "max": 0.9962},
                                "queue_recall": {"min": 0.948, "max": 0.9925},
                                "queue_precision": {"min": 0.9907, "max": 1.0},
                                "benign_like_false_positive_rate": {"max": 0.04},
                                "critical_recall_min": {"min": 0.948},
                                "macro_f1": {"min": 0.7481},
                                "weighted_f1": {"min": 0.9589},
                            },
                        },
                        "best_calibration": {
                            "status": "passed",
                            "expected_calibration_error": 0.007,
                            "brier_score_threat_positive": 0.0224,
                            "max_confidence_accuracy_gap": 0.0224,
                        },
                        "threshold_selection": {
                            "selected_on": ["train_internal_calibration"],
                        },
                    }
                },
                "readiness": {
                    "decision": "candidate_only",
                    "passed": 10,
                    "total": 10,
                    "blockers": [],
                },
                "safety": {
                    "production_promoted": False,
                    "model_activated": False,
                    "model_artifact_written": False,
                    "labels_written": False,
                    "response_automation_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    v357_agreement_path.write_text(
        json.dumps(
            {
                "ok": True,
                "phase": "v3.57",
                "generated_at": "2026-06-24T10:20:00+00:00",
                "policy_name": "binary_review_queue",
                "aggregate": {
                    "evaluated_splits": 5,
                    "passing_splits": 4,
                    "queue_f1_min": 0.9725,
                    "queue_recall_min": 0.948,
                    "queue_precision_min": 0.9907,
                    "queue_false_positive_rate_max": 0.04,
                    "agreement_rate_min": 0.884,
                    "agreement_rate_max": 0.9888,
                    "calibration_ece_max": 0.0137,
                    "category_counts": {
                        "queue_and_evidence_agree_review": 3376,
                        "evidence_only_review": 310,
                        "queue_and_evidence_agree_non_review": 324,
                    },
                    "top_evidence_only_patterns": [
                        ["app=quic-base|action=allow|port=443", 71],
                    ],
                    "top_queue_only_patterns": [],
                    "blockers": ["grouped_stratified: evidence-only review rate above 0.10"],
                },
                "readiness": {
                    "decision": "diagnostic_only",
                    "passed": 7,
                    "total": 8,
                    "blockers": ["evidence-only misses remain reviewable"],
                },
                "safety": {
                    "production_promoted": False,
                    "model_activated": False,
                    "model_artifact_written": False,
                    "labels_written": False,
                    "raw_logs_included": False,
                    "response_automation_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    v359_policy_path.write_text(
        json.dumps(
            {
                "ok": True,
                "status": "completed",
                "phase": "v3.59",
                "generated_at": "2026-06-24T11:20:00+00:00",
                "contract": {
                    "decision": "decision_support_contract_ready",
                    "contract_ready_for_runtime_activation": False,
                    "contract_ready_for_dashboard_guidance": True,
                    "recommended_supervised_strategy": "binary_soc_review_queue",
                    "exact_classification_policy": "explanation_or_ranking_only",
                    "queue": {
                        "status": "stable",
                        "readiness_decision": "candidate_only",
                        "evaluated_splits": 5,
                        "passing_splits": 5,
                        "queue_f1_min": 0.9725,
                        "queue_recall_min": 0.948,
                        "queue_precision_min": 0.9907,
                        "benign_like_false_positive_rate_max": 0.04,
                        "calibration_status": "passed",
                        "calibration_ece": 0.007,
                    },
                    "queue_evidence_agreement": {
                        "status": "usable_with_review",
                        "readiness_decision": "diagnostic_only",
                        "evaluated_splits": 5,
                        "passing_splits": 4,
                        "agreement_rate_min": 0.884,
                        "queue_false_positive_rate_max": 0.04,
                    },
                    "exact_severity": {
                        "status": "unstable",
                        "stable_policy_count": 0,
                        "evaluated_policy_count": 6,
                    },
                    "allowed_outputs": {
                        "soc_review_queue_score": {"status": "allowed_for_decision_support"},
                        "exact_severity_or_attack_label": {"status": "explanation_or_ranking_only"},
                        "rule_hybrid_evidence": {"status": "primary_detection_evidence"},
                    },
                    "blocked_uses": [
                        "automatic response from supervised ML output",
                        "real firewall blocking from supervised ML output",
                        "marking AI-generated labels as human-reviewed",
                    ],
                    "checks_passed": 7,
                    "checks_total": 7,
                    "blockers": [],
                    "safety_statement": "Supervised ML may guide SOC review prioritization only.",
                },
                "safety": {
                    "production_promoted": False,
                    "model_activated": False,
                    "model_artifact_written": False,
                    "labels_written": False,
                    "raw_logs_included": False,
                    "response_automation_allowed": False,
                    "real_firewall_blocking_enabled": False,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dashboard_router, "VALIDATION_REPORT_DIR", report_dir)
    monkeypatch.setattr(dashboard_router, "GENERALIZATION_REPORT_DIR", generalization_dir)
    monkeypatch.setattr(dashboard_router, "LAYERED_REPORT_DIR", layered_dir)
    monkeypatch.setattr(dashboard_router, "E2E_REPORT_DIR", e2e_dir)
    monkeypatch.setattr(dashboard_router, "RELIABILITY_REPORT_DIR", reliability_dir)
    monkeypatch.setattr(dashboard_router, "BENCHMARK_REPORT_DIR", reliability_dir)
    monkeypatch.setattr(dashboard_router, "V13_REPORT_DIR", reliability_dir)
    client = _client()
    try:
        unauthorized = client.get("/api/dashboard/validation-summary")
        assert unauthorized.status_code == 401
        headers = _login(client, "analyst", "analyst123")
        response = client.get("/api/dashboard/validation-summary", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["available"] is True
        assert payload["ok"] is True
        assert payload["scenario_count"] == 14
        assert payload["passed_count"] == 14
        assert payload["latest_report_name"] == report_path.name
        assert payload["latest_risk_calibration_name"].endswith("_risk_calibration.md")
        assert payload["generalization"]["available"] is True
        assert payload["generalization"]["variant_count"] == 70
        assert payload["generalization"]["passed_count"] == 70
        assert payload["generalization"]["false_positive_count"] == 0
        assert payload["generalization"]["false_negative_count"] == 0
        assert payload["generalization"]["latest_report_name"] == generalization_path.name
        assert payload["layered"]["available"] is True
        assert payload["layered"]["mode_run_count"] == 168
        assert payload["layered"]["passed_count"] == 168
        assert payload["layered"]["false_positive_count"] == 0
        assert payload["layered"]["false_negative_count"] == 0
        assert payload["layered"]["latest_report_name"] == layered_path.name
        assert payload["e2e_workflow"]["available"] is True
        assert payload["e2e_workflow"]["scenario_count"] == 3
        assert payload["e2e_workflow"]["passed_count"] == 3
        assert payload["e2e_workflow"]["alert_count"] == 2
        assert payload["e2e_workflow"]["case_count"] == 1
        assert payload["e2e_workflow"]["response_actions_created"] == 3
        assert payload["e2e_workflow"]["latest_report_name"] == e2e_path.name
        assert payload["reliability"]["available"] is True
        assert payload["reliability"]["scenario_count"] == 14
        assert payload["reliability"]["scenario_passed_count"] == 14
        assert payload["reliability"]["variant_count"] == 70
        assert payload["reliability"]["mode_run_count"] == 168
        assert payload["reliability"]["false_positive_count"] == 0
        assert payload["reliability"]["false_negative_count"] == 0
        assert payload["benchmark"]["available"] is True
        assert payload["benchmark"]["total_rows"] == 10
        assert payload["benchmark"]["f1"] == 1
        assert payload["benchmark"]["dataset_name"] == "benchmark_snapshot_demo"
        assert payload["benchmark"]["detection_mode"] == "hybrid"
        assert payload["benchmark"]["readiness_decision"] == "candidate_only"
        assert payload["drift"]["available"] is True
        assert payload["drift"]["warning_count"] == 0
        assert payload["drift"]["alert_rate"] == 0.02
        assert payload["v13_ai"]["available"] is True
        assert payload["v13_ai"]["reviewed_label_count"] == 1528
        assert payload["v13_ai"]["minimum_label_gap"] == 44
        assert payload["v13_ai"]["best_candidate"] == "extra_trees"
        assert payload["v13_ai"]["readiness_decision"] == "analyst_review_eligible"
        assert payload["v13_ai"]["response_automation_allowed"] is False
        assert payload["v14_ai"]["available"] is True
        assert payload["v14_ai"]["best_profile"] == "calibrated_low_noise"
        assert payload["v14_ai"]["benign_like_false_positive_rate"] == 0.06
        assert payload["v14_ai"]["malicious_recall"] == 0.7
        assert payload["v14_ai"]["calibration_status"] == "passed"
        assert payload["v14_ai"]["production_promoted"] is False
        assert payload["v14_ai"]["response_automation_allowed"] is False
        assert payload["v14_ai"]["false_positives_improved"] is True
        assert payload["v14_ai"]["current_blocker"] == "malicious recall and calibration"
        assert (
            payload["v14_ai"]["quic_mitigation_status"]
            == "validated candidate; not activated"
        )
        assert payload["v14_ai"]["confirmed_noisy_pattern"] == "normal QUIC/443"
        assert payload["v14_ai"]["quic_false_positive_count"] == 42
        assert payload["v14_ai"]["actionable_review_rows"] == 200
        assert payload["v14_ai"]["actionable_review_excludes_manual"] is True
        assert payload["v14_ai"]["malicious_recovery_review_rows"] == 150
        assert payload["v15_ai"]["available"] is True
        assert payload["v15_ai"]["benchmark_label_count"] == 240
        assert payload["v15_ai"]["benchmark_target_met"] is True
        assert (
            payload["v15_ai"]["readiness_decision"]
            == "benchmark_validated_candidate"
        )
        assert payload["v15_ai"]["calibration_status"] == "passed"
        assert payload["v15_ai"]["production_promoted"] is False
        assert payload["v15_ai"]["model_activated"] is False
        assert payload["v15_ai"]["response_automation_allowed"] is False
        assert payload["v16_ai"]["available"] is True
        assert payload["v16_ai"]["external_label_count"] == 320
        assert payload["v16_ai"]["source_count"] == 5
        assert payload["v16_ai"]["scenario_count"] == 14
        assert payload["v16_ai"]["threat_positive_f1"] == 0.7278
        assert payload["v16_ai"]["benign_like_false_positive_rate"] == 0.3467
        assert payload["v16_ai"]["calibration_status"] == "weak"
        assert (
            payload["v16_ai"]["overfitting_status"]
            == "significant_generalization_gap"
        )
        assert (
            payload["v16_ai"]["readiness_decision"]
            == "internal_benchmark_validated_candidate"
        )
        assert payload["v16_ai"]["external_benchmark_validated"] is False
        assert payload["v16_ai"]["production_promoted"] is False
        assert payload["v16_ai"]["model_activated"] is False
        assert payload["v16_ai"]["response_automation_allowed"] is False
        assert payload["v355_soc_queue"]["available"] is True
        assert payload["v355_soc_queue"]["best_strategy"] == "binary_review_queue_queue_only"
        assert payload["v355_soc_queue"]["policy_name"] == "binary_review_queue"
        assert payload["v355_soc_queue"]["passing_splits"] == 5
        assert payload["v355_soc_queue"]["evaluated_splits"] == 5
        assert payload["v355_soc_queue"]["queue_f1_min"] == 0.9725
        assert payload["v355_soc_queue"]["benign_like_false_positive_rate_max"] == 0.04
        assert payload["v355_soc_queue"]["calibration_status"] == "passed"
        assert payload["v355_soc_queue"]["readiness_decision"] == "candidate_only"
        assert payload["v355_soc_queue"]["production_promoted"] is False
        assert payload["v355_soc_queue"]["model_activated"] is False
        assert payload["v355_soc_queue"]["labels_written"] is False
        assert payload["v355_soc_queue"]["response_automation_allowed"] is False
        assert payload["v355_soc_queue"]["diagnostic_only"] is True
        assert payload["v357_queue_evidence_agreement"]["available"] is True
        assert payload["v357_queue_evidence_agreement"]["phase"] == "v3.57"
        assert payload["v357_queue_evidence_agreement"]["policy_name"] == "binary_review_queue"
        assert payload["v357_queue_evidence_agreement"]["passing_splits"] == 4
        assert payload["v357_queue_evidence_agreement"]["evaluated_splits"] == 5
        assert payload["v357_queue_evidence_agreement"]["queue_f1_min"] == 0.9725
        assert payload["v357_queue_evidence_agreement"]["queue_false_positive_rate_max"] == 0.04
        assert payload["v357_queue_evidence_agreement"]["agreement_rate_min"] == 0.884
        assert payload["v357_queue_evidence_agreement"]["calibration_ece_max"] == 0.0137
        assert payload["v357_queue_evidence_agreement"]["category_counts"]["evidence_only_review"] == 310
        assert (
            payload["v357_queue_evidence_agreement"]["top_evidence_only_patterns"][0][0]
            == "app=quic-base|action=allow|port=443"
        )
        assert payload["v357_queue_evidence_agreement"]["readiness_decision"] == "diagnostic_only"
        assert payload["v357_queue_evidence_agreement"]["checks_passed"] == 7
        assert payload["v357_queue_evidence_agreement"]["checks_total"] == 8
        assert payload["v357_queue_evidence_agreement"]["production_promoted"] is False
        assert payload["v357_queue_evidence_agreement"]["model_activated"] is False
        assert payload["v357_queue_evidence_agreement"]["labels_written"] is False
        assert payload["v357_queue_evidence_agreement"]["raw_logs_included"] is False
        assert payload["v357_queue_evidence_agreement"]["response_automation_allowed"] is False
        assert payload["v357_queue_evidence_agreement"]["diagnostic_only"] is True
        assert payload["v359_supervised_output_policy"]["available"] is True
        assert payload["v359_supervised_output_policy"]["phase"] == "v3.59"
        assert payload["v359_supervised_output_policy"]["decision"] == "decision_support_contract_ready"
        assert payload["v359_supervised_output_policy"]["recommended_supervised_strategy"] == "binary_soc_review_queue"
        assert payload["v359_supervised_output_policy"]["exact_classification_policy"] == "explanation_or_ranking_only"
        assert payload["v359_supervised_output_policy"]["contract_ready_for_runtime_activation"] is False
        assert payload["v359_supervised_output_policy"]["contract_ready_for_dashboard_guidance"] is True
        assert payload["v359_supervised_output_policy"]["queue_status"] == "stable"
        assert payload["v359_supervised_output_policy"]["queue_passing_splits"] == 5
        assert payload["v359_supervised_output_policy"]["queue_evaluated_splits"] == 5
        assert payload["v359_supervised_output_policy"]["queue_f1_min"] == 0.9725
        assert payload["v359_supervised_output_policy"]["queue_benign_like_false_positive_rate_max"] == 0.04
        assert payload["v359_supervised_output_policy"]["agreement_status"] == "usable_with_review"
        assert payload["v359_supervised_output_policy"]["agreement_passing_splits"] == 4
        assert payload["v359_supervised_output_policy"]["exact_severity_status"] == "unstable"
        assert payload["v359_supervised_output_policy"]["exact_stable_policy_count"] == 0
        assert payload["v359_supervised_output_policy"]["allowed_output_statuses"]["soc_review_queue_score"] == "allowed_for_decision_support"
        assert "automatic response from supervised ML output" in payload["v359_supervised_output_policy"]["blocked_uses"]
        assert payload["v359_supervised_output_policy"]["production_promoted"] is False
        assert payload["v359_supervised_output_policy"]["model_activated"] is False
        assert payload["v359_supervised_output_policy"]["labels_written"] is False
        assert payload["v359_supervised_output_policy"]["raw_logs_included"] is False
        assert payload["v359_supervised_output_policy"]["response_automation_allowed"] is False
        assert payload["v359_supervised_output_policy"]["real_firewall_blocking_enabled"] is False
        assert payload["v359_supervised_output_policy"]["diagnostic_only"] is True
        assert str(report_dir) not in json.dumps(payload)
        assert str(generalization_dir) not in json.dumps(payload)
        assert str(layered_dir) not in json.dumps(payload)
        assert str(e2e_dir) not in json.dumps(payload)
        assert str(reliability_dir) not in json.dumps(payload)
        assert payload["production_readiness_claim"] is False
        assert payload["generalization"]["production_readiness_claim"] is False
        assert payload["layered"]["production_readiness_claim"] is False
        assert payload["e2e_workflow"]["production_readiness_claim"] is False
        assert payload["reliability"]["production_readiness_claim"] is False
        assert payload["benchmark"]["production_readiness_claim"] is False
        assert payload["drift"]["production_readiness_claim"] is False
    finally:
        app.dependency_overrides.clear()
        shutil.rmtree(report_dir.parent, ignore_errors=True)
        get_settings.cache_clear()


def test_detection_tuning_report_requires_auth_and_returns_shape():
    client = _client()
    try:
        unauthorized = client.get("/api/detection/tuning")
        assert unauthorized.status_code == 401

        headers = _login(client, "analyst", "analyst123")
        response = client.get("/api/detection/tuning", headers=headers)
        assert response.status_code == 200
        payload = response.json()

        assert "summary" in payload
        assert "alert_type_pressure" in payload
        assert "suppression_candidates" in payload
        assert "ml" in payload
        assert "production_readiness" in payload
        assert "recommendations" in payload
        assert "false_positive_learning" in payload
        assert payload["summary"]["total_alerts"] >= 1
        assert any(item["name"] == "Response Safety" for item in payload["production_readiness"])
    finally:
        app.dependency_overrides.clear()


def test_unauthorized_response_access_is_rejected():
    client = _client()
    try:
        response = client.post(
            "/api/response/block-ip",
            json={"target_ip": "203.0.113.99", "reason": "api test"},
            headers={"X-Request-ID": "blocked-test-id"},
        )
        assert response.status_code == 401
        assert response.headers["X-Request-ID"] == "blocked-test-id"
        assert response.json()["request_id"] == "blocked-test-id"
    finally:
        app.dependency_overrides.clear()


def test_analyst_cannot_block_ip():
    client = _client()
    try:
        headers = _login(client, "analyst", "analyst123")
        response = client.post(
            "/api/response/block-ip",
            json={"target_ip": "203.0.113.99", "reason": "api test"},
            headers=headers,
        )
        assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_alert_workflow_requires_auth_and_audits_user():
    client = _client()
    try:
        unauthorized = client.post("/api/alerts/1/resolve")
        assert unauthorized.status_code == 401

        headers = _login(client, "analyst", "analyst123")
        resolved = client.post("/api/alerts/1/resolve", headers=headers)
        assert resolved.status_code == 200
        assert resolved.json()["status"] == "resolved"

        audit = client.get("/api/audit", headers=headers)
        assert audit.status_code == 200
        assert audit.json()[0]["actor"] == "analyst"
        assert audit.json()[0]["action"] == "alert_resolved"
    finally:
        app.dependency_overrides.clear()


def test_alert_status_transition_api_supports_new_workflow_states():
    client = _client()
    try:
        headers = _login(client, "analyst", "analyst123")
        for status in ["investigating", "needs_more_context", "contained", "resolved", "false_positive", "open"]:
            response = client.post("/api/alerts/1/status", json={"status": status}, headers=headers)
            assert response.status_code == 200
            assert response.json()["status"] == status

        invalid = client.post("/api/alerts/1/status", json={"status": "archived"}, headers=headers)
        assert invalid.status_code == 400
    finally:
        app.dependency_overrides.clear()


def test_alert_cases_group_related_alerts():
    client = _client()
    try:
        headers = _login(client, "analyst", "analyst123")
        response = client.get("/api/alerts/cases", headers=headers)

        assert response.status_code == 200
        payload = response.json()
        assert payload
        assert payload[0]["related_alert_count"] >= 1
        assert "case_id" in payload[0]
        assert "total_related_logs" in payload[0]
        assert "top_destination_ports" in payload[0]
        assert "top_actions" in payload[0]
        assert "recommended_analyst_focus" in payload[0]
        assert payload[0]["status"] in {"open", "investigating", "contained", "needs_more_context"}
    finally:
        app.dependency_overrides.clear()


def test_alert_assignment_notes_and_timeline_api():
    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        assign_self = client.post("/api/alerts/1/assign/me", headers=analyst_headers)
        assert assign_self.status_code == 200
        assert assign_self.json()["assigned_to"] == "analyst"

        mine = client.get("/api/alerts?mine=true", headers=analyst_headers)
        assert mine.status_code == 200
        assert mine.json()[0]["assigned_to"] == "analyst"

        unassigned = client.get("/api/alerts?unassigned=true", headers=analyst_headers)
        assert unassigned.status_code == 200
        assert unassigned.json() == []

        forbidden_assign = client.post("/api/alerts/1/assign", json={"username": "admin"}, headers=analyst_headers)
        assert forbidden_assign.status_code == 403

        note = client.post(
            "/api/alerts/1/notes",
            json={"note": "Investigating suspicious grouped activity."},
            headers=analyst_headers,
        )
        assert note.status_code == 200
        assert note.json()["author"] == "analyst"

        notes = client.get("/api/alerts/1/notes", headers=analyst_headers)
        assert notes.status_code == 200
        assert notes.json()[0]["note"] == "Investigating suspicious grouped activity."

        timeline = client.get("/api/alerts/1/timeline", headers=analyst_headers)
        assert timeline.status_code == 200
        event_types = {event["event_type"] for event in timeline.json()}
        assert "created" in event_types
        assert "alert_assigned" in event_types
        assert "alert_note_added" in event_types

        admin_headers = _login(client, "admin", "admin123")
        admin_assign = client.post("/api/alerts/1/assign", json={"username": "admin"}, headers=admin_headers)
        assert admin_assign.status_code == 200
        assert admin_assign.json()["assigned_to"] == "admin"

        escalated = client.post(
            "/api/alerts/1/escalate",
            json={
                "priority_owner": "analyst",
                "escalation_reason": "Supervisor review required.",
                "ticket_reference": "MFU-INC-001",
            },
            headers=analyst_headers,
        )
        assert escalated.status_code == 200
        assert escalated.json()["priority_owner"] == "analyst"
        assert escalated.json()["ticket_reference"] == "MFU-INC-001"

        report = client.get("/api/alerts/1/report", headers=analyst_headers)
        assert report.status_code == 200
        assert report.json()["alert"]["id"] == 1
        assert report.json()["generated_by"] == "analyst"
        assert "executive_summary" in report.json()
        assert "risk_assessment" in report.json()
        assert "recommended_next_steps" in report.json()
        assert "timeline" in report.json()
        assert report.json()["sla"]["label"] == "Review"

        csv_report = client.get("/api/alerts/1/report?format=csv", headers=analyst_headers)
        assert csv_report.status_code == 200
        assert "text/csv" in csv_report.headers["content-type"]

        html_report = client.get("/api/alerts/1/report?format=html", headers=analyst_headers)
        assert html_report.status_code == 200
        assert "text/html" in html_report.headers["content-type"]
        assert "ATDR Incident Report" in html_report.text

        pdf_report = client.get("/api/alerts/1/report?format=pdf", headers=analyst_headers)
        assert pdf_report.status_code == 200
        assert "application/pdf" in pdf_report.headers["content-type"]
        assert pdf_report.content.startswith(b"%PDF")
    finally:
        app.dependency_overrides.clear()


def test_list_filters_support_react_dashboard_tables(tmp_path):
    sample = tmp_path / "filters.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")

    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        imported = client.post(
            "/api/logs/import",
            data={"file_path": str(sample), "limit": "10"},
            headers=admin_headers,
        )
        assert imported.status_code == 200

        analyst_headers = _login(client, "analyst", "analyst123")
        logs = client.get(
            "/api/logs",
            params={
                "search": "Allow-Outside",
                "protocol": "icmp",
                "src_zone": "SG-Outside",
                "dst_zone": "WLAN-Inside",
                "sort_by": "app_risk",
            },
            headers=analyst_headers,
        )
        assert logs.status_code == 200
        assert int(logs.headers["X-Total-Count"]) >= 1
        assert logs.json()[0]["src_ip"] == "43.210.171.152"
        assert logs.json()[0]["protocol"] == "icmp"
        log_id = logs.json()[0]["id"]
        log_detail = client.get(f"/api/logs/{log_id}", headers=analyst_headers)
        assert log_detail.status_code == 200
        triage = log_detail.json()["triage_explanation"]
        assert triage["status"] == "not_flagged"
        assert triage["decision_support_only"] is True
        assert triage["response_automation_allowed"] is False

        alerts = client.get(
            "/api/alerts",
            params={"search": "API test", "src_ip": "203.0.113.50", "alert_type": "api"},
            headers=analyst_headers,
        )
        assert alerts.status_code == 200
        assert int(alerts.headers["X-Total-Count"]) == 1
        assert alerts.json()[0]["alert_type"] == "api_test"

        updated = client.post("/api/alerts/1/investigate", headers=analyst_headers)
        assert updated.status_code == 200
        audit = client.get(
            "/api/audit",
            params={"actor": "analyst", "action": "alert_investigating", "target_type": "alert", "target_value": "1"},
            headers=analyst_headers,
        )
        assert audit.status_code == 200
        assert int(audit.headers["X-Total-Count"]) >= 1
        assert audit.json()[0]["action"] == "alert_investigating"
    finally:
        app.dependency_overrides.clear()


def test_run_history_api_tracks_ingestion_and_detection(tmp_path):
    sample = tmp_path / "run-history.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")

    client = _client()
    try:
        headers = _login(client, "admin", "admin123")
        imported = client.post("/api/logs/import", data={"file_path": str(sample), "limit": "10"}, headers=headers)
        assert imported.status_code == 200
        assert imported.json()["run_id"] >= 1

        detection = client.post("/api/detection/run?limit=10&use_ml=false", headers=headers)
        assert detection.status_code == 200
        assert detection.json()["detection_run_id"] >= 1

        ingestion_runs = client.get("/api/ingestion/runs", headers=headers)
        assert ingestion_runs.status_code == 200
        assert ingestion_runs.json()[0]["source_type"] == "file_import"
        assert ingestion_runs.json()[0]["parsed_successfully"] == 1
        ingestion_run = client.get(f"/api/ingestion/runs/{ingestion_runs.json()[0]['run_id']}", headers=headers)
        assert ingestion_run.status_code == 200

        detection_runs = client.get("/api/detection/runs", headers=headers)
        assert detection_runs.status_code == 200
        assert detection_runs.json()[0]["detection_type"] == "rule"
        assert detection_runs.json()[0]["logs_evaluated"] >= 1
        detection_run = client.get(f"/api/detection/runs/{detection_runs.json()[0]['run_id']}", headers=headers)
        assert detection_run.status_code == 200

        summary = client.get("/api/dashboard/summary", headers=headers)
        assert summary.status_code == 200
        assert summary.json()["latest_ingestion_run"]["run_id"] == ingestion_runs.json()[0]["run_id"]
        assert summary.json()["latest_detection_run"]["run_id"] == detection_runs.json()[0]["run_id"]
    finally:
        app.dependency_overrides.clear()


def test_source_management_and_import_fallback_source():
    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        analyst_headers = _login(client, "analyst", "analyst123")

        unauthorized = client.get("/api/sources")
        assert unauthorized.status_code == 401

        created = client.post(
            "/api/sources",
            json={
                "name": "lab-firewall-1",
                "source_type": "firewall",
                "parser_profile": "palo_alto",
                "host": "192.0.2.10",
                "port": 514,
            },
            headers=admin_headers,
        )
        assert created.status_code == 200
        source = created.json()
        assert source["health"]["status"] == "idle"
        assert source["parser_profile"] == "palo_alto"

        listed = client.get("/api/sources", headers=analyst_headers)
        assert listed.status_code == 200
        assert any(item["name"] == "lab-firewall-1" for item in listed.json())

        imported_with_source = client.post(
            "/api/logs/import",
            data={"file_path": "data/samples/paloalto-demo.txt", "limit": "2", "source_id": str(source["source_id"])},
            headers=admin_headers,
        )
        assert imported_with_source.status_code == 200
        assert imported_with_source.json()["source_id"] == source["source_id"]

        source_logs = client.get("/api/logs", params={"source_id": source["source_id"]}, headers=analyst_headers)
        assert source_logs.status_code == 200
        assert int(source_logs.headers["X-Total-Count"]) == 2
        assert source_logs.json()[0]["source_name"] == "lab-firewall-1"

        detection = client.post("/api/detection/run?limit=20&use_ml=false", headers=admin_headers)
        assert detection.status_code == 200
        source_alerts = client.get("/api/alerts", params={"source_id": source["source_id"]}, headers=analyst_headers)
        assert source_alerts.status_code == 200
        assert int(source_alerts.headers["X-Total-Count"]) >= 1

        disabled = client.patch(f"/api/sources/{source['source_id']}", json={"enabled": False}, headers=admin_headers)
        assert disabled.status_code == 200
        assert disabled.json()["health"]["status"] == "disabled"
        assert disabled.json()["logs_received_count"] == 2
        assert disabled.json()["quality"]["raw_logs"] == 2

        disabled_logs = client.get("/api/logs", params={"source_status": "disabled"}, headers=analyst_headers)
        assert disabled_logs.status_code == 200
        assert int(disabled_logs.headers["X-Total-Count"]) >= 1

        imported = client.post(
            "/api/logs/import",
            data={"file_path": "data/samples/paloalto-demo.txt", "limit": "2"},
            headers=admin_headers,
        )
        assert imported.status_code == 200
        import_payload = imported.json()
        assert import_payload["source_id"] is not None

        sources = client.get("/api/sources", headers=analyst_headers).json()
        fallback = next(item for item in sources if item["name"] == "local_import")
        assert fallback["logs_received_count"] == 2
        assert fallback["parse_success_count"] == 2

        health = client.get(f"/api/sources/{fallback['source_id']}/health", headers=analyst_headers)
        assert health.status_code == 200
        assert health.json()["status"] in {"healthy", "warning", "idle"}

        source_detail = client.get(f"/api/sources/{fallback['source_id']}", headers=analyst_headers)
        assert source_detail.status_code == 200
        assert "quality" in source_detail.json()
        assert "recent_ingestion_runs" in source_detail.json()
    finally:
        app.dependency_overrides.clear()


def test_demo_control_endpoints_are_admin_only_and_operational(tmp_path):
    sample = tmp_path / "sample.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")

    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        forbidden = client.post("/api/demo/run-detection", json={"limit": 10}, headers=analyst_headers)
        assert forbidden.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        reset = client.post(
            "/api/demo/reset",
            json={"limit": 1, "sample_path": str(sample), "use_ml": False},
            headers=admin_headers,
        )
        assert reset.status_code == 200
        assert reset.json()["import"]["parsed"] == 1

        detection = client.post("/api/demo/run-detection", json={"limit": 10, "use_ml": False}, headers=admin_headers)
        assert detection.status_code == 200
        assert "created_alerts" in detection.json()

        train = client.post("/api/demo/train-ml", json={"limit": 10}, headers=admin_headers)
        assert train.status_code == 200
        assert train.json()["trained"] is False
        assert train.json()["status"] == "skipped"

        apply_ml = client.post("/api/demo/apply-ml", json={"limit": 10}, headers=admin_headers)
        assert apply_ml.status_code == 200
        assert "scored" in apply_ml.json()
        assert "anomalies" in apply_ml.json()
    finally:
        app.dependency_overrides.clear()


def test_demo_import_sample_reports_requested_available_and_raw_counts(tmp_path):
    sample = tmp_path / "tiny-safe-sample.log"
    sample.write_text(TRAFFIC_LINE + "\n" + TRAFFIC_LINE.replace("35845233", "35845234") + "\n", encoding="utf-8")

    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        response = client.post(
            "/api/demo/import-sample",
            json={"limit": 1000, "sample_path": str(sample)},
            headers=admin_headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["requested_limit"] == 1000
        assert payload["available_lines"] == 2
        assert payload["raw_logs_imported"] == 2
        assert payload["normalized_logs_created"] == 2
        assert payload["parsed_successfully"] == 2
        assert payload["parse_failures"] == 0
        assert payload["alerts_created"] == 0
        assert payload["alerts_deduplicated"] == 0
        assert payload["source"] == "tiny-safe-sample.log"
        assert "contains 2 non-empty log lines" in payload["safe_sample_note"]
    finally:
        app.dependency_overrides.clear()


def test_demo_import_sample_imports_up_to_limit_when_larger_file_available(tmp_path):
    sample = tmp_path / "larger-sample.log"
    lines = [TRAFFIC_LINE.replace("35845233", str(35845233 + index)) for index in range(5)]
    sample.write_text("\n".join(lines) + "\n", encoding="utf-8")

    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        response = client.post(
            "/api/demo/import-sample",
            json={"limit": 4, "sample_path": str(sample)},
            headers=admin_headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["requested_limit"] == 4
        assert payload["available_lines"] == 5
        assert payload["raw_logs_imported"] == 4
        assert payload["normalized_logs_created"] == 4
        assert payload["parsed_successfully"] == 4
        assert payload["safe_sample_note"] is None
    finally:
        app.dependency_overrides.clear()


def test_demo_import_sample_accepts_quoted_windows_style_path(tmp_path):
    sample = tmp_path / "quoted-sample.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")

    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        response = client.post(
            "/api/demo/import-sample",
            json={"limit": 1, "sample_path": f'"{sample}"'},
            headers=admin_headers,
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["available_lines"] == 1
        assert payload["raw_logs_imported"] == 1
        assert payload["source"] == "quoted-sample.log"
    finally:
        app.dependency_overrides.clear()


def test_demo_import_sample_missing_file_returns_clean_404(tmp_path):
    missing = tmp_path / "missing.log"

    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        response = client.post(
            "/api/demo/import-sample",
            json={"limit": 1, "sample_path": f'"{missing}"'},
            headers=admin_headers,
        )
        assert response.status_code == 404
        assert "Sample log file not found" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_demo_bundle_export_is_admin_only_and_writes_expected_files(tmp_path):
    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        forbidden = client.post(
            "/api/demo/export-bundle",
            json={"output_dir": str(tmp_path)},
            headers=analyst_headers,
        )
        assert forbidden.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        exported = client.post(
            "/api/demo/export-bundle",
            json={"output_dir": str(tmp_path), "alert_id": 1, "top_alert_limit": 5, "audit_limit": 5},
            headers=admin_headers,
        )
        assert exported.status_code == 200
        payload = exported.json()
        assert payload["counts"]["total_alerts"] == 1
        assert payload["selected_alert_id"] == 1
        expected_files = {
            "dashboard_summary.json",
            "top_alerts.json",
            "recent_audit.json",
            "ml_evaluation.json",
            "alert_1_report.json",
            "alert_1_report.csv",
            "alert_1_report.html",
            "alert_1_report.pdf",
            "demo_summary.md",
        }
        assert expected_files.issubset(set(payload["files"]))
        for path in payload["files"].values():
            assert tmp_path in Path(path).parents

        audit = client.get("/api/audit", headers=admin_headers)
        assert any(row["action"] == "demo_bundle_exported" for row in audit.json())
    finally:
        app.dependency_overrides.clear()


def test_ml_governance_endpoints_are_secured_and_record_runs():
    client = _client()
    try:
        unauthorized = client.get("/api/ml/status")
        assert unauthorized.status_code == 401

        analyst_headers = _login(client, "analyst", "analyst123")
        status = client.get("/api/ml/status", headers=analyst_headers)
        assert status.status_code == 200
        assert status.json()["model_name"] == "isolation_forest"
        assert "feature_columns" in status.json()

        profile = client.get("/api/ml/profile", headers=analyst_headers)
        assert profile.status_code == 200
        assert profile.json()["total_logs"] == 0
        assert "recommendations" in profile.json()

        report = client.get("/api/ml/report", headers=analyst_headers)
        assert report.status_code == 200
        assert report.json()["scored_log_count"] == 0
        assert report.json()["run_comparison"]["latest"] is None
        assert report.json()["drift_signals"][0]["metric"] == "training_baseline"

        forbidden_train = client.post("/api/ml/train", json={"limit": 10}, headers=analyst_headers)
        assert forbidden_train.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        train = client.post(
            "/api/ml/train",
            json={"limit": 10, "baseline_only": True, "max_app_risk": 3},
            headers=admin_headers,
        )
        assert train.status_code == 200
        assert train.json()["status"] == "skipped"
        assert train.json()["run_id"] >= 1
        assert train.json()["training_filter"]["baseline_only"] is True

        runs = client.get("/api/ml/runs", headers=analyst_headers)
        assert runs.status_code == 200
        assert runs.json()[0]["operation"] == "train"
        assert runs.json()[0]["actor"] == "admin"
    finally:
        app.dependency_overrides.clear()


def test_admin_response_workflow_audit_attribution():
    client = _client()
    try:
        headers = _login(client, "admin", "admin123")

        block = client.post(
            "/api/response/block-ip",
            json={"target_ip": "203.0.113.99", "reason": "api test", "actor": "spoofed"},
            headers=headers,
        )
        assert block.status_code == 200
        assert block.json()["status"] == "simulated"
        assert block.json()["executed_by"] == "admin"

        blocked = client.get("/api/response/blocked-ips", headers=headers)
        assert blocked.status_code == 200
        assert blocked.json()[0]["ip_address"] == "203.0.113.99"
        assert blocked.json()[0]["created_by"] == "admin"

        audit = client.get("/api/audit", headers=headers)
        assert audit.status_code == 200
        assert audit.json()[0]["action"] == "block_ip"
        assert audit.json()[0]["actor"] == "admin"
    finally:
        app.dependency_overrides.clear()


def test_suppression_api_is_admin_only_and_audited():
    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        forbidden = client.post(
            "/api/suppressions",
            json={"src_ip": "203.0.113.50", "alert_type": "api_test", "reason": "Known lab scanner."},
            headers=analyst_headers,
        )
        assert forbidden.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        created = client.post(
            "/api/suppressions",
            json={"src_ip": "203.0.113.50", "alert_type": "api_test", "reason": "Known lab scanner."},
            headers=admin_headers,
        )
        assert created.status_code == 200
        rule_id = created.json()["id"]
        assert created.json()["active"] is True

        rules = client.get("/api/suppressions", headers=analyst_headers)
        assert rules.status_code == 200
        assert rules.json()[0]["id"] == rule_id
        assert rules.json()[0]["review_status"] == "pending"

        reviewed = client.post(
            f"/api/suppressions/{rule_id}/review",
            json={"review_status": "reviewed", "review_notes": "Approved for lab scanner noise."},
            headers=admin_headers,
        )
        assert reviewed.status_code == 200
        assert reviewed.json()["review_status"] == "reviewed"
        assert reviewed.json()["reviewed_by"] == "admin"

        disabled = client.post(f"/api/suppressions/{rule_id}/disable", headers=admin_headers)
        assert disabled.status_code == 200
        assert disabled.json()["active"] is False

        audit = client.get("/api/audit", headers=admin_headers)
        actions = {row["action"] for row in audit.json()}
        assert "suppression_created" in actions
        assert "suppression_reviewed" in actions
        assert "suppression_disabled" in actions
    finally:
        app.dependency_overrides.clear()


def test_watchlist_api_is_admin_only_audited_and_used_by_detection(tmp_path):
    sample = tmp_path / "watchlist.log"
    sample.write_text(TRAFFIC_LINE + "\n", encoding="utf-8")

    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        forbidden = client.post(
            "/api/watchlists",
            json={
                "indicator_type": "src_ip",
                "indicator_value": "43.210.171.152",
                "description": "Known lab watchlist source.",
                "severity_boost": 45,
            },
            headers=analyst_headers,
        )
        assert forbidden.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        imported = client.post(
            "/api/logs/import",
            data={"file_path": str(sample), "limit": "10"},
            headers=admin_headers,
        )
        assert imported.status_code == 200
        assert imported.json()["parsed"] == 1

        created = client.post(
            "/api/watchlists",
            json={
                "indicator_type": "src_ip",
                "indicator_value": "43.210.171.152",
                "description": "Known lab watchlist source.",
                "severity_boost": 45,
            },
            headers=admin_headers,
        )
        assert created.status_code == 200
        item_id = created.json()["id"]

        detection = client.post("/api/detection/run?limit=10&use_ml=false", headers=admin_headers)
        assert detection.status_code == 200
        assert detection.json()["watchlist_matches"] >= 1

        items = client.get("/api/watchlists", headers=analyst_headers)
        assert items.status_code == 200
        assert items.json()[0]["match_count"] >= 1

        disabled = client.post(f"/api/watchlists/{item_id}/disable", headers=admin_headers)
        assert disabled.status_code == 200
        assert disabled.json()["active"] is False

        audit = client.get("/api/audit", headers=admin_headers)
        actions = {row["action"] for row in audit.json()}
        assert "watchlist_created" in actions
        assert "watchlist_disabled" in actions
    finally:
        app.dependency_overrides.clear()


def test_user_admin_and_password_change_controls():
    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")
        forbidden = client.get("/api/users", headers=analyst_headers)
        assert forbidden.status_code == 403

        admin_headers = _login(client, "admin", "admin123")
        created = client.post(
            "/api/users",
            json={
                "username": "tier2",
                "email": "tier2@school.example",
                "password": "tier2pass123",
                "role": "analyst",
                "full_name": "Tier 2 Analyst",
                "email_verified": True,
            },
            headers=admin_headers,
        )
        assert created.status_code == 200
        assert created.json()["email"] == "tier2@school.example"
        assert created.json()["email_verified"] is True
        assert created.json()["auth_provider"] == "local"
        user_id = created.json()["id"]

        email_login = client.post("/api/auth/login", json={"username": "tier2@school.example", "password": "tier2pass123"})
        assert email_login.status_code == 200

        duplicate_email = client.post(
            "/api/users",
            json={"username": "tier3", "email": "tier2@school.example", "password": "tier3pass123", "role": "analyst"},
            headers=admin_headers,
        )
        assert duplicate_email.status_code == 400
        assert "Email already exists" in duplicate_email.json()["detail"]

        invalid_email = client.post(
            "/api/users",
            json={"username": "tier4", "email": "not-an-email", "password": "tier4pass123", "role": "analyst"},
            headers=admin_headers,
        )
        assert invalid_email.status_code == 422

        patched = client.patch(
            f"/api/users/{user_id}",
            json={"email": "tier2-updated@school.example", "email_verified": False},
            headers=admin_headers,
        )
        assert patched.status_code == 200
        assert patched.json()["email"] == "tier2-updated@school.example"
        assert patched.json()["email_verified"] is False

        changed_role = client.post(f"/api/users/{user_id}/role", json={"role": "admin"}, headers=admin_headers)
        assert changed_role.status_code == 200
        assert changed_role.json()["role"] == "admin"

        reset = client.post(
            f"/api/users/{user_id}/reset-password",
            json={"new_password": "newpass123"},
            headers=admin_headers,
        )
        assert reset.status_code == 200
        assert _login(client, "tier2", "newpass123")

        disabled = client.post(f"/api/users/{user_id}/disable", headers=admin_headers)
        assert disabled.status_code == 200
        assert disabled.json()["is_active"] is False

        changed = client.post(
            "/api/auth/change-password",
            json={"current_password": "analyst123", "new_password": "analyst456"},
            headers=analyst_headers,
        )
        assert changed.status_code == 200
        assert client.post("/api/auth/login", json={"username": "analyst", "password": "analyst456"}).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_school_email_domain_policy_can_be_required(monkeypatch):
    monkeypatch.setenv("REQUIRE_SCHOOL_EMAIL", "true")
    monkeypatch.setenv("SCHOOL_EMAIL_DOMAINS", "school.example,mfu.ac.th")
    get_settings.cache_clear()
    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        rejected = client.post(
            "/api/users",
            json={"username": "outsider", "email": "outsider@example.com", "password": "outsider123", "role": "analyst"},
            headers=admin_headers,
        )
        assert rejected.status_code == 400
        assert "Email domain must be one of" in rejected.json()["detail"]

        accepted = client.post(
            "/api/users",
            json={"username": "student", "email": "student@mfu.ac.th", "password": "student123", "role": "analyst"},
            headers=admin_headers,
        )
        assert accepted.status_code == 200
        assert accepted.json()["email"] == "student@mfu.ac.th"
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_failed_login_is_audited_and_rate_limited():
    client = _client()
    try:
        for _ in range(5):
            failed = client.post("/api/auth/login", json={"username": "missing-user", "password": "wrong"})
            assert failed.status_code == 401
        limited = client.post("/api/auth/login", json={"username": "missing-user", "password": "wrong"})
        assert limited.status_code == 429

        admin_headers = _login(client, "admin", "admin123")
        audit = client.get("/api/audit", headers=admin_headers)
        assert audit.status_code == 200
        assert any(row["action"] == "login_failed" and row["target_value"] == "missing-user" for row in audit.json())
    finally:
        app.dependency_overrides.clear()
