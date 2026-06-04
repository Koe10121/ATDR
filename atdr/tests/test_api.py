from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.core.config import get_settings
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert
from atdr.app.main import app
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
