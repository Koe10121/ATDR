from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

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
        for status in ["investigating", "contained", "resolved", "false_positive", "open"]:
            response = client.post("/api/alerts/1/status", json={"status": status}, headers=headers)
            assert response.status_code == 200
            assert response.json()["status"] == status

        invalid = client.post("/api/alerts/1/status", json={"status": "archived"}, headers=headers)
        assert invalid.status_code == 400
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
            json={"username": "tier2", "password": "tier2pass123", "role": "analyst", "full_name": "Tier 2 Analyst"},
            headers=admin_headers,
        )
        assert created.status_code == 200
        user_id = created.json()["id"]

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
