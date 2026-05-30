from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base, get_db
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.main import app
from atdr.app.services.user_service import create_user


def _client() -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    with testing_session() as db:
        create_user(db, username="admin", password="admin123", role="admin", full_name="Test Admin")
        create_user(db, username="analyst", password="analyst123", role="analyst", full_name="Test Analyst")
        raw = RawLog(raw_line="synthetic IAM/RBAC test log", imported_at=now)
        db.add(raw)
        db.flush()
        log = NormalizedLog(
            raw_log_id=raw.id,
            receive_time=now,
            generated_time=now,
            log_type="TRAFFIC",
            subtype="end",
            src_ip="203.0.113.10",
            dst_ip="198.51.100.20",
            app="incomplete",
            action="deny",
            src_zone="untrust",
            dst_zone="trust",
            src_port=43123,
            dst_port=22,
            protocol="tcp",
            bytes=120,
            packets=3,
            app_risk=4,
            parsed_json={"test": "iam_rbac"},
        )
        db.add(log)
        db.flush()
        alert = Alert(
            title="High: IAM/RBAC test alert",
            alert_type="possible_port_scan",
            src_ip="203.0.113.10",
            dst_ip="198.51.100.20",
            threat_score=80,
            severity="High",
            status="open",
            explanation="Synthetic RBAC alert for access-control tests.",
            matched_rules_json=[{"name": "possible_port_scan"}],
            recommended_response="Investigate before simulated containment.",
            created_at=now,
            updated_at=now,
        )
        db.add(alert)
        db.flush()
        db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=log.id))
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
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_protected_api_rejects_unauthenticated_requests():
    client = _client()
    try:
        checks = [
            ("GET", "/api/users", None),
            ("GET", "/api/audit", None),
            ("GET", "/api/logs", None),
            ("GET", "/api/sources", None),
            ("POST", "/api/detection/run?limit=1", None),
            ("POST", "/api/response/block-ip", {"target_ip": "203.0.113.99", "reason": "test"}),
        ]
        for method, path, json_body in checks:
            response = client.request(method, path, json=json_body)
            assert response.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_admin_only_user_and_source_management_permissions():
    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        analyst_headers = _login(client, "analyst", "analyst123")

        assert client.get("/api/users", headers=analyst_headers).status_code == 403
        assert client.get("/api/users", headers=admin_headers).status_code == 200

        source_payload = {
            "name": "rbac-source",
            "source_type": "firewall",
            "parser_profile": "palo_alto",
            "host": "192.0.2.50",
            "port": 514,
            "enabled": True,
        }
        analyst_create = client.post("/api/sources", json=source_payload, headers=analyst_headers)
        assert analyst_create.status_code == 403

        admin_create = client.post("/api/sources", json=source_payload, headers=admin_headers)
        assert admin_create.status_code == 200
        source_id = admin_create.json()["source_id"]

        analyst_patch = client.patch(f"/api/sources/{source_id}", json={"enabled": False}, headers=analyst_headers)
        assert analyst_patch.status_code == 403

        admin_patch = client.patch(f"/api/sources/{source_id}", json={"enabled": False}, headers=admin_headers)
        assert admin_patch.status_code == 200
        assert admin_patch.json()["enabled"] is False

        suppression_payload = {"src_ip": "203.0.113.10", "reason": "RBAC test suppression."}
        assert client.post("/api/suppressions", json=suppression_payload, headers=analyst_headers).status_code == 403
        assert client.post("/api/suppressions", json=suppression_payload, headers=admin_headers).status_code == 200

        watchlist_payload = {
            "indicator_type": "src_ip",
            "indicator_value": "203.0.113.10",
            "description": "RBAC test watchlist.",
            "severity_boost": 20,
        }
        assert client.post("/api/watchlists", json=watchlist_payload, headers=analyst_headers).status_code == 403
        assert client.post("/api/watchlists", json=watchlist_payload, headers=admin_headers).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_analyst_can_use_allowed_investigation_detection_and_label_workflows():
    client = _client()
    try:
        headers = _login(client, "analyst", "analyst123")

        assert client.get("/api/alerts", headers=headers).status_code == 200
        assert client.get("/api/alerts/1", headers=headers).status_code == 200
        assert client.get("/api/logs", headers=headers).status_code == 200
        assert client.get("/api/logs/1", headers=headers).status_code == 200
        assert client.get("/api/audit", headers=headers).status_code == 200

        detection = client.post("/api/detection/run?limit=1&use_ml=false", headers=headers)
        assert detection.status_code == 200
        assert detection.json()

        label = client.post(
            "/api/ml/labels",
            json={
                "log_id": 1,
                "label": "suspicious",
                "attack_type": "port_scan",
                "confidence": 4,
                "review_note": "Analyst RBAC test label.",
            },
            headers=headers,
        )
        assert label.status_code == 200
        assert label.json()["reviewer"] == "analyst"

        export = client.get("/api/ml/labels/export", headers=headers)
        assert export.status_code == 200
        assert "text/csv" in export.headers["content-type"]
    finally:
        app.dependency_overrides.clear()


def test_model_training_and_log_import_are_admin_only():
    client = _client()
    try:
        analyst_headers = _login(client, "analyst", "analyst123")

        assert client.post("/api/ml/train", json={"limit": 1}, headers=analyst_headers).status_code == 403
        assert client.post("/api/ml/score", json={"limit": 1}, headers=analyst_headers).status_code == 403
        assert client.post("/api/ml/supervised/train", headers=analyst_headers).status_code == 403
        assert client.post("/api/logs/import", data={"file_path": "data/samples/paloalto-demo.txt"}, headers=analyst_headers).status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_response_permission_safety_and_denied_attempt_audit():
    client = _client()
    try:
        admin_headers = _login(client, "admin", "admin123")
        analyst_headers = _login(client, "analyst", "analyst123")

        analyst_block = client.post(
            "/api/response/block-ip",
            json={"target_ip": "203.0.113.99", "reason": "Analyst should not be able to block."},
            headers=analyst_headers,
        )
        assert analyst_block.status_code == 403

        missing_note = client.post("/api/response/block-ip", json={"target_ip": "203.0.113.99"}, headers=admin_headers)
        assert missing_note.status_code == 200
        assert missing_note.json()["status"] == "denied"
        assert "justification" in missing_note.json()["result_message"].lower()

        protected = client.post(
            "/api/response/block-ip",
            json={"target_ip": "10.0.0.10", "reason": "Attempt protected internal target."},
            headers=admin_headers,
        )
        assert protected.status_code == 200
        assert protected.json()["status"] == "denied"
        assert "protected" in protected.json()["result_message"].lower()

        audit = client.get("/api/audit", headers=admin_headers)
        assert audit.status_code == 200
        actions = [entry["action"] for entry in audit.json()]
        assert "block_ip_denied" in actions
    finally:
        app.dependency_overrides.clear()


def test_ml_and_detection_do_not_create_automatic_response_actions():
    client = _client()
    try:
        headers = _login(client, "analyst", "analyst123")
        before = client.get("/api/response/blocked-ips", headers=headers)
        assert before.status_code == 200

        detection = client.post("/api/detection/run?limit=1&use_ml=false", headers=headers)
        assert detection.status_code == 200

        after = client.get("/api/response/blocked-ips", headers=headers)
        assert after.status_code == 200
        assert after.json() == before.json()

        audit = client.get("/api/audit", headers=headers)
        assert audit.status_code == 200
        assert all(entry["action"] not in {"block_ip", "unblock_ip"} for entry in audit.json())
    finally:
        app.dependency_overrides.clear()


def test_frontend_has_admin_route_guard_and_role_aware_navigation():
    root = Path(__file__).resolve().parents[2]
    app_tsx = (root / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    admin_route = (root / "frontend" / "src" / "components" / "AdminRoute.tsx").read_text(encoding="utf-8")
    app_shell = (root / "frontend" / "src" / "components" / "AppShell.tsx").read_text(encoding="utf-8")

    assert "AdminRoute" in app_tsx
    assert "/users" in app_tsx
    assert "/demo" in app_tsx
    assert "AccessDenied" in admin_route
    assert "isAdmin" in admin_route
    assert "adminOnly" in app_shell
    assert "User Admin" in app_shell
    assert "Demo Controls" in app_shell
