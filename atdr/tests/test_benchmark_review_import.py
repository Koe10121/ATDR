import json
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.benchmarks.adapter import (
    BenchmarkRecord,
)
from atdr.app.benchmarks.review import (
    apply_benchmark_reviews,
    import_benchmark_review_csv_text,
    parse_benchmark_review_csv,
)
from atdr.app.db.database import Base, get_db
from atdr.app.db.models import MLLabel
from atdr.app.main import app
from atdr.app.services.ml_label_service import import_ml_labels_csv
from atdr.app.services.user_service import create_user


def _record(
    row_number: int,
    *,
    label: str,
    attack_type: str,
) -> BenchmarkRecord:
    return BenchmarkRecord(
        row_number=row_number,
        raw={},
        normalized={
            "timestamp": datetime(2026, 4, 20, tzinfo=timezone.utc),
            "source_name": "external-holdout",
            "scenario": "boundary-test",
            "src_ip": f"198.51.100.{row_number}",
            "dst_ip": "10.0.0.10",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": "tcp",
            "action": "allow",
            "app": "ssl",
            "bytes": 1000,
            "packets": 10,
        },
        label=label,
        attack_type=attack_type,
    )


def _review_csv() -> str:
    return "\n".join(
        [
            (
                "benchmark_row_id,current_label,expected_label,"
                "human_review_decision,human_review_attack_type,"
                "human_review_confidence,human_review_note"
            ),
            (
                "2,benign_like,benign_like,suspicious,port_scan,4,"
                "Human review found scanning behavior."
            ),
        ]
    )


def _client() -> TestClient:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, future=True)
    with TestingSession() as db:
        create_user(
            db,
            username="admin",
            password="admin123",
            role="admin",
        )

    def override_get_db() -> Generator[Session, None, None]:
        with TestingSession() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def _auth(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert response.status_code == 200
    return {
        "Authorization": f"Bearer {response.json()['access_token']}"
    }


def test_benchmark_review_import_uses_row_id_and_stays_outside_ml_labels(
    tmp_path,
):
    engine = create_engine(f"sqlite:///{tmp_path / 'labels.db'}", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        before = db.scalar(select(func.count()).select_from(MLLabel))
        result = import_benchmark_review_csv_text(
            _review_csv(),
            benchmark_kind="external_holdout",
            input_name="reviewed.csv",
            reviewer="analyst",
            output_dir=tmp_path / "artifacts",
        )
        after = db.scalar(select(func.count()).select_from(MLLabel))

    assert result["ok"] is True
    assert result["imported"] == 1
    assert result["failed"] == 0
    assert before == after == 0
    artifact = json.loads(
        Path(result["artifact_path"]).read_text(encoding="utf-8")
    )
    assert artifact["reviews"][0]["benchmark_row_id"] == 2
    assert artifact["reviews"][0]["human_review_note"].startswith(
        "Human review"
    )
    assert artifact["safety"]["stored_outside_ml_labels"] is True
    assert artifact["safety"]["model_activated"] is False
    assert artifact["safety"]["response_automation_allowed"] is False


def test_normal_label_import_still_requires_log_or_label_id(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'normal.db'}", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        result = import_ml_labels_csv(
            db,
            _review_csv(),
            reviewer="analyst",
        )

    assert result["created"] == 0
    assert result["updated"] == 0
    assert result["failed"] == 1
    assert result["error_summary"]["missing_label_id_or_log_id"] == 1


def test_benchmark_review_validation_rejects_bad_values():
    result = parse_benchmark_review_csv(
        "\n".join(
            [
                (
                    "benchmark_row_id,human_review_decision,"
                    "human_review_attack_type,human_review_confidence"
                ),
                "2,definitely_bad,port_scan,9",
            ]
        ),
        benchmark_kind="external_holdout",
        input_name="bad.csv",
    )

    assert result["ok"] is False
    assert result["imported"] == 0
    assert result["failed"] == 1
    assert result["errors"][0]["reason"] == (
        "invalid_human_review_decision"
    )


def test_api_routes_benchmark_csv_to_separate_workflow(
    tmp_path,
    monkeypatch,
):
    import atdr.app.routers.ml as ml_router
    from atdr.app.benchmarks.review import (
        import_benchmark_review_csv_text as import_service,
    )

    client = _client()
    headers = _auth(client)
    monkeypatch.setattr(
        ml_router,
        "import_benchmark_review_csv_text",
        lambda csv_text, **kwargs: import_service(
            csv_text,
            **kwargs,
            output_dir=tmp_path / "artifacts",
        ),
    )
    try:
        normal = client.post(
            "/api/ml/labels/import",
            headers=headers,
            files={
                "upload": (
                    "benchmark.csv",
                    _review_csv(),
                    "text/csv",
                )
            },
        )
        benchmark = client.post(
            "/api/ml/benchmark-reviews/import",
            headers=headers,
            params={"benchmark_kind": "external_holdout"},
            files={
                "upload": (
                    "benchmark.csv",
                    _review_csv(),
                    "text/csv",
                )
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert normal.status_code == 400
    assert "Benchmark Review Import" in normal.json()["detail"]
    assert benchmark.status_code == 200
    assert benchmark.json()["imported"] == 1
    assert benchmark.json()["artifact_name"].startswith(
        "reviewed_external_holdout_labels_"
    )


def test_apply_benchmark_reviews_overrides_expected_label_and_attack_type():
    records = [_record(2, label="benign_like", attack_type="normal")]
    parsed = parse_benchmark_review_csv(
        _review_csv(),
        benchmark_kind="external_holdout",
        input_name="reviewed.csv",
    )

    reviewed, summary, metadata = apply_benchmark_reviews(
        records,
        parsed["reviews"],
    )

    assert reviewed[0].label == "suspicious"
    assert reviewed[0].attack_type == "port_scan"
    assert summary["applied_count"] == 1
    assert metadata[2]["human_review_confidence"] == 4


