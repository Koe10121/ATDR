"""add summary performance indexes

Revision ID: a7c9d2e4f6b1
Revises: 9f4d2c7a1b8e
Create Date: 2026-05-25 21:10:00.000000
"""

from alembic import context, op
from sqlalchemy import inspect


revision = "a7c9d2e4f6b1"
down_revision = "9f4d2c7a1b8e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    _create_index_if_missing("raw_logs", "ix_raw_logs_imported_at", ["imported_at"])
    _create_index_if_missing("normalized_logs", "ix_normalized_logs_is_anomaly", ["is_anomaly"])
    _create_index_if_missing("normalized_logs", "ix_normalized_logs_anomaly_score", ["anomaly_score"])
    _create_index_if_missing("normalized_logs", "ix_normalized_anomaly_app", ["is_anomaly", "app"])
    _create_index_if_missing("normalized_logs", "ix_normalized_anomaly_dst_port", ["is_anomaly", "dst_port"])
    _create_index_if_missing("ml_model_runs", "ix_ml_model_runs_created_at", ["created_at"])
    _create_index_if_missing(
        "ml_model_runs",
        "ix_ml_model_runs_model_operation_created",
        ["model_name", "operation", "created_at"],
    )
    _create_index_if_missing("ml_labels", "ix_ml_labels_created_at", ["created_at"])
    _create_index_if_missing("ml_labels", "ix_ml_labels_reviewed_label", ["reviewed", "label"])
    _create_index_if_missing("ml_labels", "ix_ml_labels_source_reviewed", ["label_source", "reviewed"])
    _create_index_if_missing("ml_labels", "ix_ml_labels_label_label_source", ["label", "label_source"])
    _create_index_if_missing("alerts", "ix_alert_status_severity_updated", ["status", "severity", "updated_at"])


def downgrade() -> None:
    _drop_index_if_exists("alerts", "ix_alert_status_severity_updated")
    _drop_index_if_exists("ml_labels", "ix_ml_labels_label_label_source")
    _drop_index_if_exists("ml_labels", "ix_ml_labels_source_reviewed")
    _drop_index_if_exists("ml_labels", "ix_ml_labels_reviewed_label")
    _drop_index_if_exists("ml_labels", "ix_ml_labels_created_at")
    _drop_index_if_exists("ml_model_runs", "ix_ml_model_runs_model_operation_created")
    _drop_index_if_exists("ml_model_runs", "ix_ml_model_runs_created_at")
    _drop_index_if_exists("normalized_logs", "ix_normalized_anomaly_dst_port")
    _drop_index_if_exists("normalized_logs", "ix_normalized_anomaly_app")
    _drop_index_if_exists("normalized_logs", "ix_normalized_logs_anomaly_score")
    _drop_index_if_exists("normalized_logs", "ix_normalized_logs_is_anomaly")
    _drop_index_if_exists("raw_logs", "ix_raw_logs_imported_at")


def _create_index_if_missing(table_name: str, index_name: str, columns: list[str]) -> None:
    if context.is_offline_mode():
        op.execute(f'CREATE INDEX IF NOT EXISTS "{index_name}" ON "{table_name}" ({", ".join(columns)})')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name not in existing:
        op.create_index(index_name, table_name, columns, unique=False)


def _drop_index_if_exists(table_name: str, index_name: str) -> None:
    if context.is_offline_mode():
        op.execute(f'DROP INDEX IF EXISTS "{index_name}"')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name in existing:
        op.drop_index(index_name, table_name=table_name)
