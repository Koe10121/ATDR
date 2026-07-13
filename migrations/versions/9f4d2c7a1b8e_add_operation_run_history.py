"""add operation run history

Revision ID: 9f4d2c7a1b8e
Revises: f1a2b3c4d5e6
Create Date: 2026-05-25 20:30:00.000000
"""

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "9f4d2c7a1b8e"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode():
        _create_ingestion_runs_table()
        _create_detection_runs_table()
    else:
        bind = op.get_bind()
        inspector = inspect(bind)
        existing_tables = set(inspector.get_table_names())
        if "ingestion_runs" not in existing_tables:
            _create_ingestion_runs_table()
        inspector = inspect(bind)
        existing_tables = set(inspector.get_table_names())
        if "detection_runs" not in existing_tables:
            _create_detection_runs_table()
    _create_index_if_missing("ingestion_runs", "ix_ingestion_runs_finished_at", ["finished_at"])
    _create_index_if_missing("ingestion_runs", "ix_ingestion_runs_input_name", ["input_name"])
    _create_index_if_missing("ingestion_runs", "ix_ingestion_runs_source_type", ["source_type"])
    _create_index_if_missing("ingestion_runs", "ix_ingestion_runs_started_at", ["started_at"])
    _create_index_if_missing("ingestion_runs", "ix_ingestion_runs_status", ["status"])
    _create_index_if_missing("detection_runs", "ix_detection_runs_detection_type", ["detection_type"])
    _create_index_if_missing("detection_runs", "ix_detection_runs_finished_at", ["finished_at"])
    _create_index_if_missing("detection_runs", "ix_detection_runs_started_at", ["started_at"])
    _create_index_if_missing("detection_runs", "ix_detection_runs_status", ["status"])


def _create_ingestion_runs_table() -> None:
    op.create_table(
            "ingestion_runs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("source_type", sa.String(length=64), nullable=False),
            sa.Column("input_name", sa.String(length=255), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("total_lines_received", sa.Integer(), nullable=False),
            sa.Column("raw_logs_created", sa.Integer(), nullable=False),
            sa.Column("parsed_successfully", sa.Integer(), nullable=False),
            sa.Column("parse_failures", sa.Integer(), nullable=False),
            sa.Column("duplicate_raw_logs", sa.Integer(), nullable=False),
            sa.Column("alerts_created", sa.Integer(), nullable=False),
            sa.Column("alerts_deduplicated", sa.Integer(), nullable=False),
            sa.Column("alerts_suppressed", sa.Integer(), nullable=False),
            sa.Column("runtime_seconds", sa.Float(), nullable=True),
            sa.Column("error_summary", sa.Text(), nullable=True),
            sa.Column("details_json", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
    )


def _create_detection_runs_table() -> None:
    op.create_table(
            "detection_runs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("detection_type", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("logs_evaluated", sa.Integer(), nullable=False),
            sa.Column("alerts_created", sa.Integer(), nullable=False),
            sa.Column("alerts_deduplicated", sa.Integer(), nullable=False),
            sa.Column("alerts_suppressed", sa.Integer(), nullable=False),
            sa.Column("top_attack_types_json", sa.JSON(), nullable=False),
            sa.Column("runtime_seconds", sa.Float(), nullable=True),
            sa.Column("error_summary", sa.Text(), nullable=True),
            sa.Column("details_json", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_detection_runs_status"), table_name="detection_runs")
    op.drop_index(op.f("ix_detection_runs_started_at"), table_name="detection_runs")
    op.drop_index(op.f("ix_detection_runs_finished_at"), table_name="detection_runs")
    op.drop_index(op.f("ix_detection_runs_detection_type"), table_name="detection_runs")
    op.drop_table("detection_runs")
    op.drop_index(op.f("ix_ingestion_runs_status"), table_name="ingestion_runs")
    op.drop_index(op.f("ix_ingestion_runs_started_at"), table_name="ingestion_runs")
    op.drop_index(op.f("ix_ingestion_runs_source_type"), table_name="ingestion_runs")
    op.drop_index(op.f("ix_ingestion_runs_input_name"), table_name="ingestion_runs")
    op.drop_index(op.f("ix_ingestion_runs_finished_at"), table_name="ingestion_runs")
    op.drop_table("ingestion_runs")


def _create_index_if_missing(table_name: str, index_name: str, columns: list[str]) -> None:
    if context.is_offline_mode():
        op.create_index(index_name, table_name, columns, unique=False)
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name not in existing:
        op.create_index(index_name, table_name, columns, unique=False)
