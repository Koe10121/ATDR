"""add operation jobs

Revision ID: a1b2c3d4e5f7
Revises: 9c2d4e6f8a10
Create Date: 2026-06-19 10:00:00.000000
"""

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "a1b2c3d4e5f7"
down_revision = "9c2d4e6f8a10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not context.is_offline_mode():
        inspector = inspect(op.get_bind())
        if "operation_jobs" in set(inspector.get_table_names()):
            return
    op.create_table(
        "operation_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("progress_current", sa.Integer(), nullable=False),
        sa.Column("progress_total", sa.Integer(), nullable=False),
        sa.Column("result_summary_json", sa.JSON(), nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("related_ingestion_run_id", sa.Integer(), nullable=True),
        sa.Column("related_detection_run_id", sa.Integer(), nullable=True),
        sa.Column("related_ml_model_run_id", sa.Integer(), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["related_detection_run_id"], ["detection_runs.id"]),
        sa.ForeignKeyConstraint(["related_ingestion_run_id"], ["ingestion_runs.id"]),
        sa.ForeignKeyConstraint(["related_ml_model_run_id"], ["ml_model_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for index_name, columns in {
        "ix_operation_jobs_job_type": ["job_type"],
        "ix_operation_jobs_status": ["status"],
        "ix_operation_jobs_requested_by": ["requested_by"],
        "ix_operation_jobs_started_at": ["started_at"],
        "ix_operation_jobs_finished_at": ["finished_at"],
        "ix_operation_jobs_created_at": ["created_at"],
        "ix_operation_jobs_updated_at": ["updated_at"],
        "ix_operation_jobs_related_ingestion_run_id": ["related_ingestion_run_id"],
        "ix_operation_jobs_related_detection_run_id": ["related_detection_run_id"],
        "ix_operation_jobs_related_ml_model_run_id": ["related_ml_model_run_id"],
    }.items():
        op.create_index(index_name, "operation_jobs", columns, unique=False)


def downgrade() -> None:
    if context.is_offline_mode():
        return
    inspector = inspect(op.get_bind())
    if "operation_jobs" not in set(inspector.get_table_names()):
        return
    for index_name in [
        "ix_operation_jobs_related_ml_model_run_id",
        "ix_operation_jobs_related_detection_run_id",
        "ix_operation_jobs_related_ingestion_run_id",
        "ix_operation_jobs_updated_at",
        "ix_operation_jobs_created_at",
        "ix_operation_jobs_finished_at",
        "ix_operation_jobs_started_at",
        "ix_operation_jobs_requested_by",
        "ix_operation_jobs_status",
        "ix_operation_jobs_job_type",
    ]:
        _drop_index_if_exists(index_name)
    op.drop_table("operation_jobs")


def _drop_index_if_exists(index_name: str) -> None:
    if context.is_offline_mode():
        op.execute(f'DROP INDEX IF EXISTS "{index_name}"')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes("operation_jobs")}
    if index_name in existing:
        op.drop_index(index_name, table_name="operation_jobs")
