"""add durable operation job fields

Revision ID: e1f2a3b4c5d6
Revises: d4e5f6a7b8c9
Create Date: 2026-07-13 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "e1f2a3b4c5d6"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("operation_jobs", sa.Column("idempotency_key", sa.String(length=128), nullable=True))
    op.add_column("operation_jobs", sa.Column("payload_json", sa.JSON(), server_default=sa.text("'{}'"), nullable=False))
    op.add_column("operation_jobs", sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False))
    op.add_column("operation_jobs", sa.Column("max_attempts", sa.Integer(), server_default="1", nullable=False))
    op.add_column("operation_jobs", sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operation_jobs", sa.Column("lease_owner", sa.String(length=128), nullable=True))
    op.add_column("operation_jobs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ux_operation_jobs_idempotency_key", "operation_jobs", ["idempotency_key"], unique=True)
    op.create_index("ix_operation_jobs_queue_claim", "operation_jobs", ["status", "next_attempt_at", "created_at"], unique=False)
    op.create_index("ix_operation_jobs_lease_expires_at", "operation_jobs", ["lease_expires_at"], unique=False)

    op.create_table(
        "operation_worker_heartbeats",
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("current_job_id", sa.Integer(), nullable=True),
        sa.Column("details_json", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
        sa.ForeignKeyConstraint(["current_job_id"], ["operation_jobs.id"]),
        sa.PrimaryKeyConstraint("worker_id"),
    )
    op.create_index("ix_operation_worker_heartbeats_status", "operation_worker_heartbeats", ["status"], unique=False)
    op.create_index("ix_operation_worker_heartbeats_last_seen_at", "operation_worker_heartbeats", ["last_seen_at"], unique=False)
    op.create_index("ix_operation_worker_heartbeats_current_job_id", "operation_worker_heartbeats", ["current_job_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_operation_worker_heartbeats_current_job_id", table_name="operation_worker_heartbeats")
    op.drop_index("ix_operation_worker_heartbeats_last_seen_at", table_name="operation_worker_heartbeats")
    op.drop_index("ix_operation_worker_heartbeats_status", table_name="operation_worker_heartbeats")
    op.drop_table("operation_worker_heartbeats")
    op.drop_index("ix_operation_jobs_lease_expires_at", table_name="operation_jobs")
    op.drop_index("ix_operation_jobs_queue_claim", table_name="operation_jobs")
    op.drop_index("ux_operation_jobs_idempotency_key", table_name="operation_jobs")
    op.drop_column("operation_jobs", "lease_expires_at")
    op.drop_column("operation_jobs", "lease_owner")
    op.drop_column("operation_jobs", "next_attempt_at")
    op.drop_column("operation_jobs", "max_attempts")
    op.drop_column("operation_jobs", "attempt_count")
    op.drop_column("operation_jobs", "payload_json")
    op.drop_column("operation_jobs", "idempotency_key")
