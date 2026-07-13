"""add resumable ingestion operation job fields

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-07-13 16:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("operation_jobs", sa.Column("checkpoint_line", sa.Integer(), server_default="0", nullable=False))
    op.add_column("operation_jobs", sa.Column("checkpoint_bytes", sa.Integer(), server_default="0", nullable=False))
    op.add_column("operation_jobs", sa.Column("checkpoint_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operation_jobs", sa.Column("chunk_commits", sa.Integer(), server_default="0", nullable=False))
    op.add_column("operation_jobs", sa.Column("input_size_bytes", sa.Integer(), nullable=True))
    op.add_column("operation_jobs", sa.Column("input_fingerprint", sa.String(length=64), nullable=True))
    op.add_column("operation_jobs", sa.Column("cancellation_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("operation_jobs", sa.Column("cancellation_requested_by", sa.String(length=128), nullable=True))
    op.add_column("operation_jobs", sa.Column("resume_of_job_id", sa.Integer(), nullable=True))
    op.add_column("operation_jobs", sa.Column("original_job_id", sa.Integer(), nullable=True))
    op.add_column("operation_jobs", sa.Column("resume_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_operation_jobs_checkpoint_at", "operation_jobs", ["checkpoint_at"], unique=False)
    op.create_index("ix_operation_jobs_cancellation_requested_at", "operation_jobs", ["cancellation_requested_at"], unique=False)
    op.create_index("ix_operation_jobs_resume_of_job_id", "operation_jobs", ["resume_of_job_id"], unique=False)
    op.create_index("ix_operation_jobs_original_job_id", "operation_jobs", ["original_job_id"], unique=False)
    op.create_index("ix_operation_jobs_resume_expires_at", "operation_jobs", ["resume_expires_at"], unique=False)
    op.create_index("ix_operation_jobs_original_status", "operation_jobs", ["original_job_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_operation_jobs_original_status", table_name="operation_jobs")
    op.drop_index("ix_operation_jobs_resume_expires_at", table_name="operation_jobs")
    op.drop_index("ix_operation_jobs_original_job_id", table_name="operation_jobs")
    op.drop_index("ix_operation_jobs_resume_of_job_id", table_name="operation_jobs")
    op.drop_index("ix_operation_jobs_cancellation_requested_at", table_name="operation_jobs")
    op.drop_index("ix_operation_jobs_checkpoint_at", table_name="operation_jobs")
    op.drop_column("operation_jobs", "resume_expires_at")
    op.drop_column("operation_jobs", "original_job_id")
    op.drop_column("operation_jobs", "resume_of_job_id")
    op.drop_column("operation_jobs", "cancellation_requested_by")
    op.drop_column("operation_jobs", "cancellation_requested_at")
    op.drop_column("operation_jobs", "input_fingerprint")
    op.drop_column("operation_jobs", "input_size_bytes")
    op.drop_column("operation_jobs", "chunk_commits")
    op.drop_column("operation_jobs", "checkpoint_at")
    op.drop_column("operation_jobs", "checkpoint_bytes")
    op.drop_column("operation_jobs", "checkpoint_line")
