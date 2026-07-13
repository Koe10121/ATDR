"""add multiworker lease fencing and staging ownership fields

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-07-13 18:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("operation_jobs", sa.Column("lease_token", sa.String(length=64), nullable=True))
    op.add_column(
        "operation_jobs",
        sa.Column("claim_generation", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("operation_jobs", sa.Column("staging_storage_id", sa.String(length=128), nullable=True))
    op.create_index(
        "ix_operation_jobs_staging_storage_id",
        "operation_jobs",
        ["staging_storage_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_operation_jobs_staging_storage_id", table_name="operation_jobs")
    op.drop_column("operation_jobs", "staging_storage_id")
    op.drop_column("operation_jobs", "claim_generation")
    op.drop_column("operation_jobs", "lease_token")
