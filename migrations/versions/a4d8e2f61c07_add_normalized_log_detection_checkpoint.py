"""add normalized_logs.last_detection_run_id

Revision ID: a4d8e2f61c07
Revises: 5bc516e2f7e7
Create Date: 2026-09-26 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a4d8e2f61c07"
down_revision: str | None = "5bc516e2f7e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "normalized_logs",
        sa.Column("last_detection_run_id", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_normalized_logs_last_detection_run_id",
        "normalized_logs",
        ["last_detection_run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_normalized_logs_last_detection_run_id", table_name="normalized_logs")
    op.drop_column("normalized_logs", "last_detection_run_id")
