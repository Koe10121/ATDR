"""add ML governance profile covering index

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-07-28 10:00:00.000000
"""

from __future__ import annotations

from alembic import op


revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_normalized_ml_profile_cover",
        "normalized_logs",
        ["is_anomaly", "action", "app_risk", "app"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_normalized_ml_profile_cover",
        table_name="normalized_logs",
    )
