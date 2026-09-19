"""add response enforcement provenance and blocked-ip expiry

Revision ID: c3d4e5f6a7b8
Revises: b9c0d1e2f3a4
Create Date: 2026-09-19 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b9c0d1e2f3a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "response_actions",
        sa.Column("enforcement", sa.String(length=32), server_default="simulated", nullable=False),
    )
    op.add_column(
        "blocked_ips",
        sa.Column("enforcement", sa.String(length=32), server_default="simulated", nullable=False),
    )
    op.add_column(
        "blocked_ips",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("blocked_ips", "expires_at")
    op.drop_column("blocked_ips", "enforcement")
    op.drop_column("response_actions", "enforcement")
