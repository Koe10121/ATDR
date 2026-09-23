"""add users.sessions_revoked_at

Revision ID: 5bc516e2f7e7
Revises: ff5e3639ceb0
Create Date: 2026-09-23 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "5bc516e2f7e7"
down_revision: str | None = "ff5e3639ceb0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("sessions_revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_users_sessions_revoked_at",
        "users",
        ["sessions_revoked_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_users_sessions_revoked_at", table_name="users")
    op.drop_column("users", "sessions_revoked_at")
