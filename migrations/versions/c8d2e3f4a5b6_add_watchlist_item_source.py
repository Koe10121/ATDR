"""add watchlist_items.source for threat intelligence feeds

Revision ID: c8d2e3f4a5b6
Revises: b7c1d2e3f4a5
Create Date: 2026-09-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c8d2e3f4a5b6"
down_revision: str | None = "b7c1d2e3f4a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("watchlist_items", sa.Column("source", sa.String(length=128), nullable=True))
    op.create_index("ix_watchlist_items_source", "watchlist_items", ["source"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_watchlist_items_source", table_name="watchlist_items")
    op.drop_column("watchlist_items", "source")
