"""suppression destination: silence what goes to one known-good server, such as a log collector

Revision ID: f1a3c5e7b9d2
Revises: e9b1c3d5f7a9
Create Date: 2026-10-15 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa


revision: str = "f1a3c5e7b9d2"
down_revision: str | None = "e9b1c3d5f7a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _columns() -> set[str]:
    if context.is_offline_mode():
        return set()
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns("suppression_rules")}


def upgrade() -> None:
    if "dst_ip" in _columns():
        return
    with op.batch_alter_table("suppression_rules") as batch:
        batch.add_column(sa.Column("dst_ip", sa.String(length=64), nullable=True))
        batch.create_index("ix_suppression_rules_dst_ip", ["dst_ip"])


def downgrade() -> None:
    with op.batch_alter_table("suppression_rules") as batch:
        batch.drop_index("ix_suppression_rules_dst_ip")
        batch.drop_column("dst_ip")
