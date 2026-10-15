"""internet services: the MFU addresses and ports that answered someone on the internet

Revision ID: e9b1c3d5f7a9
Revises: d7f9a1b3c5e8
Create Date: 2026-10-15 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa


revision: str = "e9b1c3d5f7a9"
down_revision: str | None = "d7f9a1b3c5e8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NOW = sa.text("(CURRENT_TIMESTAMP)")


def _existing() -> set[str]:
    # With AUTO_CREATE_TABLES (the laptop's setting) the API creates a new model's table when it starts, which
    # can be before anyone runs this migration.
    if context.is_offline_mode():
        return set()
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "internet_services" in _existing():
        return
    # Each one is listed by detection the first time it answers a connection from the internet; an admin marks
    # whether it is meant to be public.
    op.create_table(
        "internet_services",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("apps", sa.JSON(), nullable=False),
        sa.Column("connections", sa.Integer(), nullable=False),
        sa.Column("sources", sa.Integer(), nullable=False),
        sa.Column("sample_sources", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("address", "port", "protocol", name="uq_internet_services_address_port_protocol"),
    )
    op.create_index("ix_internet_services_address", "internet_services", ["address"])
    op.create_index("ix_internet_services_last_seen", "internet_services", ["last_seen"])
    op.create_index("ix_internet_services_status", "internet_services", ["status"])


def downgrade() -> None:
    if context.is_offline_mode() or "internet_services" in _existing():
        op.drop_table("internet_services")
