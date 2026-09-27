"""add alert_archive for alerts replaced by newer rules

Revision ID: b7c1d2e3f4a5
Revises: a4d8e2f61c07
Create Date: 2026-09-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "b7c1d2e3f4a5"
down_revision: str | None = "a4d8e2f61c07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEXES = {
    "ix_alert_archive_original_alert_id": (["original_alert_id"], True),
    "ix_alert_archive_alert_type": (["alert_type"], False),
    "ix_alert_archive_severity": (["severity"], False),
    "ix_alert_archive_src_ip": (["src_ip"], False),
    "ix_alert_archive_superseded_by_catalog": (["superseded_by_catalog"], False),
    "ix_alert_archive_archived_at": (["archived_at"], False),
}


def upgrade() -> None:
    if not context.is_offline_mode():
        if "alert_archive" in set(inspect(op.get_bind()).get_table_names()):
            return

    op.create_table(
        "alert_archive",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("original_alert_id", sa.Integer(), nullable=False),
        sa.Column("alert_type", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("dst_ip", sa.String(length=64), nullable=True),
        sa.Column("threat_score", sa.Integer(), nullable=False),
        sa.Column("alert_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alert_json", sa.JSON(), nullable=False),
        sa.Column("evidence_log_ids", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("superseded_by_catalog", sa.String(length=64), nullable=False),
        sa.Column("archived_by", sa.String(length=128), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, (columns, unique) in INDEXES.items():
        op.create_index(name, "alert_archive", columns, unique=unique)


def downgrade() -> None:
    for name in INDEXES:
        op.drop_index(name, table_name="alert_archive")
    op.drop_table("alert_archive")
