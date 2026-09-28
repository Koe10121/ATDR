"""add ml_label_archive for labels that no longer describe their log

Revision ID: 7c2e91f4b0a3
Revises: d9e3f4a5b6c7
Create Date: 2026-09-28 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "7c2e91f4b0a3"
down_revision: str | None = "d9e3f4a5b6c7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEXES = {
    "ix_ml_label_archive_original_label_id": ["original_label_id"],
    "ix_ml_label_archive_log_id": ["log_id"],
    "ix_ml_label_archive_label_source": ["label_source"],
    "ix_ml_label_archive_archived_at": ["archived_at"],
}


def upgrade() -> None:
    op.create_table(
        "ml_label_archive",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("original_label_id", sa.Integer(), nullable=False),
        sa.Column("log_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("attack_type", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("reviewer", sa.String(length=128), nullable=False),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("label_source", sa.String(length=32), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False),
        sa.Column("label_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("archived_by", sa.String(length=128), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns in INDEXES.items():
        op.create_index(name, "ml_label_archive", columns, unique=False)


def downgrade() -> None:
    for name in INDEXES:
        op.drop_index(name, table_name="ml_label_archive")
    op.drop_table("ml_label_archive")
