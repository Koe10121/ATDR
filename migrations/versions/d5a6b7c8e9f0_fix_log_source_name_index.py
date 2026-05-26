"""fix log source name index uniqueness

Revision ID: d5a6b7c8e9f0
Revises: c4f1a8d9e2b6
Create Date: 2026-05-26 09:45:00.000000
"""

from alembic import op
from sqlalchemy import inspect


revision = "d5a6b7c8e9f0"
down_revision = "c4f1a8d9e2b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    _ensure_name_index(unique=True)


def downgrade() -> None:
    _ensure_name_index(unique=False)


def _ensure_name_index(*, unique: bool) -> None:
    inspector = inspect(op.get_bind())
    if "log_sources" not in set(inspector.get_table_names()):
        return
    existing = {index["name"]: index for index in inspector.get_indexes("log_sources")}
    index = existing.get("ix_log_sources_name")
    if index is not None and bool(index.get("unique")) == unique:
        return
    if index is not None:
        op.drop_index("ix_log_sources_name", table_name="log_sources")
    op.create_index("ix_log_sources_name", "log_sources", ["name"], unique=unique)
