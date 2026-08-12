"""add Overview source-volume covering indexes

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-08-12 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
from sqlalchemy import inspect


revision: str = "f8a9b0c1d2e3"
down_revision: str | None = "e7f8a9b0c1d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_INDEXES = (
    (
        "normalized_logs",
        "ix_normalized_logs_id_raw_log_id_cover",
        ["id", "raw_log_id"],
    ),
    (
        "raw_logs",
        "ix_raw_logs_id_source_id_cover",
        ["id", "source_id"],
    ),
)


def upgrade() -> None:
    for table_name, index_name, columns in _INDEXES:
        _create_index_if_missing(table_name, index_name, columns)
    if not context.is_offline_mode() and op.get_bind().dialect.name == "sqlite":
        # SQLite needs refreshed planner statistics before it will prefer the
        # new covering lookup hops over random rowid table reads.
        for table_name in (
            "alert_evidence",
            "normalized_logs",
            "raw_logs",
            "log_sources",
        ):
            op.execute(f"ANALYZE {table_name}")


def downgrade() -> None:
    for table_name, index_name, _columns in reversed(_INDEXES):
        _drop_index_if_present(table_name, index_name)


def _create_index_if_missing(
    table_name: str,
    index_name: str,
    columns: list[str],
) -> None:
    if context.is_offline_mode():
        op.create_index(index_name, table_name, columns, unique=False)
        return
    existing = {
        str(index["name"])
        for index in inspect(op.get_bind()).get_indexes(table_name)
    }
    if index_name not in existing:
        op.create_index(index_name, table_name, columns, unique=False)


def _drop_index_if_present(table_name: str, index_name: str) -> None:
    if context.is_offline_mode():
        op.drop_index(index_name, table_name=table_name)
        return
    existing = {
        str(index["name"])
        for index in inspect(op.get_bind()).get_indexes(table_name)
    }
    if index_name in existing:
        op.drop_index(index_name, table_name=table_name)
