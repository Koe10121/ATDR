"""add ML Governance anomaly distribution indexes

Revision ID: b9c0d1e2f3a4
Revises: f8a9b0c1d2e3
Create Date: 2026-08-12 00:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
from sqlalchemy import inspect


revision: str = "b9c0d1e2f3a4"
down_revision: str | None = "f8a9b0c1d2e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_INDEXES = (
    (
        "ix_normalized_anomaly_src_ip",
        ["is_anomaly", "src_ip"],
    ),
    (
        "ix_normalized_anomaly_dst_ip",
        ["is_anomaly", "dst_ip"],
    ),
    (
        "ix_normalized_anomaly_protocol",
        ["is_anomaly", "protocol"],
    ),
)


def upgrade() -> None:
    for index_name, columns in _INDEXES:
        _create_index_if_missing(index_name, columns)
    if not context.is_offline_mode() and op.get_bind().dialect.name == "sqlite":
        op.execute("ANALYZE normalized_logs")


def downgrade() -> None:
    for index_name, _columns in reversed(_INDEXES):
        _drop_index_if_present(index_name)


def _create_index_if_missing(index_name: str, columns: list[str]) -> None:
    if context.is_offline_mode():
        op.create_index(
            index_name,
            "normalized_logs",
            columns,
            unique=False,
        )
        return
    existing = {
        str(index["name"])
        for index in inspect(op.get_bind()).get_indexes("normalized_logs")
    }
    if index_name not in existing:
        op.create_index(
            index_name,
            "normalized_logs",
            columns,
            unique=False,
        )


def _drop_index_if_present(index_name: str) -> None:
    if context.is_offline_mode():
        op.drop_index(index_name, table_name="normalized_logs")
        return
    existing = {
        str(index["name"])
        for index in inspect(op.get_bind()).get_indexes("normalized_logs")
    }
    if index_name in existing:
        op.drop_index(index_name, table_name="normalized_logs")
