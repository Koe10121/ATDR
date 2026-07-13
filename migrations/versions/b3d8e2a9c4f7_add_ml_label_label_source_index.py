"""add ml label label-source composite index

Revision ID: b3d8e2a9c4f7
Revises: a7c9d2e4f6b1
Create Date: 2026-05-25 21:25:00.000000
"""

from alembic import context, op
from sqlalchemy import inspect


revision = "b3d8e2a9c4f7"
down_revision = "a7c9d2e4f6b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    _create_index_if_missing("ml_labels", "ix_ml_labels_label_label_source", ["label", "label_source"])


def downgrade() -> None:
    _drop_index_if_exists("ml_labels", "ix_ml_labels_label_label_source")


def _create_index_if_missing(table_name: str, index_name: str, columns: list[str]) -> None:
    if context.is_offline_mode():
        op.execute(f'CREATE INDEX IF NOT EXISTS "{index_name}" ON "{table_name}" ({", ".join(columns)})')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name not in existing:
        op.create_index(index_name, table_name, columns, unique=False)


def _drop_index_if_exists(table_name: str, index_name: str) -> None:
    if context.is_offline_mode():
        op.execute(f'DROP INDEX IF EXISTS "{index_name}"')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name in existing:
        op.drop_index(index_name, table_name=table_name)
