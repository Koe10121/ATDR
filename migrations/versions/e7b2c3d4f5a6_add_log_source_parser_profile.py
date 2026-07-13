"""add log source parser profile

Revision ID: e7b2c3d4f5a6
Revises: d5a6b7c8e9f0
Create Date: 2026-05-26 10:30:00.000000
"""

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "e7b2c3d4f5a6"
down_revision = "d5a6b7c8e9f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode():
        op.add_column("log_sources", sa.Column("parser_profile", sa.String(length=64), server_default="palo_alto", nullable=False))
        _create_index_if_missing("log_sources", "ix_log_sources_parser_profile", ["parser_profile"])
        return
    inspector = inspect(op.get_bind())
    if "log_sources" not in set(inspector.get_table_names()):
        return
    columns = {column["name"] for column in inspector.get_columns("log_sources")}
    if "parser_profile" not in columns:
        op.add_column("log_sources", sa.Column("parser_profile", sa.String(length=64), server_default="palo_alto", nullable=False))
    _create_index_if_missing("log_sources", "ix_log_sources_parser_profile", ["parser_profile"])


def downgrade() -> None:
    if context.is_offline_mode():
        return
    inspector = inspect(op.get_bind())
    if "log_sources" not in set(inspector.get_table_names()):
        return
    _drop_index_if_exists("log_sources", "ix_log_sources_parser_profile")
    columns = {column["name"] for column in inspector.get_columns("log_sources")}
    if "parser_profile" in columns:
        op.drop_column("log_sources", "parser_profile")


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
