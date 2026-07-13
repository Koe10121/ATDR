"""add log source management

Revision ID: c4f1a8d9e2b6
Revises: b3d8e2a9c4f7
Create Date: 2026-05-26 09:15:00.000000
"""

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "c4f1a8d9e2b6"
down_revision = "b3d8e2a9c4f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = None if context.is_offline_mode() else inspect(bind)
    existing_tables = set() if inspector is None else set(inspector.get_table_names())
    if "log_sources" not in existing_tables:
        op.create_table(
            "log_sources",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("source_type", sa.String(length=64), nullable=False),
            sa.Column("host", sa.String(length=255), nullable=True),
            sa.Column("port", sa.Integer(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_log_received_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("logs_received_count", sa.Integer(), nullable=False),
            sa.Column("parse_success_count", sa.Integer(), nullable=False),
            sa.Column("parse_failure_count", sa.Integer(), nullable=False),
            sa.Column("latest_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )
    for name, columns, unique in [
        ("ix_log_sources_name", ["name"], True),
        ("ix_log_sources_source_type", ["source_type"], False),
        ("ix_log_sources_host", ["host"], False),
        ("ix_log_sources_port", ["port"], False),
        ("ix_log_sources_enabled", ["enabled"], False),
        ("ix_log_sources_last_seen", ["last_seen"], False),
        ("ix_log_sources_last_log_received_at", ["last_log_received_at"], False),
    ]:
        _create_index_if_missing("log_sources", name, columns, unique=unique)

    raw_columns = set() if inspector is None else {column["name"] for column in inspector.get_columns("raw_logs")}
    if "source_id" not in raw_columns:
        # SQLite cannot add a foreign key constraint to an existing table with
        # ALTER TABLE. Keep this as an indexed application-level relationship so
        # local demo databases can migrate safely.
        op.add_column("raw_logs", sa.Column("source_id", sa.Integer(), nullable=True))
    _create_index_if_missing("raw_logs", "ix_raw_logs_source_id", ["source_id"])


def downgrade() -> None:
    if context.is_offline_mode():
        return
    _drop_index_if_exists("raw_logs", "ix_raw_logs_source_id")
    inspector = inspect(op.get_bind())
    raw_columns = {column["name"] for column in inspector.get_columns("raw_logs")}
    if "source_id" in raw_columns:
        op.drop_column("raw_logs", "source_id")
    for name in [
        "ix_log_sources_last_log_received_at",
        "ix_log_sources_last_seen",
        "ix_log_sources_enabled",
        "ix_log_sources_port",
        "ix_log_sources_host",
        "ix_log_sources_source_type",
        "ix_log_sources_name",
    ]:
        _drop_index_if_exists("log_sources", name)
    if "log_sources" in set(inspector.get_table_names()):
        op.drop_table("log_sources")


def _create_index_if_missing(table_name: str, index_name: str, columns: list[str], *, unique: bool = False) -> None:
    if context.is_offline_mode():
        prefix = "CREATE UNIQUE INDEX" if unique else "CREATE INDEX"
        op.execute(f'{prefix} IF NOT EXISTS "{index_name}" ON "{table_name}" ({", ".join(columns)})')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name not in existing:
        op.create_index(index_name, table_name, columns, unique=unique)


def _drop_index_if_exists(table_name: str, index_name: str) -> None:
    if context.is_offline_mode():
        op.execute(f'DROP INDEX IF EXISTS "{index_name}"')
        return
    inspector = inspect(op.get_bind())
    existing = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name in existing:
        op.drop_index(index_name, table_name=table_name)
