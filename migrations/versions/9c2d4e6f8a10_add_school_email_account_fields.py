"""add school email account fields

Revision ID: 9c2d4e6f8a10
Revises: e7b2c3d4f5a6
Create Date: 2026-06-04 03:05:00.000000
"""

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "9c2d4e6f8a10"
down_revision = "e7b2c3d4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if context.is_offline_mode():
        op.add_column("users", sa.Column("email", sa.String(length=255), nullable=True))
        op.add_column("users", sa.Column("email_verified", sa.Boolean(), server_default=sa.false(), nullable=False))
        op.add_column("users", sa.Column("auth_provider", sa.String(length=32), server_default="local", nullable=False))
        op.add_column("users", sa.Column("external_subject", sa.String(length=255), nullable=True))
        op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column("users", sa.Column("invited_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column("users", sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))
        _create_index_if_missing("users", "ix_users_email", ["email"], unique=True)
        _create_index_if_missing("users", "ix_users_email_verified", ["email_verified"])
        _create_index_if_missing("users", "ix_users_auth_provider", ["auth_provider"])
        _create_index_if_missing("users", "ix_users_external_subject", ["external_subject"])
        _create_index_if_missing("users", "ix_users_last_login_at", ["last_login_at"])
        _create_index_if_missing("users", "ix_users_invited_at", ["invited_at"])
        _create_index_if_missing("users", "ix_users_disabled_at", ["disabled_at"])
        return
    inspector = inspect(op.get_bind())
    if "users" not in set(inspector.get_table_names()):
        return
    columns = {column["name"] for column in inspector.get_columns("users")}
    if "email" not in columns:
        op.add_column("users", sa.Column("email", sa.String(length=255), nullable=True))
    if "email_verified" not in columns:
        op.add_column(
            "users",
            sa.Column("email_verified", sa.Boolean(), server_default=sa.false(), nullable=False),
        )
    if "auth_provider" not in columns:
        op.add_column(
            "users",
            sa.Column("auth_provider", sa.String(length=32), server_default="local", nullable=False),
        )
    if "external_subject" not in columns:
        op.add_column("users", sa.Column("external_subject", sa.String(length=255), nullable=True))
    if "last_login_at" not in columns:
        op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    if "invited_at" not in columns:
        op.add_column("users", sa.Column("invited_at", sa.DateTime(timezone=True), nullable=True))
    if "disabled_at" not in columns:
        op.add_column("users", sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))

    _create_index_if_missing("users", "ix_users_email", ["email"], unique=True)
    _create_index_if_missing("users", "ix_users_email_verified", ["email_verified"])
    _create_index_if_missing("users", "ix_users_auth_provider", ["auth_provider"])
    _create_index_if_missing("users", "ix_users_external_subject", ["external_subject"])
    _create_index_if_missing("users", "ix_users_last_login_at", ["last_login_at"])
    _create_index_if_missing("users", "ix_users_invited_at", ["invited_at"])
    _create_index_if_missing("users", "ix_users_disabled_at", ["disabled_at"])


def downgrade() -> None:
    if context.is_offline_mode():
        return
    inspector = inspect(op.get_bind())
    if "users" not in set(inspector.get_table_names()):
        return
    for index_name in [
        "ix_users_disabled_at",
        "ix_users_invited_at",
        "ix_users_last_login_at",
        "ix_users_external_subject",
        "ix_users_auth_provider",
        "ix_users_email_verified",
        "ix_users_email",
    ]:
        _drop_index_if_exists("users", index_name)
    columns = {column["name"] for column in inspector.get_columns("users")}
    for column_name in [
        "disabled_at",
        "invited_at",
        "last_login_at",
        "external_subject",
        "auth_provider",
        "email_verified",
        "email",
    ]:
        if column_name in columns:
            op.drop_column("users", column_name)


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
