"""add account email verification

Revision ID: c8d9e0f1a2b3
Revises: a1b2c3d4e5f7
Create Date: 2026-06-20 22:40:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "c8d9e0f1a2b3"
down_revision = "a1b2c3d4e5f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    if "account_email_verification_tokens" not in existing_tables:
        op.create_table(
            "account_email_verification_tokens",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("token_hash", sa.String(length=128), nullable=False),
            sa.Column("purpose", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=True),
            sa.Column("delivery_mode", sa.String(length=32), nullable=False),
            sa.Column("delivery_status", sa.String(length=32), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for index_name, columns in {
            "ix_account_email_verification_tokens_user_id": ["user_id"],
            "ix_account_email_verification_tokens_email": ["email"],
            "ix_account_email_verification_tokens_token_hash": ["token_hash"],
            "ix_account_email_verification_tokens_purpose": ["purpose"],
            "ix_account_email_verification_tokens_expires_at": ["expires_at"],
            "ix_account_email_verification_tokens_used_at": ["used_at"],
            "ix_account_email_verification_tokens_created_at": ["created_at"],
            "ix_account_email_verification_tokens_created_by": ["created_by"],
            "ix_account_email_verification_tokens_delivery_mode": ["delivery_mode"],
            "ix_account_email_verification_tokens_delivery_status": ["delivery_status"],
        }.items():
            op.create_index(index_name, "account_email_verification_tokens", columns, unique=False)

    if "email_notification_events" not in existing_tables:
        op.create_table(
            "email_notification_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("recipient_email", sa.String(length=255), nullable=False),
            sa.Column("subject", sa.String(length=255), nullable=False),
            sa.Column("body_preview", sa.Text(), nullable=False),
            sa.Column("purpose", sa.String(length=64), nullable=False),
            sa.Column("delivery_mode", sa.String(length=32), nullable=False),
            sa.Column("delivery_status", sa.String(length=32), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_summary", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        for index_name, columns in {
            "ix_email_notification_events_user_id": ["user_id"],
            "ix_email_notification_events_recipient_email": ["recipient_email"],
            "ix_email_notification_events_purpose": ["purpose"],
            "ix_email_notification_events_delivery_mode": ["delivery_mode"],
            "ix_email_notification_events_delivery_status": ["delivery_status"],
            "ix_email_notification_events_created_by": ["created_by"],
            "ix_email_notification_events_created_at": ["created_at"],
            "ix_email_notification_events_sent_at": ["sent_at"],
        }.items():
            op.create_index(index_name, "email_notification_events", columns, unique=False)


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    existing_tables = set(inspector.get_table_names())
    if "email_notification_events" in existing_tables:
        _drop_indexes("email_notification_events")
        op.drop_table("email_notification_events")
    if "account_email_verification_tokens" in existing_tables:
        _drop_indexes("account_email_verification_tokens")
        op.drop_table("account_email_verification_tokens")


def _drop_indexes(table_name: str) -> None:
    inspector = inspect(op.get_bind())
    for index in inspector.get_indexes(table_name):
        op.drop_index(index["name"], table_name=table_name)
