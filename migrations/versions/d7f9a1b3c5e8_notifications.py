"""notifications: what ATDR tells people, and where each one was sent

Revision ID: d7f9a1b3c5e8
Revises: c6e8f0a2b4d6
Create Date: 2026-10-09 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa


revision: str = "d7f9a1b3c5e8"
down_revision: str | None = "c6e8f0a2b4d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NOW = sa.text("(CURRENT_TIMESTAMP)")


def _existing() -> set[str]:
    # With AUTO_CREATE_TABLES (the laptop's setting) the API creates a new model's table when it starts, which
    # can be before anyone runs this migration.
    if context.is_offline_mode():
        return set()
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    existing = _existing()
    if "notifications" not in existing:
        # What ATDR tells people: new Critical alerts, the morning summary, a problem of its own. The bell
        # remembers the highest number each user has seen, so a number is never given out twice.
        op.create_table(
            "notifications",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=32), nullable=False),
            sa.Column("level", sa.String(length=16), nullable=False),
            sa.Column("audience", sa.String(length=16), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("link", sa.String(length=255), nullable=True),
            sa.Column("details_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sqlite_autoincrement=True,
        )
        op.create_index("ix_notifications_kind", "notifications", ["kind"])
        op.create_index("ix_notifications_created_at", "notifications", ["created_at"])
    if "notification_deliveries" not in existing:
        # One notification on its way out through one channel.
        op.create_table(
            "notification_deliveries",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("notification_id", sa.Integer(), nullable=False),
            sa.Column("channel", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
            sa.ForeignKeyConstraint(["notification_id"], ["notifications.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("notification_id", "channel", name="uq_notification_delivery_channel"),
        )
        op.create_index("ix_notification_deliveries_notification_id", "notification_deliveries", ["notification_id"])
        op.create_index("ix_notification_deliveries_status", "notification_deliveries", ["status"])
    if "notification_alerts" not in existing:
        # An alert that has been reported, so that it is reported once.
        op.create_table(
            "notification_alerts",
            sa.Column("alert_id", sa.Integer(), autoincrement=False, nullable=False),
            sa.Column("notification_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
            sa.PrimaryKeyConstraint("alert_id"),
        )
        op.create_index("ix_notification_alerts_notification_id", "notification_alerts", ["notification_id"])
    if "notification_conditions" not in existing:
        # Something about ATDR itself that needs attention now.
        op.create_table(
            "notification_conditions",
            sa.Column("key", sa.String(length=128), nullable=False),
            sa.Column("source", sa.String(length=16), nullable=False),
            sa.Column("urgent", sa.Boolean(), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("over", sa.String(length=255), nullable=False),
            sa.Column("since", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("announced_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("details_json", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("key"),
        )
    if "notification_seen" not in existing:
        # The newest notification each user has looked at.
        op.create_table(
            "notification_seen",
            sa.Column("user_id", sa.Integer(), autoincrement=False, nullable=False),
            sa.Column("seen_id", sa.Integer(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("user_id"),
        )
    if "notification_state" not in existing:
        # What the notification look remembers between looks.
        op.create_table(
            "notification_state",
            sa.Column("key", sa.String(length=64), nullable=False),
            sa.Column("value", sa.Text(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
            sa.PrimaryKeyConstraint("key"),
        )


def downgrade() -> None:
    existing = _existing()
    offline = context.is_offline_mode()
    for table in ("notification_state", "notification_seen", "notification_conditions", "notification_alerts",
                  "notification_deliveries", "notifications"):
        if offline or table in existing:
            op.drop_table(table)
