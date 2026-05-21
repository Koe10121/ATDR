"""add watchlists and suppression review

Revision ID: b8f2c1d4e6a9
Revises: 4c6cdf517f3c
Create Date: 2026-05-21 10:40:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "b8f2c1d4e6a9"
down_revision = "4c6cdf517f3c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "suppression_rules",
        sa.Column("review_status", sa.String(length=32), nullable=False, server_default="pending"),
    )
    op.add_column("suppression_rules", sa.Column("review_notes", sa.Text(), nullable=True))
    op.add_column("suppression_rules", sa.Column("reviewed_by", sa.String(length=128), nullable=True))
    op.add_column("suppression_rules", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f("ix_suppression_rules_review_status"), "suppression_rules", ["review_status"], unique=False)
    op.create_index(op.f("ix_suppression_rules_reviewed_by"), "suppression_rules", ["reviewed_by"], unique=False)

    op.create_table(
        "watchlist_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("indicator_value", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity_boost", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False),
        sa.Column("last_matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("disabled_by", sa.String(length=128), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_watchlist_items_active"), "watchlist_items", ["active"], unique=False)
    op.create_index(op.f("ix_watchlist_items_indicator_type"), "watchlist_items", ["indicator_type"], unique=False)
    op.create_index(op.f("ix_watchlist_items_indicator_value"), "watchlist_items", ["indicator_value"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_watchlist_items_indicator_value"), table_name="watchlist_items")
    op.drop_index(op.f("ix_watchlist_items_indicator_type"), table_name="watchlist_items")
    op.drop_index(op.f("ix_watchlist_items_active"), table_name="watchlist_items")
    op.drop_table("watchlist_items")

    op.drop_index(op.f("ix_suppression_rules_reviewed_by"), table_name="suppression_rules")
    op.drop_index(op.f("ix_suppression_rules_review_status"), table_name="suppression_rules")
    op.drop_column("suppression_rules", "reviewed_at")
    op.drop_column("suppression_rules", "reviewed_by")
    op.drop_column("suppression_rules", "review_notes")
    op.drop_column("suppression_rules", "review_status")
