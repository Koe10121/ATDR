"""add assistant feedback

Revision ID: d4e5f6a7b8c9
Revises: c8d9e0f1a2b3
Create Date: 2026-06-22 10:30:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "d4e5f6a7b8c9"
down_revision = "c8d9e0f1a2b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    if "assistant_feedback" in set(inspector.get_table_names()):
        return

    op.create_table(
        "assistant_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(length=128), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("answer_summary", sa.Text(), nullable=True),
        sa.Column("answer_hash", sa.String(length=64), nullable=False),
        sa.Column("context_type", sa.String(length=64), nullable=True),
        sa.Column("context_reference", sa.String(length=255), nullable=True),
        sa.Column("rating", sa.String(length=32), nullable=False),
        sa.Column("feedback_note", sa.Text(), nullable=True),
        sa.Column("external_provider_used", sa.Boolean(), nullable=False),
        sa.Column("raw_log_context_included", sa.Boolean(), nullable=False),
        sa.Column("action_requested", sa.Boolean(), nullable=False),
        sa.Column("action_executed", sa.Boolean(), nullable=False),
        sa.Column("assistant_audit_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["assistant_audit_id"], ["audit_logs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for index_name, columns in {
        "ix_assistant_feedback_actor_user_id": ["actor_user_id"],
        "ix_assistant_feedback_actor_username": ["actor_username"],
        "ix_assistant_feedback_answer_hash": ["answer_hash"],
        "ix_assistant_feedback_context_type": ["context_type"],
        "ix_assistant_feedback_context_reference": ["context_reference"],
        "ix_assistant_feedback_rating": ["rating"],
        "ix_assistant_feedback_external_provider_used": ["external_provider_used"],
        "ix_assistant_feedback_raw_log_context_included": ["raw_log_context_included"],
        "ix_assistant_feedback_action_requested": ["action_requested"],
        "ix_assistant_feedback_action_executed": ["action_executed"],
        "ix_assistant_feedback_assistant_audit_id": ["assistant_audit_id"],
        "ix_assistant_feedback_created_at": ["created_at"],
    }.items():
        op.create_index(index_name, "assistant_feedback", columns, unique=False)


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    if "assistant_feedback" not in set(inspector.get_table_names()):
        return
    for index in inspector.get_indexes("assistant_feedback"):
        op.drop_index(index["name"], table_name="assistant_feedback")
    op.drop_table("assistant_feedback")
