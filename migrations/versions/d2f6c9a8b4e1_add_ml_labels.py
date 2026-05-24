"""add ml labels

Revision ID: d2f6c9a8b4e1
Revises: b8f2c1d4e6a9
Create Date: 2026-05-23 09:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "d2f6c9a8b4e1"
down_revision = "b8f2c1d4e6a9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ml_labels",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("log_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("attack_type", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("reviewer", sa.String(length=128), nullable=False),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["log_id"], ["normalized_logs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ml_labels_attack_type"), "ml_labels", ["attack_type"], unique=False)
    op.create_index(op.f("ix_ml_labels_label"), "ml_labels", ["label"], unique=False)
    op.create_index(op.f("ix_ml_labels_log_id"), "ml_labels", ["log_id"], unique=False)
    op.create_index("ix_ml_labels_log_created", "ml_labels", ["log_id", "created_at"], unique=False)
    op.create_index(op.f("ix_ml_labels_reviewer"), "ml_labels", ["reviewer"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_ml_labels_reviewer"), table_name="ml_labels")
    op.drop_index("ix_ml_labels_log_created", table_name="ml_labels")
    op.drop_index(op.f("ix_ml_labels_log_id"), table_name="ml_labels")
    op.drop_index(op.f("ix_ml_labels_label"), table_name="ml_labels")
    op.drop_index(op.f("ix_ml_labels_attack_type"), table_name="ml_labels")
    op.drop_table("ml_labels")
