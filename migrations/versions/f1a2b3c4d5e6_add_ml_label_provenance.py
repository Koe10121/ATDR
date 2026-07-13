"""add ml label provenance

Revision ID: f1a2b3c4d5e6
Revises: d2f6c9a8b4e1
Create Date: 2026-05-23 15:35:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "f1a2b3c4d5e6"
down_revision = "d2f6c9a8b4e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ml_labels", sa.Column("label_source", sa.String(length=32), server_default="manual", nullable=False))
    op.add_column("ml_labels", sa.Column("reviewed", sa.Boolean(), server_default=sa.true(), nullable=False))
    op.create_index(op.f("ix_ml_labels_label_source"), "ml_labels", ["label_source"], unique=False)
    op.create_index(op.f("ix_ml_labels_reviewed"), "ml_labels", ["reviewed"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_ml_labels_reviewed"), table_name="ml_labels")
    op.drop_index(op.f("ix_ml_labels_label_source"), table_name="ml_labels")
    op.drop_column("ml_labels", "reviewed")
    op.drop_column("ml_labels", "label_source")
