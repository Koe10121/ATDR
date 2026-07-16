"""add indexed raw log content fingerprint

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-07-13 21:00:00.000000
"""

from __future__ import annotations

import hashlib

from alembic import context, op
import sqlalchemy as sa


revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None

_BACKFILL_BATCH_SIZE = 2000


def _fingerprint(raw_line: str) -> str:
    return hashlib.sha256(raw_line.encode("utf-8", errors="surrogatepass")).hexdigest()


def upgrade() -> None:
    op.add_column("raw_logs", sa.Column("raw_line_hash", sa.String(length=64), nullable=True))

    if context.is_offline_mode():
        if op.get_context().dialect.name == "postgresql":
            op.execute(
                sa.text(
                    """
                    UPDATE raw_logs
                    SET raw_line_hash = encode(
                        sha256(convert_to(COALESCE(raw_line, ''), 'UTF8')),
                        'hex'
                    )
                    WHERE raw_line_hash IS NULL
                    """
                )
            )
    else:
        connection = op.get_bind()
        raw_logs = sa.table(
            "raw_logs",
            sa.column("id", sa.Integer()),
            sa.column("raw_line", sa.Text()),
            sa.column("raw_line_hash", sa.String(length=64)),
        )
        last_id = 0
        while True:
            rows = connection.execute(
                sa.select(raw_logs.c.id, raw_logs.c.raw_line)
                .where(raw_logs.c.id > last_id)
                .order_by(raw_logs.c.id)
                .limit(_BACKFILL_BATCH_SIZE)
            ).mappings().all()
            if not rows:
                break
            connection.execute(
                raw_logs.update()
                .where(raw_logs.c.id == sa.bindparam("row_id"))
                .values(raw_line_hash=sa.bindparam("line_hash")),
                [
                    {
                        "row_id": int(row["id"]),
                        "line_hash": _fingerprint(str(row["raw_line"] or "")),
                    }
                    for row in rows
                ],
            )
            last_id = int(rows[-1]["id"])

    op.create_index("ix_raw_logs_raw_line_hash", "raw_logs", ["raw_line_hash"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_raw_logs_raw_line_hash", table_name="raw_logs")
    op.drop_column("raw_logs", "raw_line_hash")
