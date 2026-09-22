"""add operation job self-reference foreign keys and alert evidence uniqueness

Revision ID: ff5e3639ceb0
Revises: c3d4e5f6a7b8
Create Date: 2026-09-22 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
from sqlalchemy import inspect


revision: str = "ff5e3639ceb0"
down_revision: str | None = "c3d4e5f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RESUME_FK = "fk_operation_jobs_resume_of_job_id_operation_jobs"
_ORIGINAL_FK = "fk_operation_jobs_original_job_id_operation_jobs"
_EVIDENCE_UNIQUE = "uq_alert_evidence_alert_normalized_log"


def upgrade() -> None:
    _add_operation_job_self_reference_fks()
    _add_alert_evidence_unique_constraint()


def downgrade() -> None:
    _drop_alert_evidence_unique_constraint()
    _drop_operation_job_self_reference_fks()


def _use_batch_mode() -> bool:
    # SQLite cannot ALTER TABLE to add a constraint; Alembic's batch mode
    # rebuilds the table under the hood to work around that. Postgres (the
    # other dialect this project targets) supports adding constraints
    # directly, where batch mode would just be an unnecessary full-table
    # rebuild.
    return context.is_offline_mode() or op.get_bind().dialect.name == "sqlite"


def _add_operation_job_self_reference_fks() -> None:
    if not context.is_offline_mode():
        existing = {fk["name"] for fk in inspect(op.get_bind()).get_foreign_keys("operation_jobs")}
        if _RESUME_FK in existing and _ORIGINAL_FK in existing:
            return
    if _use_batch_mode():
        with op.batch_alter_table("operation_jobs") as batch_op:
            batch_op.create_foreign_key(_RESUME_FK, "operation_jobs", ["resume_of_job_id"], ["id"])
            batch_op.create_foreign_key(_ORIGINAL_FK, "operation_jobs", ["original_job_id"], ["id"])
    else:
        op.create_foreign_key(_RESUME_FK, "operation_jobs", "operation_jobs", ["resume_of_job_id"], ["id"])
        op.create_foreign_key(_ORIGINAL_FK, "operation_jobs", "operation_jobs", ["original_job_id"], ["id"])


def _drop_operation_job_self_reference_fks() -> None:
    if _use_batch_mode():
        with op.batch_alter_table("operation_jobs") as batch_op:
            batch_op.drop_constraint(_ORIGINAL_FK, type_="foreignkey")
            batch_op.drop_constraint(_RESUME_FK, type_="foreignkey")
    else:
        op.drop_constraint(_ORIGINAL_FK, "operation_jobs", type_="foreignkey")
        op.drop_constraint(_RESUME_FK, "operation_jobs", type_="foreignkey")


def _add_alert_evidence_unique_constraint() -> None:
    if not context.is_offline_mode():
        existing = {uc["name"] for uc in inspect(op.get_bind()).get_unique_constraints("alert_evidence")}
        if _EVIDENCE_UNIQUE in existing:
            return
    if _use_batch_mode():
        with op.batch_alter_table("alert_evidence") as batch_op:
            batch_op.create_unique_constraint(_EVIDENCE_UNIQUE, ["alert_id", "normalized_log_id"])
    else:
        op.create_unique_constraint(_EVIDENCE_UNIQUE, "alert_evidence", ["alert_id", "normalized_log_id"])


def _drop_alert_evidence_unique_constraint() -> None:
    if _use_batch_mode():
        with op.batch_alter_table("alert_evidence") as batch_op:
            batch_op.drop_constraint(_EVIDENCE_UNIQUE, type_="unique")
    else:
        op.drop_constraint(_EVIDENCE_UNIQUE, "alert_evidence", type_="unique")
