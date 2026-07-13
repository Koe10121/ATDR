from collections.abc import Generator

from sqlalchemy import inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from atdr.app.core.config import get_settings
from atdr.app.db.engine import create_configured_engine, database_kind, inspect_database_runtime, migration_head_revision


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_configured_engine(settings)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from atdr.app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def check_database_connection(db: Session | None = None) -> dict:
    try:
        if db is not None:
            db.execute(text("SELECT 1"))
            bind = db.get_bind()
        else:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            bind = engine
        inspector = inspect(bind)
        revision = None
        if inspector.has_table("alembic_version"):
            if db is not None:
                revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
            else:
                with engine.connect() as connection:
                    revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        head_revision = migration_head_revision()
        migration_status = "at_head" if revision and revision == head_revision else "unversioned" if not revision else "not_at_head"
        runtime = inspect_database_runtime(settings, probe_connection=False)
        return {
            "status": "ok",
            "dialect": database_kind(settings.database_url),
            "migration": {"status": migration_status, "revision": revision, "head_revision": head_revision},
            "backup_tools": runtime["backup_tools"],
            "secrets_exposed": False,
        }
    except Exception as exc:  # pragma: no cover - exercised by live deployments
        return {
            "status": "error",
            "dialect": database_kind(settings.database_url),
            "detail": exc.__class__.__name__,
            "secrets_exposed": False,
        }
