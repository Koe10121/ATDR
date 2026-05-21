from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from atdr.app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine_kwargs: dict = {}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, future=True, **engine_kwargs)
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
        else:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as exc:  # pragma: no cover - exercised by live deployments
        return {"status": "error", "detail": exc.__class__.__name__}
