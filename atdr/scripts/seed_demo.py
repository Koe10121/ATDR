from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.demo_service import resolve_demo_sample_path
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.user_service import ensure_demo_users
from atdr.app.core.config import get_settings


def main() -> None:
    settings = get_settings()
    sample = resolve_demo_sample_path()
    limit = settings.demo_import_limit if settings.demo_import_limit > 0 else None
    init_db()
    with SessionLocal() as db:
        print({"users": ensure_demo_users(db)})
        if sample.exists():
            print(import_log_file(db, sample, limit=limit, actor="seed_demo"))
            print(run_detection(db, limit=limit, use_ml=False, actor="seed_demo"))
        else:
            print(f"Sample file not found: {sample}")


if __name__ == "__main__":
    main()
