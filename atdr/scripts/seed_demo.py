from pathlib import Path

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.user_service import ensure_demo_users


ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "paloalto-firewall(1).log"


def main() -> None:
    init_db()
    with SessionLocal() as db:
        print({"users": ensure_demo_users(db)})
        if SAMPLE.exists():
            print(import_log_file(db, SAMPLE, limit=5000, actor="seed_demo"))
            print(run_detection(db, limit=5000, use_ml=False, actor="seed_demo"))
        else:
            print(f"Sample file not found: {SAMPLE}")


if __name__ == "__main__":
    main()
