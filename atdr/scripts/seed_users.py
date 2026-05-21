from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.user_service import ensure_demo_users


def main() -> None:
    init_db()
    with SessionLocal() as db:
        result = ensure_demo_users(db)
    print({"created_users": result})


if __name__ == "__main__":
    main()
