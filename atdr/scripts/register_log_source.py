import argparse
import json
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy import select

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import LogSource
from atdr.app.services.source_service import create_source, source_to_dict, update_source


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def register_log_source(
    *,
    name: str,
    source_type: str,
    parser_profile: str = "palo_alto",
    host: str | None = None,
    port: int | None = None,
    enabled: bool = True,
    update_existing: bool = True,
) -> dict[str, Any]:
    init_db()
    with SessionLocal() as db:
        existing = db.scalar(select(LogSource).where(LogSource.name == name).limit(1))
        if existing is not None:
            if not update_existing:
                return {"ok": False, "error": f"Source already exists: {name}", "source": source_to_dict(existing)}
            source = update_source(
                db,
                existing,
                {
                    "source_type": source_type,
                    "parser_profile": parser_profile,
                    "host": host,
                    "port": port,
                    "enabled": enabled,
                },
            )
            return {"ok": True, "action": "updated", "source": source_to_dict(source, include_quality=True, db=db)}
        try:
            source = create_source(
                db,
                name=name,
                source_type=source_type,
                parser_profile=parser_profile,
                host=host,
                port=port,
                enabled=enabled,
            )
        except IntegrityError as exc:
            db.rollback()
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "action": "created", "source": source_to_dict(source, include_quality=True, db=db)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Register or update an ATDR log source/sensor.")
    parser.add_argument("--name", required=True, help="Unique source name, for example lab-firewall-1.")
    parser.add_argument("--source-type", default="firewall", choices=["file_import", "replay", "syslog_udp", "syslog_tcp", "router", "firewall", "sample"])
    parser.add_argument("--parser-profile", default="palo_alto", choices=["palo_alto", "generic_syslog", "raw_fallback"])
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--no-update", action="store_true", help="Fail if the source already exists.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    result = register_log_source(
        name=args.name,
        source_type=args.source_type,
        parser_profile=args.parser_profile,
        host=args.host,
        port=args.port,
        enabled=not args.disabled,
        update_existing=not args.no_update,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
