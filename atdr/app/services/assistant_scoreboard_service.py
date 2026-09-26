"""Assistant scoreboard: how many realistic questions the SOC assistant answers well.

Runs every question in data/evaluation/assistant_questions.json against a
scratch copy of the configured database (the assistant records conversation
context and audit rows, so it never runs on the real one). Expected numbers
("facts") are computed here with plain queries, independently of the
assistant's own code, so a counting bug cannot grade itself as correct.
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from datetime import UTC, datetime, time as day_time, timedelta
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import PROJECT_ROOT, Settings, get_settings
from atdr.app.db.models import Alert, NormalizedLog
from atdr.app.services.assistant_service import answer_assistant_question
from atdr.app.services.detection_scoreboard_service import configured_sqlite_path, snapshot_database

QUESTIONS_PATH = PROJECT_ROOT / "data" / "evaluation" / "assistant_questions.json"
REPORT_DIR = PROJECT_ROOT / ".tmp" / "assistant_scoreboard"
FALLBACK_CONTEXT = "unmatched_question"
_NUMBER = re.compile(r"\d[\d,]*")


def _today_utc_bounds() -> tuple[datetime, datetime]:
    """Server-local calendar day as naive UTC, matching how alerts are stored."""

    local_now = datetime.now().astimezone()
    start_local = datetime.combine(local_now.date(), day_time.min, tzinfo=local_now.tzinfo)
    start = start_local.astimezone(UTC).replace(tzinfo=None)
    return start, start + timedelta(days=1)


def compute_facts(db: Session) -> dict[str, Any]:
    start, end = _today_utc_bounds()
    today = (Alert.created_at >= start, Alert.created_at < end)

    def count(*conditions) -> int:
        return int(db.scalar(select(func.count(Alert.id)).where(*conditions)) or 0)

    latest_critical = db.scalar(
        select(Alert.id).where(Alert.severity == "Critical").order_by(Alert.created_at.desc(), Alert.id.desc()).limit(1)
    )
    return {
        "logs_total": int(db.scalar(select(func.count(NormalizedLog.id))) or 0),
        "alerts_total": count(),
        "alerts_today": count(*today),
        "high_alerts_today": count(*today, Alert.severity == "High"),
        "critical_alerts_today": count(*today, Alert.severity == "Critical"),
        "open_critical_alerts": count(Alert.severity == "Critical", Alert.status == "open"),
        "latest_critical_alert": int(latest_critical) if latest_critical is not None else None,
    }


def numbers_in(text: str) -> set[int]:
    return {int(match.replace(",", "")) for match in _NUMBER.findall(text or "")}


def check_answer(spec: dict[str, Any], result: dict[str, Any], facts: dict[str, Any]) -> list[str]:
    """Return the reasons a result fails its spec (empty when it passes)."""

    answer = str(result.get("answer") or "")
    lowered = answer.lower()
    problems = []
    if spec.get("answered") and FALLBACK_CONTEXT in (result.get("context_used") or []):
        problems.append("fell back to 'no built-in answer'")
    found = numbers_in(answer)
    for name in spec.get("facts", []):
        expected = facts.get(name)
        if expected is None:
            problems.append(f"fact {name} is unavailable in this database")
        elif int(expected) not in found:
            problems.append(f"missing {name}={expected}")
    options = spec.get("any", [])
    if options and not any(option.lower() in lowered for option in options):
        problems.append(f"mentions none of {options}")
    for phrase in spec.get("all", []):
        if phrase.lower() not in lowered:
            problems.append(f"does not mention {phrase!r}")
    for phrase in spec.get("none", []):
        if phrase.lower() in lowered:
            problems.append(f"says forbidden {phrase!r}")
    return problems


def _fill(text: str, facts: dict[str, Any]) -> str:
    return re.sub(r"\{(\w+)\}", lambda match: str(facts.get(match.group(1), match.group(0))), text)


def run_assistant_scoreboard(
    *,
    source: Path | None = None,
    questions_path: Path = QUESTIONS_PATH,
    settings: Settings | None = None,
    ask: Callable[..., dict[str, Any]] = answer_assistant_question,
    work_dir: Path | None = None,
    report_dir: Path | None = REPORT_DIR,
) -> dict[str, Any]:
    suite = json.loads(questions_path.read_text(encoding="utf-8"))
    base = settings or get_settings()
    # Deterministic baseline unless a caller passes an engine on purpose; a
    # high rate limit so a batch of questions is not throttled.
    run_settings = base.model_copy(update={"assistant_rate_limit_requests": 1_000_000})
    if settings is None:
        run_settings = run_settings.model_copy(update={"assistant_llm_enabled": False})

    work_dir = (work_dir or REPORT_DIR / "work").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    copy = work_dir / f"assistant-{uuid4().hex}.db"
    snapshot_database((source or configured_sqlite_path()).resolve(), copy)
    engine = create_engine(f"sqlite:///{copy.as_posix()}", future=True)
    rows: list[dict[str, Any]] = []
    try:
        with sessionmaker(bind=engine, future=True)() as db:
            facts = compute_facts(db)

            def run(spec: dict[str, Any], *, conversation_id: str, reset: bool, case_id: str, category: str) -> None:
                question = _fill(spec["q"], facts)
                started = time.perf_counter()
                try:
                    result = ask(
                        db,
                        question=question,
                        actor="assistant_scoreboard",
                        settings=run_settings,
                        conversation_id=conversation_id,
                        reset_context=reset,
                    )
                    problems = check_answer(spec, result, facts)
                except Exception as error:  # a crash is a failed answer, not a crashed run
                    db.rollback()
                    result, problems = {}, [f"error {error.__class__.__name__}: {error}"]
                rows.append({
                    "id": case_id,
                    "category": category,
                    "question": question,
                    "passed": not problems,
                    "problems": problems,
                    "response_mode": result.get("response_mode"),
                    "seconds": round(time.perf_counter() - started, 3),
                    "answer_excerpt": str(result.get("answer") or "")[:300],
                })

            for spec in suite.get("questions", []):
                run(spec, conversation_id=f"score-{spec['id']}", reset=True, case_id=spec["id"], category=spec["category"])
            for conversation in suite.get("conversations", []):
                for index, turn in enumerate(conversation["turns"]):
                    run(turn, conversation_id=f"score-{conversation['id']}", reset=index == 0,
                        case_id=f"{conversation['id']}.{index + 1}", category=conversation["category"])
    finally:
        engine.dispose()
        copy.unlink(missing_ok=True)

    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_category[row["category"]].append(row)
    seconds = sorted(row["seconds"] for row in rows)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "suite_version": suite.get("version"),
        "engine": "gemini" if run_settings.assistant_llm_enabled else "local (no external model)",
        "facts": facts,
        "total": len(rows),
        "passed": sum(1 for row in rows if row["passed"]),
        "pass_rate": round(sum(1 for row in rows if row["passed"]) / len(rows), 4) if rows else None,
        "fallbacks": sum(1 for row in rows if any("fell back" in problem for problem in row["problems"])),
        "by_category": {
            name: {"passed": sum(1 for row in items if row["passed"]), "total": len(items)}
            for name, items in sorted(by_category.items())
        },
        "seconds_mean": round(sum(seconds) / len(seconds), 3) if seconds else None,
        "seconds_p95": seconds[max(0, int(len(seconds) * 0.95) - 1)] if seconds else None,
        "rows": rows,
    }
    if report_dir is not None:
        report_dir.mkdir(parents=True, exist_ok=True)
        text = json.dumps(report, indent=2, default=str)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        (report_dir / f"assistant-{stamp}.json").write_text(text, encoding="utf-8")
        (report_dir / "latest.json").write_text(text, encoding="utf-8")
    return report
