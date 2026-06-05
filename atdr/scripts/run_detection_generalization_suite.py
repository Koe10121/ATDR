import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import LogSource, ResponseAction
from atdr.app.detection.explanations import build_alert_detection_summary
from atdr.app.services.alert_service import list_alerts
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import count_nonblank_log_lines, import_log_file
from atdr.app.services.source_service import get_or_create_source, source_to_dict
from atdr.scripts.generate_detection_variants import DEFAULT_OUTPUT_DIR as DEFAULT_VARIANT_DIR
from atdr.scripts.generate_detection_variants import generate_detection_variants
from atdr.scripts.run_detection_validation_suite import (
    SEVERITY_RANK,
    _check_expectations,
    _json_default,
    _load_expectations,
    _risk_calibration_for_result,
)
from atdr.scripts.run_source_scenario import SCENARIOS, _temp_session_factory


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "detection_generalization"


def _scenario_source_name(scenario: str, variant_id: int, *, use_temp_db: bool) -> str:
    if use_temp_db:
        return f"generalization-{scenario}-v{variant_id}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"generalization-{scenario}-v{variant_id}-{stamp}"


def _attack_types_from_alerts(alerts: list[dict[str, Any]]) -> set[str]:
    return {str(alert.get("attack_type") or "") for alert in alerts if alert.get("attack_type")}


def _expected_attack_types(expectation: dict[str, Any]) -> set[str]:
    if expectation.get("expected_attack_types"):
        return {str(item) for item in expectation["expected_attack_types"]}
    if expectation.get("expected_attack_type"):
        return {str(expectation["expected_attack_type"])}
    return set()


def _variant_false_positive(expectation: dict[str, Any], alerts: list[dict[str, Any]]) -> bool:
    if expectation.get("expected_alert_present"):
        return False
    max_allowed = expectation.get("expected_alert_count_max")
    high_critical = [alert for alert in alerts if SEVERITY_RANK.get(str(alert.get("severity") or "Low"), 0) >= SEVERITY_RANK["High"]]
    too_many = max_allowed is not None and len(alerts) > int(max_allowed)
    return bool(high_critical or too_many)


def _variant_false_negative(expectation: dict[str, Any], alerts: list[dict[str, Any]]) -> bool:
    if not expectation.get("expected_alert_present"):
        return False
    if not alerts:
        return True
    expected = _expected_attack_types(expectation)
    if expected:
        return not expected.issubset(_attack_types_from_alerts(alerts))
    return False


def _contribution_summary(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    source_counter: Counter[str] = Counter()
    for summary in summaries:
        for source in summary.get("detection_source") or []:
            source_counter[str(source)] += 1
    return {
        "rule_alerts": source_counter.get("rule", 0),
        "anomaly_alerts": source_counter.get("anomaly", 0),
        "supervised_signal_alerts": source_counter.get("supervised", 0),
        "hybrid_signal_alerts": source_counter.get("hybrid", 0),
        "rule_contributed": source_counter.get("rule", 0) > 0,
        "anomaly_contributed": source_counter.get("anomaly", 0) > 0,
        "supervised_signal_available": source_counter.get("supervised", 0) > 0,
        "hybrid_score_available": source_counter.get("hybrid", 0) > 0,
        "interpretation": "Layered SOC triage evidence; response automation remains disabled.",
    }


def _run_variant_in_session(
    *,
    db: Session,
    scenario: str,
    variant: dict[str, Any],
    expectation: dict[str, Any],
    use_ml: bool,
    use_temp_db: bool,
) -> dict[str, Any]:
    spec = SCENARIOS[scenario]
    source = get_or_create_source(
        db,
        name=_scenario_source_name(scenario, int(variant["variant_id"]), use_temp_db=use_temp_db),
        source_type=spec.default_source_type,
        parser_profile=spec.default_parser_profile,
    )
    db.commit()
    db.refresh(source)
    response_actions_before = int(db.query(ResponseAction).count())
    path = Path(variant["path"])
    import_results = [
        import_log_file(
            db,
            path,
            actor="detection_generalization",
            source_id=source.id,
            parser_profile=spec.default_parser_profile,
        )
    ]
    detection_results = [
        run_detection(
            db,
            limit=max(100, count_nonblank_log_lines(path) * 3),
            use_ml=use_ml,
            actor="detection_generalization",
            source_id=source.id,
            source_name=source.name,
            source_type=source.source_type,
        )
    ]
    if spec.repeat_import_detection:
        import_results.append(
            import_log_file(
                db,
                path,
                actor="detection_generalization",
                source_id=source.id,
                parser_profile=spec.default_parser_profile,
            )
        )
        detection_results.append(
            run_detection(
                db,
                limit=max(100, count_nonblank_log_lines(path) * 3),
                use_ml=use_ml,
                actor="detection_generalization",
                source_id=source.id,
                source_name=source.name,
                source_type=source.source_type,
            )
        )
    db.refresh(source)
    alerts = list_alerts(db, source_id=source.id, limit=50)
    summaries = [build_alert_detection_summary(db, alert) for alert in alerts]
    checks, evidence_corpus = _check_expectations(
        db=db,
        scenario=scenario,
        expectation=expectation,
        source=source,
        alerts=alerts,
        summaries=summaries,
        response_actions_before=response_actions_before,
    )
    alert_rows = [
        {
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "risk_score": alert.threat_score,
            "title": alert.title,
            "evidence_count": len(alert.evidence),
            "attack_type": summary.get("attack_type"),
            "why_flagged": summary.get("why_flagged"),
            "detection_source": summary.get("detection_source"),
            "top_evidence_points": summary.get("top_evidence_points", []),
        }
        for alert, summary in zip(alerts, summaries, strict=False)
    ]
    passed = all(check["passed"] for check in checks)
    response_actions_created = int(db.query(ResponseAction).count()) - response_actions_before
    result = {
        "scenario": scenario,
        "variant_id": int(variant["variant_id"]),
        "variant_file": Path(variant["path"]).name,
        "passed": passed,
        "false_positive": _variant_false_positive(expectation, alert_rows),
        "false_negative": _variant_false_negative(expectation, alert_rows),
        "checks": checks,
        "source": source_to_dict(source, include_quality=True, db=db),
        "import_results": import_results,
        "detection_results": detection_results,
        "alert_count": len(alert_rows),
        "alerts": alert_rows,
        "attack_types": sorted(_attack_types_from_alerts(alert_rows)),
        "contribution": _contribution_summary(summaries),
        "safety": {
            "controlled_generalization_validation": True,
            "synthetic_variant": True,
            "real_production_deployment": False,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_actions_created": response_actions_created,
        },
        "evidence_text_excerpt": evidence_corpus[:1000],
    }
    result["risk_calibration"] = _risk_calibration_for_result(result)
    return result


def run_detection_generalization_variant(
    *,
    scenario: str,
    variant: dict[str, Any],
    expectation: dict[str, Any],
    use_temp_db: bool = True,
    use_ml: bool = False,
) -> dict[str, Any]:
    temp_engine = None
    if use_temp_db:
        temp_engine, SessionFactory = _temp_session_factory()
    else:
        init_db()
        SessionFactory = SessionLocal

    try:
        with SessionFactory() as db:
            return _run_variant_in_session(
                db=db,
                scenario=scenario,
                variant=variant,
                expectation=expectation,
                use_ml=use_ml,
                use_temp_db=use_temp_db,
            )
    finally:
        if temp_engine is not None:
            temp_engine.dispose()


def _family_summary(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        grouped[result["scenario"]].append(result)
    rows: list[dict[str, Any]] = []
    for scenario, items in sorted(grouped.items()):
        alert_attack_types = sorted({attack_type for item in items for attack_type in item.get("attack_types", [])})
        rows.append(
            {
                "scenario": scenario,
                "variants_tested": len(items),
                "passed_count": sum(1 for item in items if item["passed"]),
                "failed_count": sum(1 for item in items if not item["passed"]),
                "false_positive_count": sum(1 for item in items if item["false_positive"]),
                "false_negative_count": sum(1 for item in items if item["false_negative"]),
                "detection_consistency": round(sum(1 for item in items if item["passed"]) / max(1, len(items)), 4),
                "alert_attack_types": alert_attack_types,
                "rule_contributed": any(item["contribution"]["rule_contributed"] for item in items),
                "anomaly_contributed": any(item["contribution"]["anomaly_contributed"] for item in items),
                "supervised_signal_available": any(item["contribution"]["supervised_signal_available"] for item in items),
                "hybrid_score_available": any(item["contribution"]["hybrid_score_available"] for item in items),
            }
        )
    return rows


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Detection Generalization Validation",
        "",
        f"- Generated at: {report['generated_at']}",
        "- Scope: controlled synthetic scenario variants",
        f"- Database mode: {'temporary in-memory SQLite' if report['use_temp_db'] else 'current local database'}",
        "- Response mode: simulated and analyst-approved only",
        "- Real firewall blocking: disabled",
        "- Production readiness claim: none",
        "",
        "## Summary",
        "",
        f"- Passed variants: {report['passed_count']} / {report['variant_count']}",
        f"- False positives: {report['false_positive_count']}",
        f"- False negatives: {report['false_negative_count']}",
        "",
        "| Scenario family | Variants | Passed | False positives | False negatives | Consistency | Contributions |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for family in report["families"]:
        contributions = []
        if family["rule_contributed"]:
            contributions.append("rule")
        if family["anomaly_contributed"]:
            contributions.append("anomaly")
        if family["supervised_signal_available"]:
            contributions.append("supervised")
        if family["hybrid_score_available"]:
            contributions.append("hybrid")
        lines.append(
            "| "
            f"{family['scenario']} | "
            f"{family['variants_tested']} | "
            f"{family['passed_count']} | "
            f"{family['false_positive_count']} | "
            f"{family['false_negative_count']} | "
            f"{family['detection_consistency']:.2f} | "
            f"{', '.join(contributions) or '-'} |"
        )
    lines.extend(["", "## Variant Details", ""])
    for item in report["variants"]:
        risk = item["risk_calibration"]
        lines.extend(
            [
                f"### {item['scenario']} variant {item['variant_id']}",
                "",
                f"- Result: {'PASS' if item['passed'] else 'FAIL'}",
                f"- False positive: {'yes' if item['false_positive'] else 'no'}",
                f"- False negative: {'yes' if item['false_negative'] else 'no'}",
                f"- Alerts: {item['alert_count']}",
                f"- Attack types: {', '.join(item['attack_types']) or '-'}",
                f"- Severity max: {risk['actual_max_severity']}",
                f"- Risk max: {risk['actual_max_risk_score']}",
                f"- Response actions created: {item['safety']['response_actions_created']}",
                "",
                "Checks:",
            ]
        )
        for check in item["checks"]:
            lines.append(f"- {'PASS' if check['passed'] else 'FAIL'} {check['name']}: {check['detail']}")
        if item["alerts"]:
            lines.append("")
            lines.append("Alert evidence:")
            for alert in item["alerts"][:3]:
                lines.append(f"- {alert['alert_type']} ({alert['severity']} / {alert['risk_score']}): {alert['why_flagged']}")
        lines.append("")
    lines.extend(
        [
            "## Limitations",
            "",
            "- This reduces overfitting risk for fixed sample files but does not replace real device validation.",
            "- Variants are synthetic defensive log records, not offensive activity.",
            "- ML remains SOC triage decision support only.",
            "- Response actions remain simulated and analyst-approved only.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"detection_generalization_{timestamp}"
    json_path = output_dir / f"{stem}.json"
    md_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, default=_json_default, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def run_detection_generalization_suite(
    *,
    scenarios: list[str] | None = None,
    variants: int = 5,
    use_temp_db: bool = True,
    use_ml: bool = False,
    write_output: bool = True,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    variant_output_dir: Path = DEFAULT_VARIANT_DIR,
) -> dict[str, Any]:
    expectations = _load_expectations()
    selected = scenarios or list(expectations.keys())
    manifest = generate_detection_variants(
        scenarios=selected,
        variants=variants,
        output_dir=variant_output_dir,
    )
    results = [
        run_detection_generalization_variant(
            scenario=str(variant["scenario"]),
            variant=variant,
            expectation=expectations[str(variant["scenario"])],
            use_temp_db=use_temp_db,
            use_ml=use_ml,
        )
        for variant in manifest["variants"]
    ]
    report = {
        "ok": all(item["passed"] for item in results),
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "controlled synthetic detection generalization validation",
        "use_temp_db": use_temp_db,
        "use_ml": use_ml,
        "scenario_count": len(selected),
        "variant_count": len(results),
        "passed_count": sum(1 for item in results if item["passed"]),
        "failed_count": sum(1 for item in results if not item["passed"]),
        "false_positive_count": sum(1 for item in results if item["false_positive"]),
        "false_negative_count": sum(1 for item in results if item["false_negative"]),
        "families": _family_summary(results),
        "variants": results,
        "variant_manifest": {
            "manifest_path": manifest["manifest_path"],
            "output_dir": manifest["output_dir"],
            "variant_count": manifest["variant_count"],
        },
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "response_mode": "simulated analyst-approved only",
            "production_readiness_claim": False,
            "synthetic_variants_only": True,
        },
    }
    if write_output:
        report["paths"] = write_report(report, output_dir=output_dir)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ATDR detection generalization validation using safe generated variants.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="Scenario family to validate. Repeat for multiple.")
    parser.add_argument("--all", action="store_true", help="Validate variants for every known scenario family.")
    parser.add_argument("--variants", type=int, default=5)
    parser.add_argument("--use-temp-db", action="store_true", default=True, help="Use temporary in-memory SQLite; default true.")
    parser.add_argument("--write-to-current-db", action="store_true", help="Opt in to writing generated variants to the current local DB.")
    parser.add_argument("--use-ml", action="store_true", help="Run detection with assistive ML scoring when available.")
    parser.add_argument("--no-report", action="store_true", help="Do not write JSON/Markdown report files.")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--variant-output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    selected = None if args.all or not args.scenario else args.scenario
    report = run_detection_generalization_suite(
        scenarios=selected,
        variants=args.variants,
        use_temp_db=not args.write_to_current_db,
        use_ml=args.use_ml,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
        variant_output_dir=Path(args.variant_output_dir) if args.variant_output_dir else DEFAULT_VARIANT_DIR,
    )
    print(json.dumps(report, default=_json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
