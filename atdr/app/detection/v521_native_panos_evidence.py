from __future__ import annotations

import csv
import hashlib
import json
import math
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.detection import v56_private_panos_model_repair as v56


V521_VERSION = "v5.21-native-panos-evidence-v1"
V521_MANIFEST_VERSION = "v5.21-native-panos-role-lock-v1"
V521_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V521_MANIFEST_LATEST = "v5_21_native_panos_manifest_latest.json"
V521_RESULT_LATEST = "v5_21_native_panos_evidence_latest.json"
V521_DEVELOPMENT_PACK = "v5_21_development_assisted_review_pack.csv"
V521_BLIND_PACK = "v5_21_blind_human_verification_pack.csv"

DEVELOPMENT_ROLE_RANKS = {0, 1, 2}
BLIND_ROLE_RANK = 3
REVIEW_PATTERNS = (
    "vendor_threat_record",
    "scan_like_behavior",
    "denied_high_risk",
    "quic_443_allow",
    "incomplete_80_allow",
    "unknown_udp",
    "unknown_tcp",
    "parser_limited",
    "routine_allowed",
    "other_context",
)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stable_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def official_panos_field_contract() -> dict[str, Any]:
    return {
        "version": "v5.21-panos-official-field-contract-v1",
        "format": {
            "delimiter": "comma-separated PAN-OS syslog payload",
            "reserved_fields": "FUTURE_USE fields are not evidence features",
        },
        "traffic": {
            "required_context": [
                "generated_time",
                "source_address",
                "destination_address",
                "application",
                "source_zone",
                "destination_zone",
                "destination_port",
                "protocol",
                "action",
            ],
            "supporting_context": [
                "bytes",
                "bytes_sent",
                "bytes_received",
                "packets",
                "elapsed_time",
                "session_end_reason",
                "application_risk",
            ],
            "semantic_limit": (
                "A TRAFFIC record describes a session. An allow, deny, app-risk, "
                "or unusual port is context and is not malicious ground truth by itself."
            ),
        },
        "threat": {
            "required_context": [
                "generated_time",
                "source_address",
                "destination_address",
                "application",
                "source_zone",
                "destination_zone",
                "destination_port",
                "protocol",
                "action",
                "threat_id_or_name",
                "severity",
            ],
            "semantic_limit": (
                "A THREAT record means traffic matched a configured Security Profile. "
                "Severity and action support prioritization but still require analyst context."
            ),
        },
        "application_risk": {
            "range": "1-5",
            "semantic_limit": (
                "Application risk is relative application context; a high value alone "
                "does not establish malicious behavior."
            ),
        },
        "primary_sources": [
            {
                "title": "PAN-OS Syslog Field Descriptions",
                "url": (
                    "https://docs.paloaltonetworks.com/ngfw/administration/"
                    "monitoring/use-syslog-for-monitoring/syslog-field-descriptions"
                ),
            },
            {
                "title": "PAN-OS Traffic Log Fields",
                "url": (
                    "https://docs.paloaltonetworks.com/ngfw/administration/"
                    "monitoring/use-syslog-for-monitoring/syslog-field-descriptions/"
                    "traffic-log-fields"
                ),
            },
            {
                "title": "PAN-OS Threat Log Fields",
                "url": (
                    "https://docs.paloaltonetworks.com/ngfw/administration/"
                    "monitoring/use-syslog-for-monitoring/syslog-field-descriptions/"
                    "threat-log-fields"
                ),
            },
            {
                "title": "PAN-OS Log Types and Severity Levels",
                "url": (
                    "https://docs.paloaltonetworks.com/pan-os/11-1/"
                    "pan-os-admin/monitoring/view-and-manage-logs/"
                    "log-types-and-severity-levels/decryption-log"
                ),
            },
            {
                "title": "PAN-OS Application Objects",
                "url": (
                    "https://docs.paloaltonetworks.com/network-security/"
                    "security-policy/administration/objects/applications"
                ),
            },
        ],
        "source_type": "official_vendor_documentation",
    }


def _role_locks(connection: sqlite3.Connection) -> dict[str, Any]:
    locks: dict[str, Any] = {}
    for rank, name in v56.ROLE_NAMES.items():
        exact = hashlib.sha256()
        near = hashlib.sha256()
        rows = 0
        for exact_hash, propagation_hash in connection.execute(
            "SELECT exact_hash, propagation_hash FROM events "
            "WHERE role_rank=? ORDER BY exact_hash, propagation_hash",
            (rank,),
        ):
            exact.update(str(exact_hash).encode("ascii"))
            exact.update(b"\n")
            near.update(str(propagation_hash).encode("ascii"))
            near.update(b"\n")
            rows += 1
        locks[name] = {
            "rows": rows,
            "exact_family_digest": exact.hexdigest(),
            "near_family_digest": near.hexdigest(),
            "fingerprints_recorded_privately": True,
            "fingerprints_exposed": False,
        }
    return locks


def _safe_role_projection(roles: dict[str, Any]) -> dict[str, Any]:
    return {
        name: {
            "rows": int((value or {}).get("rows") or 0),
            "representative_families": int(
                (value or {}).get("representative_families") or 0
            ),
            "time_windows": int((value or {}).get("time_windows") or 0),
        }
        for name, value in (roles or {}).items()
    }


def _safe_stream_projection(streamed: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": streamed.get("status"),
        "rows_processed": int(streamed.get("rows_processed") or 0),
        "blank_rows": int(streamed.get("blank_rows") or 0),
        "parser_successes": int(streamed.get("parser_successes") or 0),
        "parser_failures": int(streamed.get("parser_failures") or 0),
        "parser_success_rate": streamed.get("parser_success_rate"),
        "exact_duplicate_rows": int(streamed.get("exact_duplicate_rows") or 0),
        "near_duplicate_rows": int(streamed.get("near_duplicate_rows") or 0),
        "unique_exact_families": int(streamed.get("unique_exact_families") or 0),
        "unique_near_families": int(streamed.get("unique_near_families") or 0),
        "top_log_types": streamed.get("top_log_types") or [],
        "schema_profiles": streamed.get("schema_profiles") or [],
        "parser_warning_distribution": (
            streamed.get("parser_warning_distribution") or []
        ),
        "configured_database_overlap_rows": int(
            streamed.get("configured_database_overlap_rows") or 0
        ),
        "configured_database_overlap_checked": False,
        "streaming": streamed.get("streaming") or {},
        "application_names_returned": False,
        "action_values_returned": False,
        "port_values_returned": False,
        "zone_values_returned": False,
        "timestamps_returned": False,
        "private_identifiers_returned": False,
    }


def _quarantine_summary(connection: sqlite3.Connection) -> dict[str, Any]:
    reasons = [
        {
            "reason": str(reason or "unclassified_quarantine"),
            "rows": int(count),
        }
        for reason, count in connection.execute(
            "SELECT COALESCE(quarantine_reason, 'unclassified_quarantine'), "
            "COUNT(*) FROM events WHERE role_rank=? "
            "GROUP BY COALESCE(quarantine_reason, 'unclassified_quarantine') "
            "ORDER BY COUNT(*) DESC, quarantine_reason",
            (4,),
        )
    ]
    return {
        "rows": sum(item["rows"] for item in reasons),
        "reasons": reasons,
        "excluded_from_development": True,
        "excluded_from_blind_evaluation": True,
        "raw_evidence_included": False,
        "private_identifiers_included": False,
    }


def _pattern(row: dict[str, Any]) -> str:
    log_type = str(row.get("log_type") or "").upper()
    app = str(row.get("app") or "").lower()
    action = str(row.get("action") or "").lower()
    protocol = str(row.get("protocol") or "").lower()
    port = row.get("dst_port")
    parser_limited = bool(
        row.get("parser_error")
        or int(row.get("required_missing_count") or 0) >= 2
    )
    scan_like = bool(
        int(row.get("source_unique_ports") or 0) >= 10
        or (
            int(row.get("source_event_count") or 0) >= 20
            and int(row.get("source_unique_destinations") or 0) >= 8
        )
    )
    denied = any(token in action for token in v56.DENY_ACTION_TOKENS)
    if log_type == "THREAT":
        return "vendor_threat_record"
    if scan_like:
        return "scan_like_behavior"
    if denied and int(row.get("app_risk") or 0) >= 4:
        return "denied_high_risk"
    if app == "quic-base" and action == "allow" and port == 443:
        return "quic_443_allow"
    if app == "incomplete" and action == "allow" and port == 80:
        return "incomplete_80_allow"
    if app == "unknown-udp" or (app in v56.UNKNOWN_APPS and protocol == "udp"):
        return "unknown_udp"
    if app == "unknown-tcp" or (app in v56.UNKNOWN_APPS and protocol == "tcp"):
        return "unknown_tcp"
    if parser_limited:
        return "parser_limited"
    if action == "allow" and int(row.get("app_risk") or 0) <= 2:
        return "routine_allowed"
    return "other_context"


def _priority(pattern: str, *, blind: bool) -> str:
    if blind:
        return "required_human_ground_truth"
    if pattern in {
        "vendor_threat_record",
        "scan_like_behavior",
        "denied_high_risk",
        "parser_limited",
    }:
        return "high"
    if pattern in {"unknown_udp", "unknown_tcp", "incomplete_80_allow"}:
        return "medium"
    return "standard"


def _offer(
    buckets: dict[tuple[int, str], list[dict[str, Any]]],
    key: tuple[int, str],
    row: dict[str, Any],
    *,
    cap: int,
) -> None:
    values = buckets.setdefault(key, [])
    values.append(row)
    values.sort(key=lambda item: str(item["selection_key"]))
    del values[cap:]


def _round_robin(
    buckets: dict[tuple[int, str], list[dict[str, Any]]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    keys = sorted(buckets)
    offset = 0
    while len(selected) < limit:
        added = False
        for key in keys:
            values = buckets[key]
            if offset < len(values):
                selected.append(values[offset])
                added = True
                if len(selected) >= limit:
                    break
        if not added:
            break
        offset += 1
    return selected


def _review_token(propagation_hash: str) -> str:
    return hashlib.sha256(
        f"v5.21-review:{propagation_hash}".encode("ascii")
    ).hexdigest()[:24]


def _base_review_row(row: dict[str, Any], *, blind: bool) -> dict[str, Any]:
    role = v56.ROLE_NAMES[int(row["role_rank"])]
    pattern = _pattern(row)
    return {
        "review_token": _review_token(str(row["propagation_hash"])),
        "evidence_role": role,
        "evidence_role_is_blind": blind,
        "pattern": pattern,
        "review_priority": _priority(pattern, blind=blind),
        "event_time_utc": row.get("event_time"),
        "log_type": row.get("log_type"),
        "subtype": row.get("subtype"),
        "application": row.get("app"),
        "action": row.get("action"),
        "protocol": row.get("protocol"),
        "source_port": row.get("src_port"),
        "destination_port": row.get("dst_port"),
        "source_zone": row.get("src_zone"),
        "destination_zone": row.get("dst_zone"),
        "bytes": row.get("bytes"),
        "packets": row.get("packets"),
        "elapsed_time": row.get("elapsed_time"),
        "application_risk": row.get("app_risk"),
        "threat_severity": row.get("threat_severity"),
        "session_end_reason": row.get("session_end_reason"),
        "parser_error": bool(row.get("parser_error")),
        "parser_warning_count": int(row.get("parser_warning_count") or 0),
        "required_missing_count": int(row.get("required_missing_count") or 0),
        "schema_bucket": row.get("schema_bucket"),
        "group_size": int(row.get("group_size") or 1),
        "source_event_count": int(row.get("source_event_count") or 0),
        "source_deny_count": int(row.get("source_deny_count") or 0),
        "source_unique_destinations": int(
            row.get("source_unique_destinations") or 0
        ),
        "source_unique_ports": int(row.get("source_unique_ports") or 0),
        "source_unknown_app_count": int(
            row.get("source_unknown_app_count") or 0
        ),
        "source_high_risk_app_count": int(
            row.get("source_high_risk_app_count") or 0
        ),
        "destination_repeat_count": int(
            row.get("destination_repeat_count") or 0
        ),
        "raw_log_included": False,
        "source_ip_included": False,
        "destination_ip_included": False,
        "human_decision": "",
        "human_attack_type": "",
        "human_confidence": "",
        "human_notes": "",
        "human_reviewer": "",
        "human_reviewed_at": "",
        "human_must_confirm": True,
        "import_ready": False,
    }


def build_review_packs(
    connection: sqlite3.Connection,
    *,
    review_limit: int = 160,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    total_limit = max(20, min(int(review_limit), 500))
    blind_limit = max(10, int(math.ceil(total_limit * 0.25)))
    development_limit = total_limit - blind_limit
    bucket_cap = max(
        4,
        int(math.ceil(total_limit / max(1, len(REVIEW_PATTERNS)))) * 2,
    )
    development_buckets: dict[tuple[int, str], list[dict[str, Any]]] = {}
    blind_buckets: dict[tuple[int, str], list[dict[str, Any]]] = {}
    candidate_counts: Counter[str] = Counter()

    for values in connection.execute(v56.REPRESENTATIVE_QUERY):
        row = v56._row_mapping(values)
        rank = int(row["role_rank"])
        pattern = _pattern(row)
        candidate_counts[f"{v56.ROLE_NAMES[rank]}:{pattern}"] += 1
        candidate = {
            **row,
            "selection_key": _stable_hash(
                {
                    "version": V521_VERSION,
                    "role": rank,
                    "pattern": pattern,
                    "family": row["propagation_hash"],
                }
            ),
        }
        target = blind_buckets if rank == BLIND_ROLE_RANK else development_buckets
        _offer(target, (rank, pattern), candidate, cap=bucket_cap)

    development_candidates = _round_robin(
        development_buckets,
        limit=development_limit,
    )
    blind_candidates = _round_robin(blind_buckets, limit=blind_limit)

    development_rows: list[dict[str, Any]] = []
    for row in development_candidates:
        codes, score = v56._rule_evidence(row)
        suggestion = v56.assisted_decision(
            row,
            rule_codes=codes,
            rule_score=score,
        )
        development_rows.append(
            {
                **_base_review_row(row, blind=False),
                "assisted_suggestion": suggestion["decision"],
                "assisted_attack_type": (
                    "vendor_threat"
                    if str(row.get("log_type") or "").upper() == "THREAT"
                    else "behavioral_anomaly"
                    if suggestion["decision"] in {"suspicious", "malicious"}
                    else ""
                ),
                "assisted_confidence": suggestion["confidence"],
                "assisted_reason": suggestion["evidence_summary"],
                "assisted_provenance": suggestion["provenance"],
                "rule_codes": "|".join(suggestion["rule_codes"]),
                "rule_score": suggestion["rule_score"],
                "suggestion_is_weak": True,
                "human_reviewed": False,
                "blind_suggestion_suppressed": False,
            }
        )

    blind_rows = [
        {
            **_base_review_row(row, blind=True),
            "assisted_suggestion": "",
            "assisted_attack_type": "",
            "assisted_confidence": "",
            "assisted_reason": "",
            "assisted_provenance": "",
            "rule_codes": "",
            "rule_score": "",
            "suggestion_is_weak": False,
            "human_reviewed": False,
            "blind_suggestion_suppressed": True,
        }
        for row in blind_candidates
    ]
    summary = {
        "requested_rows": total_limit,
        "development_rows": len(development_rows),
        "blind_rows": len(blind_rows),
        "development_suggestions_are_weak": True,
        "blind_suggestions_generated": False,
        "human_reviewed_rows_created": 0,
        "import_ready_rows_created": 0,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "candidate_strata": len(candidate_counts),
        "candidate_counts_recorded_privately": True,
    }
    return development_rows, blind_rows, summary


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _pack_fingerprint(rows: Iterable[dict[str, Any]]) -> str:
    return _stable_hash(
        [
            {
                "review_token": row["review_token"],
                "role": row["evidence_role"],
                "pattern": row["pattern"],
            }
            for row in rows
        ]
    )


def _render_report(result: dict[str, Any]) -> str:
    roles = result.get("evidence_roles") or {}
    review = result.get("review_packs") or {}
    quarantine = result.get("quarantine") or {}
    lines = [
        "# v5.21 Native PAN-OS Evidence Program",
        "",
        f"Generated: {result.get('generated_at')}",
        "",
        "## Outcome",
        "",
        f"- Status: `{result.get('status')}`",
        f"- Rows streamed: `{(result.get('source_evidence') or {}).get('rows_processed')}`",
        f"- Parser failures: `{(result.get('source_evidence') or {}).get('parser_failures')}`",
        f"- Duplicate families contained: `{result.get('duplicate_families_contained')}`",
        f"- Rows quarantined from chronological evidence: `{quarantine.get('rows', 0)}`",
        f"- Development assisted rows: `{review.get('development_rows')}`",
        f"- Blind human-verification rows: `{review.get('blind_rows')}`",
        "- Human-reviewed rows created automatically: `0`",
        "- Configured database accessed or changed: `false`",
        "- Model activated or promoted: `false`",
        "- Response action created: `false`",
        "",
        "## Chronological Roles",
        "",
        "| Role | Rows | Representative families | Time windows |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, value in roles.items():
        lines.append(
            f"| {name} | {value.get('rows', 0)} | "
            f"{value.get('representative_families', 0)} | "
            f"{value.get('time_windows', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Label Integrity",
            "",
            "Development suggestions are weak/assisted and require human confirmation. "
            "The blind pack contains no rule, model, or AI suggestion. Neither pack is "
            "import-ready. The manifest and packs are ignored local evidence and must not "
            "be committed.",
            "",
            "## Remaining Gate",
            "",
            "A qualified human or advisor must independently confirm enough native rows. "
            "v5.22 must freeze its candidate before reading any blind-pack decisions. A "
            "second real device is still required for source generalization claims.",
            "",
        ]
    )
    return "\n".join(lines)


def _failure(status: str, *, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "version": V521_VERSION,
        "status": status,
        "message": message,
        "path_returned": False,
        "raw_evidence_returned": False,
        "ip_addresses_returned": False,
        "fingerprints_returned": False,
        "configured_database_accessed": False,
        "configured_database_written": False,
        "model_artifact_written": False,
        "model_activated": False,
        "response_actions_created": 0,
    }


def run_v521_native_panos_evidence(
    *,
    sample_path: Path,
    use_temp_db: bool,
    preflight_only: bool = False,
    review_limit: int = 160,
    chunk_size: int = 2000,
    output_dir: Path = V521_OUTPUT_DIR,
    write_output: bool = True,
) -> dict[str, Any]:
    if not use_temp_db:
        return _failure(
            "failed_closed_temp_db_acknowledgement_required",
            message="Re-run with --use-temp-db.",
        )
    if not sample_path.exists() or not sample_path.is_file():
        return _failure(
            "private_evidence_unavailable",
            message="The supplied private evidence file is unavailable.",
        )

    source_fingerprint = _file_sha256(sample_path)
    development_rows: list[dict[str, Any]] = []
    blind_rows: list[dict[str, Any]] = []
    review_summary = {
        "requested_rows": int(review_limit),
        "development_rows": 0,
        "blind_rows": 0,
        "development_suggestions_are_weak": True,
        "blind_suggestions_generated": False,
        "human_reviewed_rows_created": 0,
        "import_ready_rows_created": 0,
        "raw_logs_included": False,
        "ip_addresses_included": False,
    }
    streamed: dict[str, Any]
    role_result: dict[str, Any]
    aggregate_result: dict[str, Any]
    role_locks: dict[str, Any]
    quarantine_summary: dict[str, Any]

    try:
        with tempfile.TemporaryDirectory(prefix="atdr-v521-") as temp_root:
            index_path = Path(temp_root) / "native-evidence.sqlite3"
            connection = sqlite3.connect(index_path)
            try:
                streamed = v56.stream_private_file_to_disposable_index(
                    sample_path,
                    connection,
                    database_url="sqlite:///:memory:",
                    chunk_size=chunk_size,
                )
                if not streamed.get("ok"):
                    return _failure(
                        "private_evidence_stream_failed",
                        message="Private evidence could not be parsed into the disposable index.",
                    )
                role_result = v56.predeclare_chronological_roles(connection)
                if not role_result.get("ok"):
                    result = _failure(
                        str(role_result.get("status") or "role_partition_failed"),
                        message=(
                            "Evidence has insufficient chronological windows or failed "
                            "duplicate-family containment."
                        ),
                    )
                    result["distinct_time_windows"] = int(
                        role_result.get("distinct_time_windows") or 0
                    )
                    return result
                aggregate_result = v56.build_disposable_behavior_aggregates(
                    connection
                )
                role_locks = _role_locks(connection)
                quarantine_summary = _quarantine_summary(connection)
                if not preflight_only:
                    development_rows, blind_rows, review_summary = build_review_packs(
                        connection,
                        review_limit=review_limit,
                    )
            finally:
                connection.close()
    except (OSError, sqlite3.Error, ValueError) as exc:
        result = _failure(
            "native_evidence_program_failed",
            message="The disposable native-evidence program failed closed.",
        )
        result["error_type"] = exc.__class__.__name__
        return result

    private_manifest = {
        "version": V521_MANIFEST_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_file_sha256": source_fingerprint,
        "source_path_recorded": False,
        "source_file_name_recorded": False,
        "role_policy": role_result.get("policy") or {},
        "roles": role_result.get("roles") or {},
        "role_locks": role_locks,
        "quarantine": quarantine_summary,
        "exact_family_cross_role_count": int(
            role_result.get("exact_family_cross_role_count") or 0
        ),
        "near_family_cross_role_count": int(
            role_result.get("near_family_cross_role_count") or 0
        ),
        "development_pack_fingerprint": _pack_fingerprint(development_rows),
        "blind_pack_fingerprint": _pack_fingerprint(blind_rows),
        "blind_suggestions_generated": False,
        "blind_decisions_opened": False,
        "human_reviewed_rows_created": 0,
        "raw_logs_included": False,
        "ip_addresses_included": False,
        "configured_database_accessed": False,
        "model_artifact_written": False,
    }
    private_manifest["manifest_fingerprint"] = _stable_hash(private_manifest)

    result = {
        "ok": True,
        "version": V521_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "native_panos_preflight_complete"
            if preflight_only
            else "native_panos_evidence_roles_locked"
        ),
        "preflight_only": bool(preflight_only),
        "source_evidence": _safe_stream_projection(streamed),
        "evidence_roles": _safe_role_projection(
            role_result.get("roles") or {}
        ),
        "distinct_time_windows": int(
            role_result.get("distinct_time_windows") or 0
        ),
        "duplicate_families_contained": bool(
            role_result.get("duplicate_families_contained")
        ),
        "exact_family_cross_role_count": int(
            role_result.get("exact_family_cross_role_count") or 0
        ),
        "near_family_cross_role_count": int(
            role_result.get("near_family_cross_role_count") or 0
        ),
        "behavior_aggregates": {
            "source_time_windows": int(
                aggregate_result.get("source_time_windows") or 0
            ),
            "representative_groups": int(
                aggregate_result.get("representative_groups") or 0
            ),
            "raw_evidence_included": False,
            "private_identifiers_returned": False,
        },
        "quarantine": quarantine_summary,
        "review_packs": review_summary,
        "official_field_contract": official_panos_field_contract(),
        "manifest": {
            "created": bool(write_output),
            "manifest_file_name": V521_MANIFEST_LATEST if write_output else None,
            "result_file_name": V521_RESULT_LATEST if write_output else None,
            "development_pack_file_name": (
                V521_DEVELOPMENT_PACK
                if write_output and development_rows
                else None
            ),
            "blind_pack_file_name": (
                V521_BLIND_PACK if write_output and blind_rows else None
            ),
            "fingerprints_recorded_privately": True,
            "fingerprints_returned": False,
            "paths_returned": False,
        },
        "evidence_sufficiency": {
            "native_schema_available": True,
            "chronological_roles_available": True,
            "duplicate_containment_passed": bool(
                role_result.get("duplicate_families_contained")
            ),
            "independent_human_labels_available": False,
            "second_real_device_available": False,
            "enough_for_diagnostic_shadow_rebuild": bool(
                not preflight_only and development_rows
            ),
            "enough_for_activation_or_production_claim": False,
        },
        "safety": {
            "configured_database_accessed": False,
            "configured_database_written": False,
            "labels_written": 0,
            "human_reviewed_labels_created": 0,
            "model_artifact_written": False,
            "model_activated": False,
            "model_promoted": False,
            "alerts_created": 0,
            "detection_runs_created": 0,
            "response_actions_created": 0,
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "raw_logs_returned": False,
            "ip_addresses_returned": False,
            "private_paths_returned": False,
            "fingerprints_returned": False,
            "secrets_exposed": False,
            "disposable_index_removed": True,
        },
        "lifecycle_state": "shadow_observation",
        "next_gate": (
            "Human/advisor confirmation of native development evidence and a "
            "sealed blind pack are required before v5.22 can make any stronger claim."
        ),
    }

    if write_output:
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / V521_MANIFEST_LATEST
        result_path = output_dir / V521_RESULT_LATEST
        report_path = output_dir / f"v5_21_native_panos_evidence_{_stamp()}.md"
        manifest_path.write_text(
            json.dumps(private_manifest, indent=2, default=str),
            encoding="utf-8",
        )
        if development_rows:
            _write_csv(output_dir / V521_DEVELOPMENT_PACK, development_rows)
        if blind_rows:
            _write_csv(output_dir / V521_BLIND_PACK, blind_rows)
        result_path.write_text(
            json.dumps(result, indent=2, default=str),
            encoding="utf-8",
        )
        report_path.write_text(_render_report(result), encoding="utf-8")

    return result
