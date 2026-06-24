import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.scripts.run_source_scenario import SCENARIOS


DEFAULT_SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
DEFAULT_SAMPLE = PROJECT_ROOT / "data" / "samples" / "paloalto-demo.txt"
PRIVATE_TOKENS = ("users\\", "/users/", "downloads", "desktop")


def _safe_path_label(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(PROJECT_ROOT.resolve())
        return str(relative).replace("\\", "/")
    except ValueError:
        return path.name


def _redact_example(raw_line: str) -> str:
    text = raw_line.strip().replace("\r", " ").replace("\n", " ")
    # Preserve enough structure for parser debugging while avoiding long raw evidence dumps.
    if len(text) > 180:
        text = f"{text[:177]}..."
    lower = text.lower()
    if any(token in lower for token in PRIVATE_TOKENS):
        return "[redacted private path/log evidence]"
    return text


def _profile_for_path(path: Path) -> str:
    for scenario, spec in SCENARIOS.items():
        if path.name == spec.filename:
            return spec.default_parser_profile
    return "palo_alto"


def _sample_paths(selected: list[str] | None = None) -> list[Path]:
    if selected:
        paths: list[Path] = []
        for item in selected:
            if item in SCENARIOS:
                paths.append(DEFAULT_SCENARIO_DIR / SCENARIOS[item].filename)
            else:
                paths.append(Path(item))
        return paths
    paths = [DEFAULT_SAMPLE] if DEFAULT_SAMPLE.exists() else []
    paths.extend(sorted(DEFAULT_SCENARIO_DIR.glob("*.txt")))
    return paths


def _iter_nonblank_lines(path: Path) -> list[str]:
    return [line.rstrip("\r\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def validate_parser_normalization(samples: list[str] | None = None, *, limit_per_file: int | None = None) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    app_counter: Counter[str] = Counter()
    action_counter: Counter[str] = Counter()
    port_counter: Counter[str] = Counter()
    profile_counter: Counter[str] = Counter()
    malformed_examples: list[dict[str, str]] = []
    totals = Counter()

    for path in _sample_paths(samples):
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        profile = _profile_for_path(path)
        profile_counter[profile] += 1
        lines = _iter_nonblank_lines(path)
        if limit_per_file is not None:
            lines = lines[:limit_per_file]
        file_counts: Counter[str] = Counter()
        file_warnings: Counter[str] = Counter()
        for line in lines:
            totals["total_sample_lines_checked"] += 1
            file_counts["lines_checked"] += 1
            parsed = parse_log_line_for_profile(line, profile)
            parsed_json = parsed.parsed_json if isinstance(parsed.parsed_json, dict) else {}
            normalized = parsed.normalized or {}
            warnings = [str(item) for item in parsed_json.get("parser_warnings", []) if item]
            parser_error = parsed.error or parsed_json.get("parser_error")

            if parser_error:
                totals["parse_failures"] += 1
                file_counts["parse_failures"] += 1
                if len(malformed_examples) < 5:
                    malformed_examples.append(
                        {
                            "file": _safe_path_label(path),
                            "parser_profile": profile,
                            "error": str(parser_error),
                            "raw_excerpt": _redact_example(line),
                        }
                    )
            else:
                totals["parsed_successfully"] += 1
                file_counts["parsed_successfully"] += 1

            if parsed_json.get("raw_fallback") or profile == "raw_fallback":
                totals["raw_fallback_count"] += 1
                file_counts["raw_fallback_count"] += 1
            if parsed.syslog_timestamp is None and normalized.get("generated_time") is None and normalized.get("receive_time") is None:
                totals["missing_timestamp_count"] += 1
                file_counts["missing_timestamp_count"] += 1
            if not normalized.get("src_ip"):
                totals["missing_src_ip_count"] += 1
                file_counts["missing_src_ip_count"] += 1
            if not normalized.get("dst_ip"):
                totals["missing_dst_ip_count"] += 1
                file_counts["missing_dst_ip_count"] += 1
            if not normalized.get("action"):
                totals["missing_action_count"] += 1
                file_counts["missing_action_count"] += 1
            app = str(normalized.get("app") or "").strip().lower()
            if app in {"", "unknown", "incomplete", "not-applicable", "unknown-tcp"}:
                totals["unknown_app_count"] += 1
                file_counts["unknown_app_count"] += 1
            if app:
                app_counter[app] += 1
            action = str(normalized.get("action") or "").strip().lower()
            if action:
                action_counter[action] += 1
            dst_port = normalized.get("dst_port")
            if dst_port is not None:
                port_counter[str(dst_port)] += 1
            for warning in warnings:
                file_warnings[warning] += 1

        files.append(
            {
                "path": _safe_path_label(path),
                "parser_profile": profile,
                "available_lines_checked": file_counts["lines_checked"],
                "parsed_successfully": file_counts["parsed_successfully"],
                "parse_failures": file_counts["parse_failures"],
                "raw_fallback_count": file_counts["raw_fallback_count"],
                "unknown_app_count": file_counts["unknown_app_count"],
                "missing_timestamp_count": file_counts["missing_timestamp_count"],
                "missing_src_ip_count": file_counts["missing_src_ip_count"],
                "missing_dst_ip_count": file_counts["missing_dst_ip_count"],
                "missing_action_count": file_counts["missing_action_count"],
                "top_parser_warnings": file_warnings.most_common(5),
            }
        )

    report = {
        "ok": True,
        "read_only": True,
        "database_mutated": False,
        "validation_scope": "safe sample/scenario parser and normalization validation",
        "files_checked": len(files),
        "parser_profiles_used": dict(profile_counter),
        "total_sample_lines_checked": totals["total_sample_lines_checked"],
        "parsed_successfully": totals["parsed_successfully"],
        "parse_failures": totals["parse_failures"],
        "raw_fallback_count": totals["raw_fallback_count"],
        "missing_timestamp_count": totals["missing_timestamp_count"],
        "missing_src_ip_count": totals["missing_src_ip_count"],
        "missing_dst_ip_count": totals["missing_dst_ip_count"],
        "missing_action_count": totals["missing_action_count"],
        "unknown_app_count": totals["unknown_app_count"],
        "top_normalized_apps": app_counter.most_common(10),
        "top_normalized_actions": action_counter.most_common(10),
        "top_destination_ports": port_counter.most_common(10),
        "malformed_examples": malformed_examples,
        "files": files,
        "safety": {
            "uses_safe_samples_by_default": True,
            "private_paths_redacted": True,
            "raw_log_context_limited": True,
            "response_actions_created": 0,
        },
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate parser and normalization quality on safe ATDR samples.")
    parser.add_argument("--sample", action="append", help="Scenario name or file path. Defaults to safe bundled samples.")
    parser.add_argument("--limit-per-file", type=int, default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = validate_parser_normalization(args.sample, limit_per_file=args.limit_per_file)
    print(json.dumps(report, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
