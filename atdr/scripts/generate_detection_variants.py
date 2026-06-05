import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.services.log_service import count_nonblank_log_lines
from atdr.scripts.run_detection_validation_suite import _json_default, _load_expectations
from atdr.scripts.run_source_scenario import SCENARIOS


SCENARIO_DIR = PROJECT_ROOT / "data" / "samples" / "scenarios"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "detection_variants"
AUTH_PORTS = [22, 995, 3389, 445, 1433]
COMMON_WEB_PORTS = [443, 80, 53, 443]
VARIANT_NOTE = (
    "Synthetic defensive log variant generated for ATDR validation. "
    "No payloads, exploit steps, or offensive instructions are included."
)


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _shift_palo_time(match: re.Match[str], minutes: int) -> str:
    value = match.group(0)
    shifted = datetime.strptime(value, "%Y/%m/%d %H:%M:%S") + timedelta(minutes=minutes)
    return shifted.strftime("%Y/%m/%d %H:%M:%S")


def _shift_iso_time(match: re.Match[str], minutes: int) -> str:
    value = match.group(0)
    has_millis = "." in value
    clean = value.replace("+07:00", "")
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if has_millis else "%Y-%m-%dT%H:%M:%S"
    shifted = datetime.strptime(clean, fmt) + timedelta(minutes=minutes)
    if has_millis:
        return shifted.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "+07:00"
    return shifted.strftime("%Y-%m-%dT%H:%M:%S") + "+07:00"


def _shift_timestamps(line: str, *, scenario: str, variant_index: int, line_index: int) -> str:
    minutes = variant_index * 37
    if scenario != "repeated_dedup_traffic":
        minutes += line_index
    line = re.sub(r"2026/05/20 \d{2}:\d{2}:\d{2}", lambda match: _shift_palo_time(match, minutes), line)
    return re.sub(
        r"2026-05-20T\d{2}:\d{2}:\d{2}(?:\.\d{3})?\+07:00",
        lambda match: _shift_iso_time(match, minutes),
        line,
    )


def _map_ip(ip: str, *, variant_index: int, ordinal: int) -> str:
    if ip == "0.0.0.0":
        return ip
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    last = _safe_int(parts[3], 10)
    if ip.startswith("10."):
        second = 40 + ((variant_index + ordinal) % 40)
        third = 10 + ((_safe_int(parts[2], 20) + variant_index * 3 + ordinal) % 80)
        fourth = 10 + ((last + variant_index * 11 + ordinal) % 220)
        return f"10.{second}.{third}.{fourth}"
    if ip.startswith("203.0.113."):
        return f"203.0.113.{1 + ((last + variant_index * 17 + ordinal) % 249)}"
    if ip.startswith("198.51.100."):
        return f"198.51.100.{1 + ((last + variant_index * 13 + ordinal) % 249)}"
    if ip.startswith("192.0.2."):
        return f"192.0.2.{1 + ((last + variant_index * 19 + ordinal) % 249)}"
    return ip


def _replace_ips(text: str, *, variant_index: int) -> str:
    mapping: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        ip = match.group(0)
        if ip not in mapping:
            mapping[ip] = _map_ip(ip, variant_index=variant_index, ordinal=len(mapping) + 1)
        return mapping[ip]

    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", replace, text)


def _split_palo_line(line: str) -> tuple[str, list[str]] | None:
    marker = " 1,"
    index = line.find(marker)
    if index < 0:
        return None
    prefix = line[: index + 1]
    return prefix, line[index + 1 :].split(",")


def _scenario_dst_port(scenario: str, *, variant_index: int, line_index: int, current_port: int) -> int:
    if scenario in {"port_scan_like_traffic", "mixed_small_subnet_validation"} and current_port >= 20000:
        return 20000 + variant_index * 100 + line_index
    if scenario in {"brute_force_like_traffic", "repeated_dedup_traffic"}:
        return AUTH_PORTS[(variant_index - 1) % len(AUTH_PORTS)]
    if scenario == "malware_c2_like_beaconing":
        return 4400 + variant_index * 13
    if scenario == "policy_violation_suspicious_app":
        return 6800 + variant_index
    if scenario in {"normal_web_dns_quic_traffic", "normal_repeated_same_service_traffic"}:
        return COMMON_WEB_PORTS[(line_index + variant_index) % len(COMMON_WEB_PORTS)]
    return current_port


def _vary_numeric_fields(fields: list[str], *, scenario: str, variant_index: int, line_index: int) -> None:
    if len(fields) <= 34:
        return
    if fields[22].isdigit():
        fields[22] = str(_safe_int(fields[22]) + variant_index * 10000 + line_index)
    if fields[24].isdigit():
        fields[24] = str(40000 + variant_index * 100 + line_index)
    if fields[25].isdigit():
        current_port = _safe_int(fields[25])
        fields[25] = str(_scenario_dst_port(scenario, variant_index=variant_index, line_index=line_index, current_port=current_port))

    if scenario == "data_exfiltration_suspicion":
        bytes_total = 70_000_000 + variant_index * 1_000_000 + line_index * 500_000
        fields[31] = str(bytes_total)
        fields[32] = str(bytes_total - 2_000_000)
        fields[33] = "2000000"
        fields[34] = str(35_000 + variant_index * 100 + line_index)
    elif scenario == "normal_high_volume_but_allowed_traffic":
        bytes_total = 2_000_000 + variant_index * 150_000 + line_index * 20_000
        fields[31] = str(bytes_total)
        fields[32] = str(max(0, bytes_total - 900_000))
        fields[33] = "900000"
        fields[34] = str(500 + variant_index * 10 + line_index)


def _transform_palo_line(line: str, *, scenario: str, variant_index: int, line_index: int) -> str:
    split = _split_palo_line(line)
    shifted = _replace_ips(
        _shift_timestamps(line, scenario=scenario, variant_index=variant_index, line_index=line_index),
        variant_index=variant_index,
    )
    if split is None:
        return shifted.rstrip() + ("   " if variant_index % 2 == 0 else "")

    shifted_split = _split_palo_line(shifted)
    if shifted_split is None:
        return shifted
    prefix, fields = shifted_split
    if len(fields) > 52:
        _vary_numeric_fields(fields, scenario=scenario, variant_index=variant_index, line_index=line_index)
    return prefix + ",".join(fields)


def _normal_noise_lines(*, variant_index: int) -> list[str]:
    path = SCENARIO_DIR / "normal_web_dns_quic_traffic.txt"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [
        _transform_palo_line(line, scenario="normal_web_dns_quic_traffic", variant_index=variant_index, line_index=index + 1)
        for index, line in enumerate(lines[: min(variant_index, 3)])
    ]


def generate_variant_lines(scenario: str, *, variant_index: int) -> list[str]:
    spec = SCENARIOS[scenario]
    source_path = SCENARIO_DIR / spec.filename
    base_lines = [line for line in source_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    transformed = [
        _transform_palo_line(line, scenario=scenario, variant_index=variant_index, line_index=index + 1)
        for index, line in enumerate(base_lines)
    ]
    if scenario not in {
        "normal_allowed_traffic",
        "normal_web_dns_quic_traffic",
        "normal_high_volume_but_allowed_traffic",
        "normal_repeated_same_service_traffic",
        "generic_syslog_mixed",
        "malformed_raw_fallback",
    }:
        transformed.extend(_normal_noise_lines(variant_index=variant_index))
    if scenario == "mixed_small_subnet_validation" and variant_index % 2 == 1:
        transformed.append(f"variant-{variant_index} raw-format odd line preserved for parser fallback validation")
    return transformed


def generate_detection_variants(
    *,
    scenarios: list[str] | None = None,
    variants: int = 5,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    clean: bool = False,
) -> dict[str, Any]:
    expectations = _load_expectations()
    selected = scenarios or list(expectations.keys())
    unknown = sorted(set(selected) - set(SCENARIOS))
    if unknown:
        raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}")
    if variants < 1:
        raise ValueError("variants must be at least 1")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_dir / f"variants_{timestamp}"
    if clean and run_dir.exists():
        for child in run_dir.rglob("*"):
            if child.is_file():
                child.unlink()
    run_dir.mkdir(parents=True, exist_ok=True)

    items: list[dict[str, Any]] = []
    for scenario in selected:
        scenario_dir = run_dir / scenario
        scenario_dir.mkdir(parents=True, exist_ok=True)
        spec = SCENARIOS[scenario]
        for variant_index in range(1, variants + 1):
            lines = generate_variant_lines(scenario, variant_index=variant_index)
            path = scenario_dir / f"{scenario}_variant_{variant_index}.txt"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            items.append(
                {
                    "scenario": scenario,
                    "variant_id": variant_index,
                    "path": str(path),
                    "filename": path.name,
                    "line_count": count_nonblank_log_lines(path),
                    "source_type": spec.default_source_type,
                    "parser_profile": spec.default_parser_profile,
                    "variation_types": [
                        "source_ip_shift",
                        "destination_ip_shift",
                        "timestamp_shift",
                        "safe_port_variation",
                        "intensity_variation",
                        "benign_noise" if scenario not in {"normal_allowed_traffic", "generic_syslog_mixed", "malformed_raw_fallback"} else "no_extra_noise",
                    ],
                }
            )

    manifest = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "output_dir": str(run_dir),
        "scenario_count": len(selected),
        "variant_count": len(items),
        "variants_per_scenario": variants,
        "safety": {
            "synthetic_defensive_logs_only": True,
            "offensive_payloads_generated": False,
            "writes_current_database": False,
            "note": VARIANT_NOTE,
        },
        "variants": items,
    }
    manifest_path = run_dir / "variant_manifest.json"
    manifest["manifest_path"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, default=_json_default, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate safe synthetic ATDR detection scenario variants.")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), help="Scenario to vary. Repeat for multiple.")
    parser.add_argument("--all", action="store_true", help="Generate variants for every known scenario.")
    parser.add_argument("--variants", type=int, default=5)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    selected = None if args.all or not args.scenario else args.scenario
    result = generate_detection_variants(
        scenarios=selected,
        variants=args.variants,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
        clean=args.clean,
    )
    print(json.dumps(result, default=_json_default, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
