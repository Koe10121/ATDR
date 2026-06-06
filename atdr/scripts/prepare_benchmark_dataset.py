import argparse
import json
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.adapter import (
    load_benchmark_config,
    load_benchmark_csv,
    select_benchmark_records,
    write_benchmark_snapshot,
)
from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.detection_reliability_common import json_default


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"


def render_markdown(snapshot: dict[str, Any]) -> str:
    profile = snapshot.get("profile") or {}
    lines = [
        "# ATDR Prepared Benchmark Snapshot",
        "",
        f"- Snapshot ID: {snapshot.get('snapshot_id')}",
        f"- Input name: {snapshot.get('input_name')}",
        f"- Requested limit: {snapshot.get('requested_limit')}",
        f"- Sample strategy: {snapshot.get('sample_strategy')}",
        f"- Rows in snapshot: {profile.get('total_rows', 0)}",
        f"- Private raw payloads excluded: {snapshot.get('private_raw_payloads_excluded')}",
        "- Production readiness claim: none",
        "",
        "## Label Distribution",
        "",
    ]
    for label, count in (profile.get("label_distribution") or {}).items():
        lines.append(f"- {label}: {count}")
    lines.extend(["", "## Attack Type Distribution", ""])
    for attack_type, count in (profile.get("attack_type_distribution") or {}).items():
        lines.append(f"- {attack_type}: {count}")
    lines.extend(["", "## Missing Field Rates", ""])
    for field, item in (profile.get("missing_field_rates") or {}).items():
        lines.append(f"- {field}: {item.get('missing')} missing ({item.get('rate')})")
    imbalance = profile.get("class_imbalance") or {}
    lines.extend(
        [
            "",
            "## Class Imbalance",
            "",
            f"- Ratio: {imbalance.get('imbalance_ratio')}",
            f"- Warning: {imbalance.get('warning') or 'none'}",
            "",
            "## Safety",
            "",
            "- This prepared snapshot is generated output and must stay out of Git.",
            "- Benchmark metrics remain separate from local firewall-log metrics.",
            "- ML and detection remain SOC decision support only.",
        ]
    )
    return "\n".join(lines)


def prepare_benchmark_dataset(
    *,
    input_csv: Path,
    mapping_config: Path | None = None,
    label_config: Path | None = None,
    limit: int | None = None,
    sample_strategy: str = "balanced",
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    if sample_strategy not in {"balanced", "random", "time"}:
        raise ValueError("sample_strategy must be balanced, random, or time")
    config = load_benchmark_config(mapping_config, label_config)
    all_records, mapping_summary = load_benchmark_csv(input_csv, mapping_config=config, limit=None)
    mapping_summary["required_fields"] = config.get("required_fields") or [
        "timestamp",
        "src_ip",
        "dst_ip",
        "action",
        "app",
        "label",
        "attack_type",
    ]
    records = select_benchmark_records(all_records, limit=limit, sample_strategy=sample_strategy)
    snapshot = write_benchmark_snapshot(
        records,
        input_name=input_csv.name,
        mapping_summary=mapping_summary,
        output_dir=output_dir,
        sample_strategy=sample_strategy,
        requested_limit=limit,
        include_raw=False,
    )
    markdown_path = Path(snapshot["snapshot_path"]).with_suffix(".md")
    markdown_path.write_text(render_markdown(snapshot), encoding="utf-8")
    snapshot["summary_path"] = str(markdown_path)
    snapshot["source_total_rows"] = len(all_records)
    snapshot["rows_selected"] = len(records)
    snapshot["ok"] = True
    return snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a sanitized ATDR benchmark snapshot from a mapped CSV.")
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--mapping-config", default=None)
    parser.add_argument("--label-config", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--sample-strategy", choices=["balanced", "random", "time"], default="balanced")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = prepare_benchmark_dataset(
        input_csv=Path(args.input_csv),
        mapping_config=Path(args.mapping_config) if args.mapping_config else None,
        label_config=Path(args.label_config) if args.label_config else None,
        limit=args.limit,
        sample_strategy=args.sample_strategy,
        output_dir=Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT_DIR,
    )
    print(json.dumps(result, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
