from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5


_SECRET_PATTERNS = (
    ("private_key_material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)

_SENSITIVE_SUFFIXES = {
    ".db",
    ".joblib",
    ".log",
    ".onnx",
    ".pickle",
    ".pkl",
    ".pt",
    ".sqlite",
    ".sqlite3",
}

_ALLOWED_ENV_EXAMPLES = {
    ".env.example",
    ".env.lab.example",
    ".env.preproduction.example",
    ".env.production.example",
    ".env.shell.example",
    "atdr.env.example",
}


def tracked_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return sorted(
        value.decode("utf-8", errors="strict")
        for value in result.stdout.split(b"\0")
        if value
    )


def _sensitive_path_rule(relative_path: str) -> str | None:
    normalized = relative_path.replace("\\", "/")
    path = Path(normalized)
    lower_parts = {part.lower() for part in path.parts}
    if path.name.startswith(".env") and path.name not in _ALLOWED_ENV_EXAMPLES:
        return "private_environment_file"
    if path.name == "atdr.env" or (path.name.endswith(".env.local") and path.name not in _ALLOWED_ENV_EXAMPLES):
        return "private_environment_file"
    if path.suffix.lower() in _SENSITIVE_SUFFIXES:
        return "private_runtime_artifact"
    if {"ml_baseline_reviews", "demo_exports"} & lower_parts:
        return "private_generated_evidence"
    return None


def scan_repository_paths(root: Path, relative_paths: Iterable[str]) -> dict[str, Any]:
    paths = sorted(set(relative_paths))
    findings: list[dict[str, str]] = []
    scanned_files = 0
    skipped_binary_or_large = 0
    for relative_path in paths:
        path_rule = _sensitive_path_rule(relative_path)
        if path_rule:
            findings.append({"path": relative_path, "rule": path_rule})
            continue
        path = root / relative_path
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 2_000_000:
                skipped_binary_or_large += 1
                continue
            data = path.read_bytes()
            if b"\0" in data:
                skipped_binary_or_large += 1
                continue
            text = data.decode("utf-8")
        except (OSError, UnicodeError):
            skipped_binary_or_large += 1
            continue
        scanned_files += 1
        for rule, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                findings.append({"path": relative_path, "rule": rule})
    unique_findings = [
        {"path": path, "rule": rule}
        for path, rule in sorted({(item["path"], item["rule"]) for item in findings})
    ]
    return {
        "ok": not unique_findings,
        "tracked_path_count": len(paths),
        "scanned_text_file_count": scanned_files,
        "skipped_binary_or_large_count": skipped_binary_or_large,
        "finding_count": len(unique_findings),
        "findings": unique_findings,
        "matched_values_exposed": False,
        "secrets_exposed": False,
    }


def scan_tracked_repository(root: Path) -> dict[str, Any]:
    return scan_repository_paths(root, tracked_paths(root))


def _python_components(root: Path) -> list[dict[str, str]]:
    path = root / "requirements.lock.txt"
    components: list[dict[str, str]] = []
    if not path.is_file():
        return components
    for line in path.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or "==" not in clean:
            continue
        name, version = clean.split("==", 1)
        name = name.strip()
        version = version.split(";", 1)[0].split("\\", 1)[0].strip()
        if name and version:
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{quote(name.lower(), safe='-._')}@{quote(version, safe='-._+')}",
                }
            )
    return components


def _frontend_components(root: Path) -> list[dict[str, str]]:
    path = root / "frontend/package-lock.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages") if isinstance(payload, dict) else None
    if not isinstance(packages, dict):
        return []
    components: list[dict[str, str]] = []
    for package_path, item in packages.items():
        if not package_path or not isinstance(item, dict):
            continue
        name = str(item.get("name") or package_path.rsplit("node_modules/", 1)[-1]).strip()
        version = str(item.get("version") or "").strip()
        if not name or not version:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{quote(name, safe='@/-._')}@{quote(version, safe='-._+')}",
            }
        )
    return components


def build_cyclonedx_sbom(root: Path) -> dict[str, Any]:
    components = _python_components(root) + _frontend_components(root)
    deduplicated = {
        (item["purl"], item["name"], item["version"]): item
        for item in components
    }
    ordered = [deduplicated[key] for key in sorted(deduplicated)]
    identity = "\n".join(item["purl"] for item in ordered)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, identity)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "MFU ATDR",
            }
        },
        "components": ordered,
    }


def build_security_acceptance_report(root: Path) -> dict[str, Any]:
    scan = scan_tracked_repository(root)
    codeql = root / ".github/workflows/codeql.yml"
    ci = root / ".github/workflows/ci.yml"
    ci_text = ci.read_text(encoding="utf-8") if ci.is_file() else ""
    controls = {
        "tracked_secret_scan": scan["ok"],
        "python_dependency_audit": "pip_audit" in ci_text or "pip-audit" in ci_text,
        "frontend_dependency_audit": "npm audit" in ci_text,
        "sbom_generation": "sbom" in ci_text.lower() or "cyclonedx" in ci_text.lower(),
        "codeql_python_typescript": codeql.is_file()
        and "python" in codeql.read_text(encoding="utf-8")
        and "javascript-typescript" in codeql.read_text(encoding="utf-8"),
    }
    failed = [name for name, passed in controls.items() if not passed]
    return {
        "ok": not failed,
        "status": "security_controls_ready" if not failed else "security_controls_incomplete",
        "controls": controls,
        "failed_controls": failed,
        "repository_scan": scan,
        "external_network_calls_made": False,
        "filesystem_writes_performed": False,
        "matched_values_exposed": False,
        "secrets_exposed": False,
    }
