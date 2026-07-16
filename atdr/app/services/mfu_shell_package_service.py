from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


PACKAGE_MANIFEST_NAME = "mfu-shell-release.json"
PACKAGE_FORMAT_VERSION = 1
BUILD_CONFIRMATION = "BUILD_SANITIZED_MFU_SHELL"
INSTALL_CONFIRMATION = "INSTALL_VERIFIED_MFU_SHELL"


class ShellPackageError(ValueError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_shell_contract(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ShellPackageError("MFU shell contract is missing or invalid JSON.") from exc
    package = payload.get("package_release")
    if not isinstance(package, dict):
        raise ShellPackageError("MFU shell contract does not define package_release.")
    if package.get("format_version") != PACKAGE_FORMAT_VERSION:
        raise ShellPackageError("MFU shell package format version is unsupported.")
    return payload


def _package_policy(contract: dict[str, Any]) -> dict[str, Any]:
    package = contract["package_release"]
    policy = package.get("sanitization_policy")
    if not isinstance(policy, dict):
        raise ShellPackageError("MFU shell contract does not define a sanitization policy.")
    return policy


def _normalise_relative(path: Path) -> str:
    return path.as_posix().lstrip("./")


def _path_is_excluded(relative: str, policy: dict[str, Any]) -> bool:
    pure = PurePosixPath(relative)
    parts = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    excluded_directories = {str(item).lower() for item in policy.get("excluded_directory_names", [])}
    if any(part in excluded_directories for part in parts[:-1]):
        return True
    prefixes = tuple(str(item).strip("/").lower() for item in policy.get("excluded_relative_prefixes", []))
    lowered = relative.lower()
    if any(lowered == prefix or lowered.startswith(f"{prefix}/") for prefix in prefixes):
        return True
    if any(name.startswith(str(item).lower()) for item in policy.get("excluded_name_prefixes", [])):
        return True
    if any(name.endswith(str(item).lower()) for item in policy.get("excluded_name_suffixes", [])):
        return True
    if any(str(item).lower() in name for item in policy.get("excluded_name_contains", [])):
        return True
    return False


_PRIVATE_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\users\\[^\\\s]+|/users/[^/\s]+/)")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_GOOGLE_CLIENT_RE = re.compile(r"(?i)[0-9]{6,}-[a-z0-9_-]{20,}\.apps\.googleusercontent\.com")
_ASSIGNED_SECRET_RE = re.compile(
    r"(?i)(?:client[_-]?secret|admin[_-]?secret|api[_-]?key|access[_-]?token)"
    r"\s*[:=]\s*['\"]([a-z0-9_+./=-]{16,})['\"]"
)
_TOKEN_RE = re.compile(r"(?i)(?:gh[pousr]_[a-z0-9]{20,}|sk-[a-z0-9_-]{20,})")


def _scan_text_safety(relative: str, content: bytes) -> list[str]:
    if b"\x00" in content or len(content) > 2_000_000:
        return []
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return []
    findings: list[str] = []
    if _PRIVATE_PATH_RE.search(text):
        findings.append("personal_machine_path")
    if _PRIVATE_KEY_RE.search(text):
        findings.append("private_key")
    if _GOOGLE_CLIENT_RE.search(text):
        findings.append("hardcoded_google_client")
    if _ASSIGNED_SECRET_RE.search(text) or _TOKEN_RE.search(text):
        findings.append("hardcoded_secret")
    return findings


def _source_files(source_root: Path, contract: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise ShellPackageError("The MFU shell source directory does not exist.")
    policy = _package_policy(contract)
    allowed_roots = [str(item).strip("/") for item in policy.get("included_roots", [])]
    if not allowed_roots:
        raise ShellPackageError("The shell package policy has no included roots.")

    entries: list[dict[str, Any]] = []
    content_by_path: dict[str, bytes] = {}
    unsafe: list[dict[str, Any]] = []
    for root_name in allowed_roots:
        root_path = source_root / Path(root_name)
        if not root_path.is_dir():
            raise ShellPackageError(f"Required shell source root is missing: {root_name}")
        for path in sorted(root_path.rglob("*"), key=lambda item: item.as_posix().lower()):
            if path.is_symlink():
                relative = _normalise_relative(path.relative_to(source_root))
                raise ShellPackageError(f"Symbolic links are not allowed in the shell package: {relative}")
            if not path.is_file():
                continue
            relative = _normalise_relative(path.relative_to(source_root))
            if _path_is_excluded(relative, policy):
                continue
            content = path.read_bytes()
            findings = _scan_text_safety(relative, content)
            if findings:
                unsafe.append({"path": relative, "finding_classes": findings})
                continue
            digest = _sha256_bytes(content)
            entries.append({"path": relative, "sha256": digest, "size": len(content)})
            content_by_path[relative] = content

    if unsafe:
        paths = ", ".join(item["path"] for item in unsafe[:8])
        raise ShellPackageError(f"Shell source safety scan failed for {len(unsafe)} file(s): {paths}")

    required = [str(item).replace("\\", "/") for item in contract.get("required_paths", [])]
    included = set(content_by_path)
    missing = [item for item in required if item not in included]
    if missing:
        raise ShellPackageError(f"Sanitization policy excluded required shell files: {', '.join(missing)}")
    return entries, content_by_path


def _source_fingerprint(entries: list[dict[str, Any]]) -> str:
    material = "".join(f"{item['path']}={item['sha256']}\n" for item in entries).encode("utf-8")
    return _sha256_bytes(material)


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _zip_bytes(manifest: dict[str, Any], content_by_path: dict[str, bytes]) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024) as handle:
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for relative, content in [(PACKAGE_MANIFEST_NAME, _manifest_bytes(manifest)), *sorted(content_by_path.items())]:
                info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        handle.seek(0)
        return handle.read()


def build_shell_package(
    *,
    source_root: Path,
    contract_path: Path,
    output_directory: Path,
    confirmation: str | None,
    write: bool,
    overwrite: bool = False,
) -> dict[str, Any]:
    contract = load_shell_contract(contract_path)
    package = contract["package_release"]
    entries, content_by_path = _source_files(source_root, contract)
    fingerprint = _source_fingerprint(entries)
    manifest = {
        "package_format_version": PACKAGE_FORMAT_VERSION,
        "release_version": str(package["release_version"]),
        "source_template_version": str(package["source_template_version"]),
        "source_fingerprint": fingerprint,
        "private_configuration_included": False,
        "generated_runtime_included": False,
        "file_count": len(entries),
        "total_bytes": sum(int(item["size"]) for item in entries),
        "required_paths": [str(item).replace("\\", "/") for item in contract.get("required_paths", [])],
        "safety": {
            "environment_files_excluded": True,
            "secrets_exposed": False,
            "database_files_excluded": True,
            "logs_excluded": True,
            "model_artifacts_excluded": True,
            "generated_uploads_excluded": True,
        },
        "files": entries,
    }
    archive_content = _zip_bytes(manifest, content_by_path)
    archive_sha256 = _sha256_bytes(archive_content)
    archive_name = str(package["archive_name"])
    expected_archive = str(package.get("archive_sha256", "")).lower()
    expected_source = str(package.get("source_fingerprint", "")).lower()
    contract_locked = len(expected_archive) == 64 and len(expected_source) == 64
    contract_match = archive_sha256 == expected_archive and fingerprint == expected_source
    result: dict[str, Any] = {
        "ok": True,
        "status": "preview",
        "package_format_version": PACKAGE_FORMAT_VERSION,
        "release_version": manifest["release_version"],
        "archive_name": archive_name,
        "archive_sha256": archive_sha256,
        "source_fingerprint": fingerprint,
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
        "private_configuration_included": False,
        "secrets_exposed": False,
        "contract_match": contract_match,
        "write_performed": False,
    }
    if not write:
        return result
    if confirmation != BUILD_CONFIRMATION:
        raise ShellPackageError(f"Package creation requires --confirm {BUILD_CONFIRMATION}.")
    if contract_locked and not contract_match:
        raise ShellPackageError("Shell source does not match the approved release contract; define a new reviewed version.")
    output_directory.mkdir(parents=True, exist_ok=True)
    archive_path = output_directory / archive_name
    if archive_path.exists() and not overwrite:
        existing_hash = _sha256_file(archive_path)
        if existing_hash != archive_sha256:
            raise ShellPackageError("A different archive already exists at the output path; choose a new release version.")
        result.update({"status": "reused", "archive_path": str(archive_path), "write_performed": False})
        return result
    temporary = archive_path.with_name(f".{archive_path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(archive_content)
    os.replace(temporary, archive_path)
    result.update({"status": "created", "archive_path": str(archive_path), "write_performed": True})
    return result


def _safe_archive_names(archive: zipfile.ZipFile) -> list[str]:
    names: list[str] = []
    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if info.is_dir():
            continue
        if not name or path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            raise ShellPackageError("The shell package contains an unsafe archive path.")
        if name in names:
            raise ShellPackageError(f"The shell package contains a duplicate path: {name}")
        names.append(name)
    return names


def verify_shell_package(*, package_path: Path, contract_path: Path, require_contract_hash: bool = True) -> dict[str, Any]:
    contract = load_shell_contract(contract_path)
    package = contract["package_release"]
    if not package_path.is_file():
        raise ShellPackageError("The MFU shell package does not exist.")
    archive_sha256 = _sha256_file(package_path)
    expected_hash = str(package.get("archive_sha256", "")).lower()
    if require_contract_hash and (len(expected_hash) != 64 or archive_sha256 != expected_hash):
        raise ShellPackageError("MFU shell package checksum does not match the approved contract.")
    with zipfile.ZipFile(package_path, "r") as archive:
        names = _safe_archive_names(archive)
        if PACKAGE_MANIFEST_NAME not in names:
            raise ShellPackageError("MFU shell package manifest is missing.")
        try:
            manifest = json.loads(archive.read(PACKAGE_MANIFEST_NAME).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ShellPackageError("MFU shell package manifest is invalid.") from exc
        if manifest.get("package_format_version") != PACKAGE_FORMAT_VERSION:
            raise ShellPackageError("MFU shell package format version is invalid.")
        if manifest.get("release_version") != package.get("release_version"):
            raise ShellPackageError("MFU shell package release version does not match the contract.")
        if manifest.get("private_configuration_included") is not False:
            raise ShellPackageError("MFU shell package must not contain private configuration.")
        expected_source = str(package.get("source_fingerprint", "")).lower()
        if require_contract_hash and manifest.get("source_fingerprint") != expected_source:
            raise ShellPackageError("MFU shell source fingerprint does not match the approved contract.")
        file_entries = manifest.get("files")
        if not isinstance(file_entries, list):
            raise ShellPackageError("MFU shell package file manifest is invalid.")
        manifest_paths = [str(item.get("path", "")) for item in file_entries]
        archive_paths = [name for name in names if name != PACKAGE_MANIFEST_NAME]
        if sorted(manifest_paths) != sorted(archive_paths):
            raise ShellPackageError("MFU shell package contents do not match its manifest.")
        policy = _package_policy(contract)
        for item in file_entries:
            relative = str(item.get("path", ""))
            if _path_is_excluded(relative, policy):
                raise ShellPackageError(f"MFU shell package contains a forbidden path: {relative}")
            content = archive.read(relative)
            if _sha256_bytes(content) != item.get("sha256") or len(content) != item.get("size"):
                raise ShellPackageError(f"MFU shell package file checksum failed: {relative}")
            findings = _scan_text_safety(relative, content)
            if findings:
                raise ShellPackageError(f"MFU shell package safety scan failed: {relative}")
        required = [str(item).replace("\\", "/") for item in contract.get("required_paths", [])]
        missing = [item for item in required if item not in manifest_paths]
        if missing:
            raise ShellPackageError(f"MFU shell package is missing required files: {', '.join(missing)}")
    return {
        "ok": True,
        "status": "verified",
        "package_format_version": PACKAGE_FORMAT_VERSION,
        "release_version": manifest["release_version"],
        "archive_name": package_path.name,
        "archive_sha256": archive_sha256,
        "source_fingerprint": manifest["source_fingerprint"],
        "file_count": len(file_entries),
        "private_configuration_included": False,
        "secrets_exposed": False,
    }


def verify_installed_shell(*, shell_root: Path, contract_path: Path) -> dict[str, Any]:
    contract = load_shell_contract(contract_path)
    package = contract["package_release"]
    manifest_path = shell_root / PACKAGE_MANIFEST_NAME
    if not manifest_path.is_file():
        raise ShellPackageError("Installed MFU shell package manifest is missing.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ShellPackageError("Installed MFU shell package manifest is invalid.") from exc
    if manifest.get("release_version") != package.get("release_version"):
        raise ShellPackageError("Installed MFU shell release does not match the approved contract.")
    if manifest.get("source_fingerprint") != package.get("source_fingerprint"):
        raise ShellPackageError("Installed MFU shell fingerprint does not match the approved contract.")
    file_entries = manifest.get("files")
    if not isinstance(file_entries, list):
        raise ShellPackageError("Installed MFU shell file manifest is invalid.")
    for item in file_entries:
        relative = str(item.get("path", ""))
        target = shell_root / Path(relative)
        if not target.is_file() or _sha256_file(target) != item.get("sha256"):
            raise ShellPackageError(f"Installed MFU shell source integrity failed: {relative}")
    return {
        "ok": True,
        "status": "installed_verified",
        "release_version": manifest["release_version"],
        "source_fingerprint": manifest["source_fingerprint"],
        "file_count": len(file_entries),
        "private_configuration_included": False,
        "secrets_exposed": False,
    }


def install_shell_package(
    *,
    package_path: Path,
    contract_path: Path,
    install_base: Path,
    confirmation: str | None,
) -> dict[str, Any]:
    if confirmation != INSTALL_CONFIRMATION:
        raise ShellPackageError(f"Package installation requires --confirm {INSTALL_CONFIRMATION}.")
    verified = verify_shell_package(package_path=package_path, contract_path=contract_path)
    release_version = str(verified["release_version"])
    destination = install_base / release_version
    install_base.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        try:
            current = verify_installed_shell(shell_root=destination, contract_path=contract_path)
            return {**verified, **current, "install_root": str(destination), "reused": True, "write_performed": False}
        except ShellPackageError:
            quarantine = install_base / f"{release_version}.quarantine.{uuid.uuid4().hex[:12]}"
            destination.replace(quarantine)

    # Keep the atomic extraction directory compact for Windows installations.
    # The release tree contains some long supervisor-template filenames, and a
    # verbose staging name can otherwise cross the legacy MAX_PATH boundary.
    staging = install_base / f".s-{uuid.uuid4().hex[:8]}"
    try:
        staging.mkdir(parents=True)
        with zipfile.ZipFile(package_path, "r") as archive:
            for name in _safe_archive_names(archive):
                target = staging / Path(name)
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(name))
                except OSError as exc:
                    raise ShellPackageError(
                        "MFU shell extraction failed. On Windows, place the ATDR clone in a shorter "
                        "directory (spaces are supported) or enable Windows long-path support."
                    ) from exc
        verify_installed_shell(shell_root=staging, contract_path=contract_path)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return {
        **verified,
        "status": "installed_verified",
        "install_root": str(destination),
        "reused": False,
        "write_performed": True,
    }
