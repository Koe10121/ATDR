from __future__ import annotations

import ast
import re
import subprocess
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit


MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)")
HTML_LINK_RE = re.compile(r"(?:href|src)=[\"'](?P<target>[^\"']+)[\"']", re.IGNORECASE)
MODULE_COMMAND_RE = re.compile(
    r"(?:python(?:\.exe)?|py(?:\s+-\d+(?:\.\d+)?)?)\s+-m\s+(?P<module>[A-Za-z_][\w.]*)",
    re.IGNORECASE,
)
SCRIPT_COMMAND_RE = re.compile(
    r"(?P<path>(?:\.\\|\./)?(?:scripts|atdr[\\/]scripts)[\\/][A-Za-z0-9_.-]+\.(?:py|ps1|cmd|js))",
    re.IGNORECASE,
)
MODULE_TEXT_RE = re.compile(r"\batdr\.(?:app|scripts|tests)(?:\.[A-Za-z_]\w*)+\b")
DOC_REFERENCE_RE = re.compile(r"^docs/[A-Za-z0-9_./-]+\.md(?:#[A-Za-z0-9_.-]+)?$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
WINDOWS_ABSOLUTE_RE = re.compile(r"^(?:/?[A-Za-z]:[\\/]|\\\\)")
EXTERNAL_SCHEMES = {"http", "https", "mailto", "data", "app", "tel"}
IGNORED_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    "dist",
    ".tmp",
    "tmp",
    ".pytest_cache",
    ".pytest_tmp",
    "ml_baseline_reviews",
    "demo_exports",
}


def _repo_paths(root: Path) -> list[Path]:
    try:
        top_level = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()
        if Path(top_level).resolve() != root.resolve():
            raise OSError("Audit root is not the repository top level.")
        completed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            capture_output=True,
            check=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return sorted(
            path
            for path in root.rglob("*")
            if path.is_file() and not any(part in IGNORED_PARTS for part in path.relative_to(root).parts)
        )
    return sorted(
        path
        for line in completed.stdout.splitlines()
        if line.strip() and (path := root / line).is_file()
    )


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _without_fenced_code(text: str) -> str:
    lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        marker = FENCE_RE.match(line)
        if marker:
            current = marker.group(1)
            if fence is None:
                fence = current
            elif current == fence:
                fence = None
            lines.append("")
            continue
        lines.append("" if fence else line)
    return "\n".join(lines)


def _heading_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    counts: Counter[str] = Counter()
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        title = re.sub(r"<[^>]+>", "", match.group("title")).strip().lower()
        slug = "".join(
            character
            for character in title
            if character.isalnum()
            or unicodedata.category(character).startswith("M")
            or character in " _-"
        )
        slug = re.sub(r"\s+", "-", slug).strip("-")
        suffix = counts[slug]
        counts[slug] += 1
        anchors.add(f"{slug}-{suffix}" if suffix else slug)
    return anchors


def _resolve_markdown_target(root: Path, source: Path, raw_target: str) -> tuple[Path | None, str | None, str | None]:
    target = raw_target.strip("<>")
    parsed = urlsplit(target)
    if parsed.scheme.lower() in EXTERNAL_SCHEMES or target.startswith("//"):
        return None, None, "external"
    if WINDOWS_ABSOLUTE_RE.match(target):
        return None, parsed.fragment or None, "absolute_local_path"
    path_text = unquote(parsed.path)
    if not path_text:
        return source, parsed.fragment or None, "internal"
    candidate = root / path_text.lstrip("/") if path_text.startswith("/") else source.parent / path_text
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None, parsed.fragment or None, "outside_repository"
    return resolved, parsed.fragment or None, "internal"


def _markdown_graph(root: Path, paths: Iterable[Path]) -> dict[str, Any]:
    markdown_paths = [path for path in paths if path.suffix.lower() == ".md"]
    markdown_set = {path.resolve() for path in markdown_paths}
    existing_set = {path.resolve() for path in paths}
    anchors_by_path: dict[Path, set[str]] = {}
    edges: list[dict[str, str]] = []
    broken: list[dict[str, str]] = []
    portable_failures: list[dict[str, str]] = []
    external_count = 0

    for source in markdown_paths:
        text = source.read_text(encoding="utf-8", errors="replace")
        visible_text = _without_fenced_code(text)
        raw_targets = [match.group("target") for match in MARKDOWN_LINK_RE.finditer(visible_text)]
        raw_targets.extend(match.group("target") for match in HTML_LINK_RE.finditer(visible_text))
        for raw_target in raw_targets:
            target_path, fragment, kind = _resolve_markdown_target(root, source, raw_target)
            source_name = _relative(root, source)
            if kind == "external":
                external_count += 1
                continue
            if kind in {"absolute_local_path", "outside_repository"}:
                portable_failures.append({"source": source_name, "target": raw_target, "reason": kind})
                continue
            target_name = _relative(root, target_path) if target_path is not None else raw_target
            edges.append({"source": source_name, "target": target_name, "fragment": fragment or ""})
            if target_path is None or target_path not in existing_set:
                broken.append({"source": source_name, "target": raw_target, "reason": "missing_target"})
                continue
            if fragment and target_path in markdown_set:
                if target_path not in anchors_by_path:
                    anchors_by_path[target_path] = _heading_anchors(
                        target_path.read_text(encoding="utf-8", errors="replace")
                    )
                if unquote(fragment).lower() not in anchors_by_path[target_path]:
                    broken.append({"source": source_name, "target": raw_target, "reason": "missing_anchor"})

    return {
        "markdown_file_count": len(markdown_paths),
        "internal_edge_count": len(edges),
        "external_link_count": external_count,
        "broken_count": len(broken),
        "portable_failure_count": len(portable_failures),
        "broken": broken,
        "portable_failures": portable_failures,
        "edges": edges,
    }


def _module_name(root: Path, path: Path) -> str | None:
    relative = path.relative_to(root)
    if path.suffix != ".py":
        return None
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _module_candidates(module: str) -> tuple[str, str]:
    return f"{module.replace('.', '/')}.py", f"{module.replace('.', '/')}/__init__.py"


def _resolve_import(current_module: str, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    package = current_module.split(".")[:-1]
    keep = max(0, len(package) - node.level + 1)
    prefix = package[:keep]
    if node.module:
        prefix.extend(node.module.split("."))
    return ".".join(prefix)


def _python_graph(root: Path, paths: Iterable[Path], text_paths: Iterable[Path]) -> dict[str, Any]:
    python_paths = [path for path in paths if path.suffix == ".py"]
    relative_paths = {_relative(root, path): path for path in python_paths}
    module_to_path = {
        module: _relative(root, path)
        for path in python_paths
        if (module := _module_name(root, path))
    }
    edges: set[tuple[str, str]] = set()
    parse_errors: list[dict[str, str]] = []
    main_entry_points: set[str] = set()
    document_references: set[tuple[str, str]] = set()
    missing_document_references: set[tuple[str, str]] = set()

    for path in python_paths:
        source_name = _relative(root, path)
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text, filename=source_name)
        except SyntaxError as exc:
            parse_errors.append({"path": source_name, "reason": f"SyntaxError:{exc.lineno}"})
            continue
        current_module = _module_name(root, path) or ""
        checks_runtime_doc_references = source_name.startswith(("atdr/app/", "atdr/scripts/"))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = _resolve_import(current_module, node)
                modules.append(base)
                modules.extend(f"{base}.{alias.name}" for alias in node.names if base)
            for module in modules:
                probe = module
                while probe:
                    if probe in module_to_path:
                        edges.add((source_name, module_to_path[probe]))
                        break
                    probe = probe.rpartition(".")[0]
            if (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and "__name__" in ast.unparse(node.test)
                and "__main__" in ast.unparse(node.test)
            ):
                main_entry_points.add(source_name)
            if (
                checks_runtime_doc_references
                and isinstance(node, ast.Constant)
                and isinstance(node.value, str)
            ):
                reference = node.value.strip().replace("\\", "/")
                if DOC_REFERENCE_RE.fullmatch(reference):
                    document_path = reference.split("#", maxsplit=1)[0]
                    document_references.add((source_name, document_path))
                    if not (root / document_path).is_file():
                        missing_document_references.add((source_name, document_path))

    documented_modules: set[str] = set()
    documented_scripts: set[str] = set()
    missing_commands: list[dict[str, str]] = []
    dynamic_module_references: set[str] = set()
    for path in text_paths:
        if path.suffix.lower() not in {".md", ".yml", ".yaml", ".ps1", ".cmd", ".js", ".ts", ".tsx", ".py"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        source_name = _relative(root, path)
        supported_command_source = not source_name.startswith(
            ("atdr/tests/", "docs/archive/", "docs/reference/")
        )
        for match in MODULE_COMMAND_RE.finditer(text):
            module = match.group("module")
            documented_modules.add(module)
            candidates = _module_candidates(module)
            target = next((candidate for candidate in candidates if candidate in relative_paths), None)
            if target:
                edges.add((source_name, target))
            elif module.startswith("atdr.") and supported_command_source:
                missing_commands.append({"source": source_name, "command": f"python -m {module}"})
        for match in SCRIPT_COMMAND_RE.finditer(text):
            command_path = match.group("path").replace("\\", "/").removeprefix("./")
            documented_scripts.add(command_path)
            if not (root / command_path).is_file() and supported_command_source:
                missing_commands.append({"source": source_name, "command": command_path})
        dynamic_module_references.update(MODULE_TEXT_RE.findall(text))

    inbound: Counter[str] = Counter(target for _, target in edges)
    script_inventory: list[dict[str, Any]] = []
    for source_name in sorted(relative_paths):
        if not source_name.startswith("atdr/scripts/"):
            continue
        module = _module_name(root, relative_paths[source_name]) or ""
        referenced_by_command = module in documented_modules or source_name in documented_scripts
        if source_name.endswith("/__init__.py") or source_name == "atdr/scripts/__init__.py":
            classification = "keep_package"
        elif inbound[source_name] or referenced_by_command:
            classification = "keep_referenced"
        elif source_name in main_entry_points:
            classification = "keep_compatibility_cli"
        else:
            classification = "review_required"
        script_inventory.append(
            {
                "path": source_name,
                "classification": classification,
                "inbound_reference_count": inbound[source_name],
                "documented_command": referenced_by_command,
                "main_entry_point": source_name in main_entry_points,
            }
        )

    return {
        "python_file_count": len(python_paths),
        "internal_edge_count": len(edges),
        "parse_error_count": len(parse_errors),
        "parse_errors": parse_errors,
        "main_entry_point_count": len(main_entry_points),
        "documented_module_count": len(documented_modules),
        "documented_script_count": len(documented_scripts),
        "dynamic_module_reference_count": len(dynamic_module_references),
        "missing_command_count": len(missing_commands),
        "missing_commands": missing_commands,
        "document_reference_count": len(document_references),
        "missing_document_reference_count": len(missing_document_references),
        "missing_document_references": [
            {"source": source, "document": document}
            for source, document in sorted(missing_document_references)
        ],
        "script_classification_counts": dict(Counter(item["classification"] for item in script_inventory)),
        "script_inventory": script_inventory,
        "edges": [
            {"source": source, "target": target}
            for source, target in sorted(edges)
        ],
    }


def _documentation_inventory(root: Path, paths: Iterable[Path]) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    for path in paths:
        if path.suffix.lower() not in {".md", ".html"}:
            continue
        relative = _relative(root, path)
        if relative.startswith("docs/archive/"):
            classification = "archive"
            reason = "Historical audit or superseded guidance retained for traceability."
        elif relative.startswith("docs/reference/"):
            classification = "keep_reference"
            reason = "University/template reference; not an ATDR runtime contract."
        elif relative == "docs/tasks/tasklist-progress.html":
            classification = "keep_generated_view"
            reason = "Canonical taskboard view generated from the active Markdown source."
        else:
            classification = "keep_active"
            reason = "Current operator, product, security, governance, or implementation reference."
        inventory.append({"path": relative, "classification": classification, "reason": reason})
    return inventory


def _surface_groups(root: Path, paths: Iterable[Path]) -> dict[str, list[str]]:
    relative_paths = [_relative(root, path) for path in paths]

    def select(predicate) -> list[str]:
        return sorted(path for path in relative_paths if predicate(path))

    return {
        "documentation": select(lambda path: path.endswith((".md", ".html")) and path.startswith("docs/")),
        "runbooks": select(
            lambda path: path.startswith("docs/")
            and path.endswith(".md")
            and any(token in Path(path).name.upper() for token in ("RUNBOOK", "QUICKSTART", "HANDOFF"))
        ),
        "allowlists": select(lambda path: path.endswith("_COMMIT_ALLOWLIST.md")),
        "change_records": select(
            lambda path: path.endswith(".md")
            and ("/changes/" in path or Path(path).name.startswith("T1_T20_"))
        ),
        "versioned_scripts": select(
            lambda path: path.startswith("atdr/scripts/run_v") and path.endswith(".py")
        ),
        "wrappers": select(
            lambda path: path.startswith("scripts/") and path.endswith((".cmd", ".ps1"))
        ),
        "migrations": select(lambda path: path.startswith("migrations/") and path.endswith(".py")),
        "routers": select(lambda path: path.startswith("atdr/app/routers/") and path.endswith(".py")),
        "job_handlers": select(
            lambda path: path.startswith("atdr/app/")
            and path.endswith(".py")
            and any(token in Path(path).stem.lower() for token in ("job", "worker", "operation"))
        ),
        "tests": select(
            lambda path: path.startswith(("atdr/tests/", "frontend/tests/"))
            and path.endswith((".py", ".ts", ".tsx"))
        ),
        "ci": select(lambda path: path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))),
    }


def build_repository_surface_report(root: Path, *, include_edges: bool = False) -> dict[str, Any]:
    root = root.resolve()
    paths = _repo_paths(root)
    markdown = _markdown_graph(root, paths)
    python = _python_graph(root, paths, paths)
    documentation_inventory = _documentation_inventory(root, paths)
    groups = _surface_groups(root, paths)
    inventory = {
        "counts": {name: len(items) for name, items in groups.items()},
        "documentation_classification_counts": dict(
            Counter(item["classification"] for item in documentation_inventory)
        ),
    }
    if not include_edges:
        markdown.pop("edges", None)
        python.pop("edges", None)
        python.pop("script_inventory", None)
    else:
        inventory["groups"] = groups
        inventory["documentation"] = documentation_inventory
    ok = not any(
        (
            markdown["broken_count"],
            markdown["portable_failure_count"],
            python["parse_error_count"],
            python["missing_command_count"],
            python["missing_document_reference_count"],
        )
    )
    return {
        "ok": ok,
        "status": "repository_surface_valid" if ok else "repository_surface_issues",
        "path_count": len(paths),
        "markdown": markdown,
        "python": python,
        "inventory": inventory,
        "runtime_behavior_changed": False,
        "filesystem_writes_performed": False,
        "private_evidence_accessed": False,
        "secrets_exposed": False,
    }
