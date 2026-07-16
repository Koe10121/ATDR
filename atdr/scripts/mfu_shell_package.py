from __future__ import annotations

import argparse
import json
from pathlib import Path

from atdr.app.services.mfu_shell_package_service import (
    BUILD_CONFIRMATION,
    INSTALL_CONFIRMATION,
    ShellPackageError,
    build_shell_package,
    install_shell_package,
    verify_installed_shell,
    verify_shell_package,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build, verify, or install a sanitized versioned MFU shell package.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preview-build", action="store_true")
    action.add_argument("--build", action="store_true")
    action.add_argument("--verify-package", action="store_true")
    action.add_argument("--install", action="store_true")
    action.add_argument("--verify-installed", action="store_true")
    parser.add_argument("--template-root", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--output-directory", type=Path, default=Path(".atdr_runtime/packages"))
    parser.add_argument("--install-base", type=Path, default=Path(".atdr_runtime/shell"))
    parser.add_argument("--shell-root", type=Path)
    parser.add_argument("--contract", type=Path, default=Path("config/mfu-shell-contract.json"))
    parser.add_argument("--confirm")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--result-path", type=Path)
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        if args.preview_build or args.build:
            if args.template_root is None:
                parser.error("--template-root is required for package build operations.")
            result = build_shell_package(
                source_root=args.template_root,
                contract_path=args.contract,
                output_directory=args.output_directory,
                confirmation=args.confirm,
                write=args.build,
                overwrite=args.overwrite,
            )
        elif args.verify_package:
            if args.package is None:
                parser.error("--package is required for verification.")
            result = verify_shell_package(package_path=args.package, contract_path=args.contract)
        elif args.install:
            if args.package is None:
                parser.error("--package is required for installation.")
            result = install_shell_package(
                package_path=args.package,
                contract_path=args.contract,
                install_base=args.install_base,
                confirmation=args.confirm,
            )
        else:
            if args.shell_root is None:
                parser.error("--shell-root is required for installed-shell verification.")
            result = verify_installed_shell(shell_root=args.shell_root, contract_path=args.contract)
    except ShellPackageError as exc:
        result = {"ok": False, "status": "failed", "message": str(exc), "secrets_exposed": False}
    rendered = json.dumps(result, indent=2 if args.pretty else None)
    if args.result_path:
        args.result_path.parent.mkdir(parents=True, exist_ok=True)
        args.result_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
