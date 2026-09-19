"""Real, host-level IP enforcement via the Windows Firewall (netsh advfirewall).

This is the only real-enforcement connector ATDR ships. It is opt-in
(`RESPONSE_PROVIDER=windows_firewall` and `RESPONSE_SIMULATION=false`) and
scoped deliberately narrowly: it blocks inbound and outbound traffic to/from
a single IP address on the machine the ATDR backend runs on, using the
host's own Windows Firewall. It never touches any other device, does not
require a real firewall/network-owner approval (it is the operator's own
machine), and is fully reversible with `remove_block`.

Every command is built from an explicit argument list (never a shell string)
so a target IP can never inject additional commands. `target_ip` must already
be validated as a real IP address by the caller (response_service does this
via `ipaddress.ip_address` before any connector is invoked).
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass


RULE_NAME_PREFIX = "ATDR-Block"


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    ok: bool
    message: str


def _rule_name(target_ip: str, direction: str) -> str:
    return f"{RULE_NAME_PREFIX}-{direction}-{target_ip}"


def _run(args: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return 1, "netsh was not found on this host. Windows Firewall enforcement requires Windows."
    except subprocess.TimeoutExpired:
        return 1, "netsh did not respond within 15 seconds."
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output.strip()


def is_supported_platform() -> bool:
    return platform.system() == "Windows"


def apply_block(target_ip: str) -> ConnectorResult:
    if not is_supported_platform():
        return ConnectorResult(False, "Windows Firewall enforcement is only available when the backend runs on Windows.")

    # Idempotent: clear any stale rule with this exact name first so repeated
    # block calls (or a block after a prior failed cleanup) never accumulate
    # duplicate rules for the same IP.
    remove_block(target_ip)

    for direction in ("in", "out"):
        code, output = _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_rule_name(target_ip, direction)}",
                "dir=" + direction,
                "action=block",
                f"remoteip={target_ip}",
                "enable=yes",
                "profile=any",
            ]
        )
        if code != 0:
            # Best-effort rollback of whatever direction(s) already succeeded
            # so a partial failure never leaves a half-applied block.
            remove_block(target_ip)
            if "requires elevation" in output.lower() or "access is denied" in output.lower():
                return ConnectorResult(
                    False,
                    "Windows Firewall rule creation failed: administrator privileges are required. "
                    "Run the ATDR backend process as Administrator to use real enforcement.",
                )
            return ConnectorResult(False, f"Windows Firewall rule creation failed ({direction}): {output or 'unknown netsh error'}")

    return ConnectorResult(True, f"Windows Firewall now blocks inbound and outbound traffic for {target_ip} on this host.")


def remove_block(target_ip: str) -> ConnectorResult:
    if not is_supported_platform():
        return ConnectorResult(False, "Windows Firewall enforcement is only available when the backend runs on Windows.")

    failures: list[str] = []
    for direction in ("in", "out"):
        code, output = _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={_rule_name(target_ip, direction)}",
            ]
        )
        # netsh returns a non-zero code when no matching rule exists, which is
        # the expected/successful outcome of removing a block that already
        # isn't there. Only surface genuine errors, not "no rules match".
        if code != 0 and "no rules match" not in output.lower():
            failures.append(f"{direction}: {output or 'unknown netsh error'}")

    if failures:
        return ConnectorResult(False, "Windows Firewall rule removal failed: " + "; ".join(failures))
    return ConnectorResult(True, f"Windows Firewall no longer blocks {target_ip} on this host.")
