"""Consistent stand-in names for MFU IP addresses in files shared for review.

Reviewers judge behaviour, so relationships must survive: the same address always
gets the same name, and addresses in the same /16 and /24 share a prefix.
``mfu-lan-3.12.7`` is host 7 in subnet 12 of private block 3; ``mfu-pub-1.2.5``
is one of MFU's public addresses. Internet addresses are left as they are,
since their owner and reputation are part of what a reviewer weighs.

The mapping is the key back to real addresses. It stays in the git-ignored
``.tmp/`` folder with the other private review files and is reused, so every
file in a review round uses the same names.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from pathlib import Path

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
_PORT_SUFFIX = re.compile(r":\d{1,5}$")


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


class MfuPseudonyms:
    """Maps MFU addresses to stable stand-ins; other addresses pass through."""

    def __init__(self, mfu_networks: Iterable[str] = (), mapping: dict[str, str] | None = None) -> None:
        self.mfu_networks = [ipaddress.ip_network(network, strict=False) for network in mfu_networks]
        self.mapping: dict[str, str] = {}
        self._ids: dict[tuple, int] = {}
        for real, name in (mapping or {}).items():
            self._remember(real, name)

    # ------------------------------------------------------------------ persistence
    @classmethod
    def load(cls, path: Path, mfu_networks: Iterable[str] = ()) -> MfuPseudonyms:
        mapping = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return cls(mfu_networks, mapping)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.mapping, indent=1, sort_keys=True), encoding="utf-8")

    # ------------------------------------------------------------------ naming
    def is_mfu(self, value: str) -> bool:
        address = _address(value)
        if address is None:
            return False
        if str(address) in self.mapping:
            return True
        return address.is_private or any(address in network for network in self.mfu_networks)

    def name(self, value: str) -> str:
        """The stand-in for an MFU address; anything else is returned unchanged."""

        address = _address(value)
        if address is None or not self.is_mfu(value):
            return value
        real = str(address)
        if real not in self.mapping:
            kind = ("lan" if address.is_private else "pub") + ("6" if address.version == 6 else "")
            block, subnet = self._groups(address)
            b = self._next(("block", kind), (kind, block))
            s = self._next(("subnet", kind, block), (kind, block, subnet))
            h = self._next(("host", kind, block, subnet), (kind, block, subnet, real))
            self.mapping[real] = f"mfu-{kind}-{b}.{s}.{h}"
        return self.mapping[real]

    def text(self, value: object) -> object:
        """Replace every MFU address inside free text, such as ``10.1.2.3:443 (20)``."""

        if not isinstance(value, str):
            return value
        value = _IPV4.sub(lambda match: self.name(match.group(0)), value)
        return _IPV6.sub(self._ipv6_in_text, value)

    def _ipv6_in_text(self, match: re.Match) -> str:
        token = match.group(0)
        # "addr:port" is ambiguous for IPv6; prefer an address already named from a structured field.
        stripped = _PORT_SUFFIX.sub("", token)
        if stripped != token and _address(stripped) and str(_address(stripped)) in self.mapping:
            return self.name(stripped) + token[len(stripped):]
        if _address(token) is not None:
            return self.name(token)
        return token

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _groups(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[str, str]:
        if address.version == 4:
            return str(ipaddress.ip_network(f"{address}/16", strict=False)), str(ipaddress.ip_network(f"{address}/24", strict=False))
        return str(ipaddress.ip_network(f"{address}/48", strict=False)), str(ipaddress.ip_network(f"{address}/64", strict=False))

    def _next(self, counter: tuple, key: tuple) -> int:
        if key not in self._ids:
            self._ids[counter] = self._ids.get(counter, 0) + 1
            self._ids[key] = self._ids[counter]
        return self._ids[key]

    def _remember(self, real: str, name: str) -> None:
        address = _address(real)
        match = re.fullmatch(r"mfu-(lan6?|pub6?)-(\d+)\.(\d+)\.(\d+)", name)
        if address is None or match is None:
            raise ValueError(f"Not a pseudonym mapping entry: {name!r}")
        kind, b, s, h = match.group(1), *(int(part) for part in match.groups()[1:])
        block, subnet = self._groups(address)
        for counter, key, number in (
            (("block", kind), (kind, block), b),
            (("subnet", kind, block), (kind, block, subnet), s),
            (("host", kind, block, subnet), (kind, block, subnet, str(address)), h),
        ):
            self._ids[key] = number
            self._ids[counter] = max(self._ids.get(counter, 0), number)
        self.mapping[str(address)] = name


def leftover_mfu_addresses(text: str, pseudonyms: MfuPseudonyms) -> list[str]:
    """MFU addresses still present in ``text``: a check before a file is shared."""

    found = [match.group(0) for match in _IPV4.finditer(text)]
    found += [match.group(0) for match in _IPV6.finditer(text) if _address(match.group(0)) is not None]
    return [value for value in found if pseudonyms.is_mfu(value)]
