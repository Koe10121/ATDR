"""Simulated attacks blended into real MFU traffic.

MFU cannot be attacked for real, so the model learns attack behaviour from
simulated firewall logs added to real traffic windows (the approach of
"injecting" attacks into real logs, as in the Sensors 2024 study on firewall
logs). To keep the model from simply learning "this looks simulated":

- zone names, internal hosts and destinations come from the real traffic;
- attacks by an internal host are added to a real host's existing traffic, so
  that host's window mixes normal and malicious sessions;
- every attack draws its own intensity, from obvious to subtle (for example a
  scan of 8 ports over five minutes, or a beacon with 30% timing jitter).

Each call returns firewall-log rows with the same columns as
``behavior_features.LOG_COLUMNS`` and the (source IP, window) it labels.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from atdr.app.detection.rules import AUTH_SERVICE_PORTS

ATTACK_TYPES = ("port_scan", "brute_force", "dos_ddos", "malware_c2", "data_exfiltration_suspicion")
SCENARIOS = {
    "port_scan": ("vertical_scan", "horizontal_scan"),
    "brute_force": ("brute_force",),
    "dos_ddos": ("flood",),
    "malware_c2": ("beaconing",),
    "data_exfiltration_suspicion": ("exfiltration",),
}
SERVICE_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
LOGIN_APPS = {22: "ssh", 3389: "ms-rdp", 445: "ms-ds-smb", 21: "ftp", 23: "telnet", 3306: "mysql", 1433: "mssql-db",
              5900: "vnc", 25: "smtp", 110: "pop3", 143: "imap", 993: "imap", 995: "pop3", 389: "ldap"}


@dataclass(frozen=True, slots=True)
class Network:
    """What real MFU traffic looks like in one window."""

    inside_zone: str
    outside_zone: str
    internal_hosts: tuple[str, ...]
    external_hosts: tuple[str, ...]

    @classmethod
    def from_logs(cls, logs: pd.DataFrame) -> "Network":
        inside = logs.loc[logs["src_zone"].fillna("").str.contains("Inside", case=False), "src_zone"]
        outside = logs.loc[logs["dst_zone"].fillna("").str.contains("Outside", case=False), "dst_zone"]
        internal = logs.loc[logs["src_ip"].map(_is_private), "src_ip"].dropna().unique()
        external = logs.loc[~logs["dst_ip"].map(_is_private), "dst_ip"].dropna().unique()
        return cls(
            inside_zone=inside.mode().iat[0] if not inside.empty else "Inside",
            outside_zone=outside.mode().iat[0] if not outside.empty else "Outside",
            internal_hosts=tuple(sorted(internal)),
            external_hosts=tuple(sorted(external)),
        )


def _is_private(ip: object) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _public_ip(rng: np.random.Generator) -> str:
    while True:
        candidate = ipaddress.ip_address(int(rng.integers(0x01000000, 0xDF000000)))
        if candidate.is_global:
            return str(candidate)


def _log_uniform(rng: np.random.Generator, low: float, high: float) -> float:
    return float(np.exp(rng.uniform(np.log(low), np.log(high))))


class Simulator:
    def __init__(self, network: Network, window_start: datetime, *, seed: int, first_log_id: int = -1) -> None:
        self.network = network
        self.window_start = window_start
        self.rng = np.random.default_rng(seed)
        self.next_id = first_log_id

    # ------------------------------------------------------------ helpers
    def _times(self, count: int, *, regular_interval: float | None = None, jitter: float = 0.0) -> list[datetime]:
        rng = self.rng
        if regular_interval is not None:
            offset = rng.uniform(0, regular_interval)
            times, current = [], offset
            while current < 299 and len(times) < count:
                times.append(current)
                current += regular_interval * (1 + rng.uniform(-jitter, jitter))
        else:
            duration = _log_uniform(rng, 5, 295)
            start = rng.uniform(0, 299 - duration)
            times = sorted(start + rng.uniform(0, duration, size=count))
        return [self.window_start + timedelta(seconds=float(value)) for value in times]

    def _row(self, time: datetime, src: str, dst: str, port: int, inbound: bool, **fields) -> dict:
        self.next_id -= 1
        inside, outside = self.network.inside_zone, self.network.outside_zone
        return {
            "log_id": self.next_id,
            "generated_time": time,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "src_zone": outside if inbound else inside,
            "dst_zone": inside if inbound else outside,
            "log_type": "TRAFFIC",
            **fields,
        }

    def _probe(self, time: datetime, src: str, dst: str, port: int, inbound: bool, deny_share: float) -> dict:
        # Field values follow MFU's real labeled scan logs: mostly allowed, one packet, app "incomplete",
        # no reply, and the session ages out.
        rng = self.rng
        denied = rng.random() < deny_share
        answered = not denied and rng.random() < 0.05
        return self._row(
            time, src, dst, port, inbound,
            action=str(rng.choice(["deny", "drop"])) if denied else "allow",
            app="ping" if port == 0 else str(rng.choice(["incomplete", "unknown-udp", "insufficient-data", "not-applicable"], p=[0.82, 0.1, 0.04, 0.04])),
            app_risk=float(rng.choice([1, 2, 3, 4])),
            bytes_sent=float(rng.integers(40, 140)),
            bytes_received=float(rng.integers(40, 600)) if answered else 0.0,
            packets=1.0 if rng.random() < 0.83 else float(rng.integers(2, 4)),
            elapsed_time=0.0 if rng.random() < 0.95 else 1.0,
            session_end_reason="policy-deny" if denied else ("aged-out" if rng.random() < 0.9 else str(rng.choice(["tcp-rst-from-server", "tcp-rst-from-client"]))),
        )

    def _attacker(self, inbound: bool) -> str:
        if inbound or not self.network.internal_hosts:
            return _public_ip(self.rng)
        return str(self.rng.choice(self.network.internal_hosts))

    def _target(self, inbound: bool) -> str:
        pool = self.network.internal_hosts if inbound else self.network.external_hosts
        return str(self.rng.choice(pool)) if pool and self.rng.random() < 0.7 else (
            f"10.{self.rng.integers(0, 256)}.{self.rng.integers(0, 256)}.{self.rng.integers(1, 255)}" if inbound else _public_ip(self.rng)
        )

    # ------------------------------------------------------------ scenarios
    def vertical_scan(self) -> list[dict]:
        rng = self.rng
        inbound = rng.random() < 0.7
        src, dst = self._attacker(inbound), self._target(inbound)
        count = int(_log_uniform(rng, 5, 1000))
        ports = set(rng.choice(SERVICE_PORTS, size=min(len(SERVICE_PORTS), count // 2 + 1), replace=False).tolist())
        while len(ports) < count:
            ports.add(int(rng.integers(1, 65536)))
        deny_share = 0.0 if rng.random() < 0.7 else rng.uniform(0.3, 1.0)
        times = self._times(len(ports))
        return [self._probe(time, src, dst, int(port), inbound, deny_share) for time, port in zip(times, sorted(ports, key=lambda _: rng.random()))]

    def horizontal_scan(self) -> list[dict]:
        rng = self.rng
        inbound = rng.random() < 0.6
        src = self._attacker(inbound)
        hosts = int(_log_uniform(rng, 10, 500))
        ports = rng.choice([22, 23, 80, 443, 445, 3389, 8080, 1433, 3306, 5900], size=int(rng.integers(1, 4)), replace=False)
        deny_share = 0.0 if rng.random() < 0.7 else rng.uniform(0.3, 1.0)
        targets = {self._target(inbound) for _ in range(hosts * 2)}
        targets = list(targets)[:hosts]
        pairs = [(target, int(port)) for target in targets for port in ports]
        times = self._times(len(pairs))
        return [self._probe(time, src, dst, port, inbound, deny_share) for time, (dst, port) in zip(times, pairs)]

    def brute_force(self) -> list[dict]:
        rng = self.rng
        inbound = rng.random() < 0.6
        src = self._attacker(inbound)
        port = int(rng.choice(sorted(AUTH_SERVICE_PORTS)))
        targets = [self._target(inbound) for _ in range(int(rng.integers(1, 3)))]
        attempts = int(_log_uniform(rng, 6, 300))
        blocked = rng.uniform(0, 0.5) if rng.random() < 0.3 else 0.0
        rows = []
        for time in self._times(attempts):
            denied = rng.random() < blocked
            rows.append(self._row(
                time, src, str(rng.choice(targets)), port, inbound,
                action="deny" if denied else "allow",
                app=LOGIN_APPS.get(port, "unknown-tcp") if rng.random() < 0.8 else "incomplete",
                app_risk=float(rng.choice([3, 4, 5])),
                bytes_sent=0.0 if denied else float(rng.integers(900, 4500)),
                bytes_received=0.0 if denied else float(rng.integers(900, 6000)),
                packets=1.0 if denied else float(rng.integers(8, 30)),
                elapsed_time=0.0 if denied else float(rng.integers(1, 6)),
                session_end_reason="policy-deny" if denied else str(rng.choice(["tcp-fin", "tcp-rst-from-server", "tcp-rst-from-client"])),
            ))
        return rows

    def flood(self) -> list[dict]:
        rng = self.rng
        inbound = rng.random() < 0.6
        src, dst = self._attacker(inbound), self._target(inbound)
        port = int(rng.choice([80, 443, 53, 123, 8080, int(rng.integers(1024, 65536))]))
        count = int(_log_uniform(rng, 150, 5000))
        deny_share = 0.0 if rng.random() < 0.5 else rng.uniform(0.2, 1.0)
        rows = []
        for time in self._times(count):
            row = self._probe(time, src, dst, port, inbound, deny_share)
            row["app"] = str(rng.choice(["incomplete", "dns", "ntp", "web-browsing", "unknown-udp"])) if port in (53, 123) else row["app"]
            rows.append(row)
        return rows

    def beaconing(self) -> list[dict]:
        rng = self.rng
        src = str(rng.choice(self.network.internal_hosts)) if self.network.internal_hosts else self._attacker(False)
        dst = _public_ip(rng) if rng.random() < 0.8 or not self.network.external_hosts else str(rng.choice(self.network.external_hosts))
        interval = rng.uniform(5, 70)
        jitter = rng.uniform(0, 0.3)
        port = int(rng.choice([443, 443, 8080, 8443, 80, int(rng.integers(1024, 65536))]))
        app = "ssl" if port in (443, 8443) else str(rng.choice(["web-browsing", "unknown-tcp"]))
        rows = []
        for time in self._times(1000, regular_interval=interval, jitter=jitter):
            rows.append(self._row(
                time, src, dst, port, False,
                action="allow", app=app, app_risk=float(rng.choice([2, 3, 4])),
                bytes_sent=float(rng.integers(200, 2000)), bytes_received=float(rng.integers(100, 5000)),
                packets=float(rng.integers(4, 13)), elapsed_time=float(rng.integers(0, 3)),
                session_end_reason="tcp-fin",
            ))
        return rows

    def exfiltration(self) -> list[dict]:
        rng = self.rng
        src = str(rng.choice(self.network.internal_hosts)) if self.network.internal_hosts else self._attacker(False)
        dst = _public_ip(rng)
        sessions = int(rng.integers(1, 21))
        total = _log_uniform(rng, 30e6, 2e9)
        shares = rng.dirichlet(np.ones(sessions))
        port = int(rng.choice([443, 443, 21, 22, 8443, int(rng.integers(1024, 65536))]))
        app = {443: "ssl", 8443: "ssl", 21: "ftp", 22: "ssh"}.get(port, "unknown-tcp")
        rows = []
        for time, share in zip(self._times(sessions), shares):
            sent = float(total * share)
            rows.append(self._row(
                time, src, dst, port, False,
                action="allow", app=app, app_risk=float(rng.choice([2, 3, 4, 5])),
                bytes_sent=sent, bytes_received=float(rng.integers(2000, 200000)),
                packets=float(max(10, sent / 1400)), elapsed_time=float(rng.integers(20, 600)),
                session_end_reason="tcp-fin",
            ))
        return rows

    def attack(self, attack_type: str) -> tuple[pd.DataFrame, tuple[str, datetime]]:
        scenario = str(self.rng.choice(SCENARIOS[attack_type]))
        rows = getattr(self, scenario)()
        frame = pd.DataFrame(rows)
        return frame, (str(frame["src_ip"].iat[0]), self.window_start)
