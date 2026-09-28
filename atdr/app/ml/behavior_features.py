"""What one source did in one 5-minute window, as numbers a model can learn from.

The rules judge the same unit (a source's activity in a 5-minute clock
window), so a model finding and a rule alert can be compared directly. Every
feature comes from raw firewall fields; no rule output is used, so the model
cannot simply learn to copy the rules.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd

from atdr.app.detection.rules import (
    AUTH_SERVICE_PORTS,
    BACKGROUND_MAX_CONNECTIONS,
    BACKGROUND_MAX_HOSTS,
    BACKGROUND_MAX_PORTS,
    COMMON_PORTS,
    INSIDE_ZONE_TOKENS,
    OUTSIDE_ZONE_TOKENS,
    P2P_SUBCATEGORY,
    P2P_TECHNOLOGY,
)

WINDOW = "5min"
LOG_COLUMNS = [
    "log_id", "generated_time", "src_ip", "dst_ip", "dst_port", "src_zone", "dst_zone", "action", "app",
    "app_risk", "bytes_sent", "bytes_received", "packets", "elapsed_time", "session_end_reason", "log_type",
    "app_technology", "app_subcategory",
]
UNKNOWN_APPS = ("unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "insufficient-data", "not-applicable")
DENY_PREFIXES = ("deny", "drop", "reset", "block")
MIN_BEACON_CONNECTIONS = 4
# Policy columns returned next to FEATURES; the classifier never sees them.
POLICY_COLUMNS = ["p2p_share"]
# A window that is mostly peer-to-peer file sharing is policy activity, not an attack.
P2P_POLICY_SHARE = 0.5
# Background probing: an internet host sending a few unanswered connections to a few MFU addresses.
# The internet does this to every public network all day, so it is summarised, not alerted on one by
# one. The limits are the rules' (detection/rules.py), so both engines agree on what background is.
PROBE_MAX_HOSTS = BACKGROUND_MAX_HOSTS
PROBE_MAX_PORTS = BACKGROUND_MAX_PORTS
PROBE_MAX_CONNECTIONS = BACKGROUND_MAX_CONNECTIONS
FEATURES = [
    "n_logs", "n_dst_ips", "n_dst_ports", "max_ports_per_dst", "max_dsts_per_port", "top_dst_share",
    "top_service_logs", "deny_share", "zero_reply_share", "mean_packets", "max_packets", "bytes_sent_total",
    "bytes_sent_max", "bytes_received_total", "upload_ratio", "mean_elapsed", "short_session_share",
    "unknown_app_share", "max_app_risk", "high_risk_share", "outbound_share", "inbound_share", "src_is_private",
    "auth_port_share", "uncommon_port_share", "threat_logs", "n_apps", "beacon_count", "beacon_interval",
    "beacon_cv", "beacon_dst_sources",
]


def _zone_side(zones: pd.Series, tokens: set[str]) -> pd.Series:
    lowered = zones.fillna("").str.lower().str.split(r"[^a-z0-9]+", regex=True)
    return lowered.map(lambda parts: bool(set(parts) & tokens))


def _is_private(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def is_background_probe(features: pd.DataFrame) -> pd.Series:
    return (
        (features["src_is_private"] == 0)
        & (features["inbound_share"] >= 0.5)
        & (features["zero_reply_share"] >= 0.8)
        & (features["n_dst_ips"] <= PROBE_MAX_HOSTS)
        & (features["n_dst_ports"] <= PROBE_MAX_PORTS)
        & (features["n_logs"] <= PROBE_MAX_CONNECTIONS)
    )


def is_p2p_policy(features: pd.DataFrame) -> pd.Series:
    """Mostly peer-to-peer file sharing, with no firewall threat detection among its connections."""

    if "p2p_share" not in features:
        return pd.Series(False, index=features.index)
    return (features["p2p_share"].fillna(0) >= P2P_POLICY_SHARE) & (features["threat_logs"].fillna(0) == 0)


def load_logs(database: Path, *, start: str | None = None, end: str | None = None) -> pd.DataFrame:
    """Read the columns the features need from an ATDR SQLite database (read-only)."""

    where, params = [], []
    if start:
        where.append("generated_time >= ?")
        params.append(start)
    if end:
        where.append("generated_time < ?")
        params.append(end)
    columns = ", ".join(f"id AS log_id" if name == "log_id" else name for name in LOG_COLUMNS)
    query = f"SELECT {columns} FROM normalized_logs" + (f" WHERE {' AND '.join(where)}" if where else "")
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        frame = pd.read_sql_query(query, connection, params=params)
    frame["generated_time"] = pd.to_datetime(frame["generated_time"])
    return frame


def destination_pairs(logs: pd.DataFrame) -> pd.DataFrame:
    """Who talked to each destination in each window: distinct (window, dst_ip, src_ip) rows."""

    frame = logs.dropna(subset=["src_ip", "dst_ip", "generated_time"])
    pairs = pd.DataFrame({"window": frame["generated_time"].dt.floor(WINDOW), "dst_ip": frame["dst_ip"], "src_ip": frame["src_ip"]})
    return pairs.drop_duplicates()


def window_features(logs: pd.DataFrame, *, context_pairs: pd.DataFrame | None = None) -> tuple[pd.DataFrame, pd.Series]:
    """Features per (src_ip, window), and the log ids behind each row.

    ``logs`` has LOG_COLUMNS; rows without a source IP or time are ignored.
    ``beacon_dst_sources`` counts every source that contacted a destination in the
    window, so when ``logs`` holds only some sources (one alert's source, or a
    simulated attack blended into one host), pass the whole window's
    ``destination_pairs`` as ``context_pairs``.
    """

    frame = logs.dropna(subset=["src_ip", "generated_time"]).copy()
    frame["window"] = frame["generated_time"].dt.floor(WINDOW)
    frame["action_l"] = frame["action"].fillna("").str.lower()
    frame["denied"] = frame["action_l"].str.startswith(DENY_PREFIXES)
    frame["zero_reply"] = frame["bytes_received"].fillna(0) <= 0
    frame["short"] = frame["elapsed_time"].fillna(0) <= 1
    frame["unknown_app"] = frame["app"].fillna("").str.lower().isin(UNKNOWN_APPS)
    frame["high_risk"] = frame["app_risk"].fillna(0) >= 4
    frame["outbound"] = _zone_side(frame["src_zone"], INSIDE_ZONE_TOKENS) & _zone_side(frame["dst_zone"], OUTSIDE_ZONE_TOKENS)
    frame["inbound"] = _zone_side(frame["src_zone"], OUTSIDE_ZONE_TOKENS) & _zone_side(frame["dst_zone"], INSIDE_ZONE_TOKENS)
    ports = frame["dst_port"]
    frame["auth_port"] = ports.isin(AUTH_SERVICE_PORTS)
    frame["uncommon_port"] = ports.notna() & ~ports.isin(COMMON_PORTS)
    frame["threat"] = frame["log_type"].fillna("").str.upper().eq("THREAT")
    frame["p2p"] = (
        frame.get("app_technology", pd.Series(index=frame.index, dtype=object)).fillna("").str.lower().eq(P2P_TECHNOLOGY)
        & frame.get("app_subcategory", pd.Series(index=frame.index, dtype=object)).fillna("").str.lower().eq(P2P_SUBCATEGORY)
    )
    frame["service"] = frame["dst_ip"].fillna("") + ":" + ports.fillna(-1).astype(int).astype(str)
    key = ["src_ip", "window"]
    grouped = frame.groupby(key, sort=False)

    features = grouped.agg(
        n_logs=("log_id", "size"),
        n_dst_ips=("dst_ip", "nunique"),
        n_dst_ports=("dst_port", "nunique"),
        deny_share=("denied", "mean"),
        zero_reply_share=("zero_reply", "mean"),
        mean_packets=("packets", "mean"),
        max_packets=("packets", "max"),
        bytes_sent_total=("bytes_sent", "sum"),
        bytes_sent_max=("bytes_sent", "max"),
        bytes_received_total=("bytes_received", "sum"),
        mean_elapsed=("elapsed_time", "mean"),
        short_session_share=("short", "mean"),
        unknown_app_share=("unknown_app", "mean"),
        max_app_risk=("app_risk", "max"),
        high_risk_share=("high_risk", "mean"),
        outbound_share=("outbound", "mean"),
        inbound_share=("inbound", "mean"),
        auth_port_share=("auth_port", "mean"),
        uncommon_port_share=("uncommon_port", "mean"),
        threat_logs=("threat", "sum"),
        n_apps=("app", "nunique"),
        p2p_share=("p2p", "mean"),
    )
    features["max_ports_per_dst"] = frame.groupby([*key, "dst_ip"])["dst_port"].nunique().groupby(level=[0, 1]).max()
    features["max_dsts_per_port"] = frame.groupby([*key, "dst_port"])["dst_ip"].nunique().groupby(level=[0, 1]).max()
    per_dst = frame.groupby([*key, "dst_ip"]).size()
    features["top_dst_share"] = per_dst.groupby(level=[0, 1]).max() / features["n_logs"]
    features["top_service_logs"] = frame.groupby([*key, "service"]).size().groupby(level=[0, 1]).max()
    features["upload_ratio"] = features["bytes_sent_total"] / (features["bytes_received_total"].fillna(0) + 1)
    features["src_is_private"] = [float(_is_private(ip)) for ip in features.index.get_level_values(0)]

    # Beaconing: the most regular repeated connection to one destination. A beacon can hide among a
    # busy host's normal traffic, so this is the steadiest destination, not the busiest one.
    pairs = destination_pairs(frame)
    if context_pairs is not None:
        pairs = pd.concat([pairs, context_pairs[["window", "dst_ip", "src_ip"]]], ignore_index=True).drop_duplicates()
    prevalence = pairs.groupby(["window", "dst_ip"])["src_ip"].nunique()
    ordered = frame.sort_values([*key, "dst_ip", "generated_time"])
    ordered["gap"] = ordered.groupby([*key, "dst_ip"])["generated_time"].diff().dt.total_seconds()
    gaps = ordered.groupby([*key, "dst_ip"])["gap"].agg(["count", "mean", "std"])
    gaps["connections"] = gaps["count"] + 1
    gaps["cv"] = gaps["std"] / gaps["mean"].replace(0, np.nan)
    repeated = gaps[(gaps["connections"] >= MIN_BEACON_CONNECTIONS) & gaps["cv"].notna()]
    steadiest = repeated.sort_values("cv", ascending=False).groupby(level=[0, 1]).tail(1)
    # How many sources contacted that steady destination. Campus apps check in with servers that many
    # devices use (Google, LINE, CDNs); a C2 server usually hears from one or a few infected hosts.
    beacon_destination = pd.MultiIndex.from_arrays(
        [steadiest.index.get_level_values(1), steadiest.index.get_level_values(2)], names=["window", "dst_ip"]
    )
    steadiest = steadiest.droplevel(2)
    steadiest["dst_sources"] = prevalence.reindex(beacon_destination).to_numpy()
    features["beacon_count"] = steadiest["connections"]
    features["beacon_interval"] = steadiest["mean"]
    features["beacon_cv"] = steadiest["cv"]
    features["beacon_dst_sources"] = steadiest["dst_sources"]

    evidence = grouped["log_id"].agg(list)
    return features[[*FEATURES, *POLICY_COLUMNS]].astype(float), evidence
