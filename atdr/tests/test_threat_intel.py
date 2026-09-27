"""Threat intelligence feeds: parsed offline, replace their own list, never touch manual items or MFU hosts."""

from __future__ import annotations

import random
import time
from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import select

from atdr.app.db.models import Alert, AuditLog, NormalizedLog, RawLog, WatchlistItem
from atdr.app.services.detection_service import run_detection
from atdr.app.services.threat_intel_service import import_feed, parse_feed, stored_log_matches
from atdr.app.services.watchlist_service import (
    WatchlistIndex,
    _normalized_value,
    create_watchlist_item,
    list_watchlist_items,
    watchlist_feed_summary,
)
from atdr.tests.test_assistant import _client_with_session, _login
from atdr.tests.test_detection_grouping import _session

FEODO = '''################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
################################################################
#
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2026-01-01 00:00:00","10.1.2.3","443","online","2026-03-12","QakBot"
# end
'''
THREATFOX = '''################################################################
# ThreatFox IOCs: recent ip-port - CSV format                  #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-09-27 13:46:34", "1", "38.190.196.25:5638", "ip:port", "botnet_cc", "win.cobalt_strike", "", "Cobalt Strike", "", "75", "False", "None", "", "0", "abuse_ch"
"2026-09-27 12:00:00", "2", "38.190.196.25:443", "ip:port", "botnet_cc", "win.cobalt_strike", "", "Cobalt Strike", "", "100", "False", "None", "", "0", "abuse_ch"
"2026-09-27 11:00:00", "3", "45.9.148.10:80", "ip:port", "payload_delivery", "elf.mirai", "", "Mirai", "", "50", "False", "None", "", "0", "abuse_ch"
"2026-09-27 10:00:00", "4", "evil.example:443", "domain", "botnet_cc", "x", "", "X", "", "100", "False", "None", "", "0", "abuse_ch"
'''
PLAIN = """# my list
203.0.113.9   # documentation range, not global
8.8.4.4
not-an-ip
192.168.1.1
91.92.93.94  # C2
"""


def test_feodo_threatfox_and_plain_lists_are_recognised_and_mfu_addresses_skipped():
    feodo = parse_feed(FEODO)
    assert feodo.format == "feodo" and [i.ip for i in feodo.indicators] == ["50.16.16.211", "162.243.103.246"]
    assert feodo.skipped_private == 1 and feodo.indicators[0].severity_boost == 60 and feodo.indicators[1].severity_boost == 40
    assert "QakBot C2 server, port 443, online" in feodo.indicators[0].description

    threatfox = parse_feed(THREATFOX)
    by_ip = {indicator.ip: indicator for indicator in threatfox.indicators}
    assert threatfox.format == "threatfox" and sorted(by_ip) == ["38.190.196.25", "45.9.148.10"], "domains are left out"
    assert "port(s) 443, 5638" in by_ip["38.190.196.25"].description and by_ip["38.190.196.25"].severity_boost == 60
    assert by_ip["45.9.148.10"].severity_boost == 40, "confidence below 75 gets the lower boost"

    plain = parse_feed(PLAIN)
    assert plain.format == "plain" and [i.ip for i in plain.indicators] == ["8.8.4.4", "91.92.93.94"]
    assert plain.skipped_invalid == 1 and plain.skipped_private == 2


def test_an_import_replaces_its_own_feed_and_leaves_manual_items_alone():
    db = _session()
    manual = create_watchlist_item(db, indicator_type="dst_ip", indicator_value="50.16.16.211", description="analyst",
                                   severity_boost=30, actor="koe")
    dry = import_feed(db, source="Feodo", feed=parse_feed(FEODO), actor="koe")
    assert dry["added"] == 2 and not dry["applied"] and len(list_watchlist_items(db)) == 1

    import_feed(db, source="Feodo", feed=parse_feed(FEODO), actor="koe", apply=True)
    newer = FEODO.replace('"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"\n', "")
    second = import_feed(db, source="Feodo", feed=parse_feed(newer), actor="koe", apply=True)
    assert second["disabled"] == 1 and second["unchanged"] == 1
    items = {item.indicator_value: item for item in db.scalars(select(WatchlistItem).where(WatchlistItem.source == "Feodo"))}
    assert not items["162.243.103.246"].active and items["50.16.16.211"].active
    assert db.get(WatchlistItem, manual.id).active and db.get(WatchlistItem, manual.id).source is None

    back = import_feed(db, source="Feodo", feed=parse_feed(FEODO), actor="koe", apply=True)
    assert back["reactivated"] == 1 and items["162.243.103.246"].active
    assert [item.id for item in list_watchlist_items(db, manual_only=True)] == [manual.id]
    assert watchlist_feed_summary(db)[0] | {"last_added_at": None} == {
        "source": "Feodo", "indicators": 2, "active": 2, "last_added_at": None, "matches": 0, "last_matched_at": None}
    audits = list(db.scalars(select(AuditLog).where(AuditLog.action == "watchlist_feed_imported")))
    assert len(audits) == 3 and audits[1].details["disabled"] == 1


def test_the_index_matches_exactly_like_comparing_every_item_and_stays_fast():
    rng = random.Random(3)
    items = [SimpleNamespace(indicator_type=rng.choice(WatchlistIndex.FIELDS), indicator_value=f"{rng.randint(1, 60)}.1.1.1")
             for _ in range(5000)]
    logs = [SimpleNamespace(src_ip=f"{rng.randint(1, 80)}.1.1.1", dst_ip=f"{rng.randint(1, 80)}.1.1.1", app="1.1.1.1",
                            src_country=None, dst_country="") for _ in range(2000)]
    index = WatchlistIndex(items)
    started = time.perf_counter()
    fast = [sorted(map(id, index.matches(log))) for log in logs]
    elapsed = time.perf_counter() - started
    slow = [sorted(id(item) for item in items if _normalized_value(item.indicator_type, item.indicator_value)
                   == _normalized_value(item.indicator_type, getattr(log, item.indicator_type))) for log in logs]
    assert fast == slow
    assert elapsed < 0.5, f"2,000 logs against 5,000 items took {elapsed:.2f}s"


def test_a_host_calling_a_feed_address_raises_a_watchlist_alert():
    db = _session()
    import_feed(db, source="Feodo", feed=parse_feed(FEODO), actor="koe", apply=True)
    raw = RawLog(raw_line="beacon")
    db.add(raw)
    db.flush()
    db.add(NormalizedLog(raw_log_id=raw.id, generated_time=datetime(2026, 5, 20, 13, 40), log_type="TRAFFIC",
                         src_ip="10.1.200.251", dst_ip="50.16.16.211", src_zone="WLAN-Inside", dst_zone="SG-Outside",
                         app="web-browsing", dst_port=443, action="allow", protocol="tcp", bytes=500, packets=4, parsed_json={}))
    db.commit()
    assert stored_log_matches(db, ["50.16.16.211", "1.2.3.4"]) == {"logs": 1, "sources": 1, "indicators_seen": 1}
    run_detection(db, limit=100, use_ml=False, actor="test")
    alert = db.scalar(select(Alert))
    assert alert is not None and alert.alert_type == "watchlist_match" and alert.threat_score >= 60
    assert db.scalar(select(WatchlistItem).where(WatchlistItem.indicator_value == "50.16.16.211")).match_count == 1


def test_the_api_lists_feeds_apart_from_manual_items():
    client, sessions = _client_with_session()
    try:
        with sessions() as db:
            create_watchlist_item(db, indicator_type="src_ip", indicator_value="45.33.32.156", description="scanner",
                                  severity_boost=30, actor="admin")
            import_feed(db, source="ThreatFox recent", feed=parse_feed(THREATFOX), actor="admin", apply=True)
        anonymous = client.get("/api/watchlists/feeds")
        headers = _login(client)
        feeds = client.get("/api/watchlists/feeds", headers=headers)
        manual = client.get("/api/watchlists", params={"manual_only": True}, headers=headers)
        everything = client.get("/api/watchlists", headers=headers)
    finally:
        client.app.dependency_overrides.clear()
    assert anonymous.status_code == 401
    assert feeds.status_code == 200 and feeds.json()[0]["source"] == "ThreatFox recent" and feeds.json()[0]["active"] == 2
    assert [item["indicator_value"] for item in manual.json()] == ["45.33.32.156"]
    assert len(everything.json()) == 3 and {item["source"] for item in everything.json()} == {None, "ThreatFox recent"}
