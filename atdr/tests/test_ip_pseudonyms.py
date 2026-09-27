"""Review files hide MFU addresses but keep who-talked-to-whom intact."""

from __future__ import annotations

from atdr.app.core.ip_pseudonyms import MfuPseudonyms, leftover_mfu_addresses

MFU_PUBLIC = ["202.28.45.0/24", "2001:3c8:5505::/48"]


def test_the_same_address_always_gets_the_same_name_and_subnets_stay_grouped():
    names = MfuPseudonyms(MFU_PUBLIC)
    first = names.name("10.1.134.171")
    assert first == "mfu-lan-1.1.1" and names.name("10.1.134.171") == first
    assert names.name("10.1.134.9") == "mfu-lan-1.1.2", "same /24: same subnet, next host"
    assert names.name("10.1.7.9") == "mfu-lan-1.2.1", "same /16, other /24: same block, next subnet"
    assert names.name("172.26.59.11") == "mfu-lan-2.1.1", "another private block"
    assert names.name("202.28.45.66") == "mfu-pub-1.1.1"
    assert names.name("2001:3c8:5505:194::1") == "mfu-pub6-1.1.1"


def test_internet_addresses_and_non_addresses_pass_through():
    names = MfuPseudonyms(MFU_PUBLIC)
    assert names.name("142.250.66.131") == "142.250.66.131"
    assert names.name("202.28.99.1") == "202.28.99.1", "only MFU's own public ranges are MFU"
    assert names.name("not an ip") == "not an ip"
    assert names.text(1679) == 1679


def test_free_text_is_rewritten_without_touching_times_ports_or_versions():
    names = MfuPseudonyms(MFU_PUBLIC)
    text = "10.1.134.171:51234 -> 202.28.45.66:3416 (20), 142.250.66.131:443 at 13:50:03, catalog v5.34.0, host 10.1.134.171."
    assert names.text(text) == (
        "mfu-lan-1.1.1:51234 -> mfu-pub-1.1.1:3416 (20), 142.250.66.131:443 at 13:50:03, catalog v5.34.0, host mfu-lan-1.1.1."
    )
    assert names.text("build 10.1.2.3.4") == "build 10.1.2.3.4", "five dotted numbers are not an address"
    named = names.name("2001:3c8:5505::6")
    assert names.text("peer 2001:3c8:5505::6:443 (2)") == f"peer {named}:443 (2)"


def test_the_key_is_reused_so_every_file_in_a_round_agrees(tmp_path):
    key = tmp_path / "key.json"
    first = MfuPseudonyms(MFU_PUBLIC)
    first.name("10.1.134.171")
    first.name("10.1.7.9")
    first.save(key)

    again = MfuPseudonyms.load(key, MFU_PUBLIC)
    assert again.name("10.1.7.9") == "mfu-lan-1.2.1"
    assert again.name("10.1.7.10") == "mfu-lan-1.2.2", "numbering continues from the saved key"
    assert again.name("10.9.0.1") == "mfu-lan-2.1.1"


def test_nothing_from_mfu_is_left_after_rewriting():
    names = MfuPseudonyms(MFU_PUBLIC)
    text = "src 10.1.134.171 dst 202.28.45.66 via 2001:3c8:5505:194::1, internet 8.8.8.8"
    assert leftover_mfu_addresses(text, names) == ["10.1.134.171", "202.28.45.66", "2001:3c8:5505:194::1"]
    assert leftover_mfu_addresses(names.text(text), names) == []
