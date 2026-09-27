"""MR9 — nguồn danh tiếng: tập CIDR, danh sách Tor/datacenter/VPN nạp từ file, blocklist có hạn dùng."""

import json

import pytest

from app.detection.engine import Blocklist, CidrSet, LoginAttempt, ThreatIntel
from app.detection.engine.intel import DEFAULT_DIR, DATACENTER_FILE, TOR_FILE, VPN_FILE


def attempt(ip="1.2.3.4", asn=None, username="alice", ts=1000.0):
    return LoginAttempt(ts=ts, username=username, success=False, ip=ip, asn=asn)


# ------------------------------------------------------------------------------------------------ CidrSet


def test_cidr_set_matches_addresses_inside_and_only_inside_the_networks():
    cidrs = CidrSet(["10.0.0.0/8", "192.168.1.0/24", "203.0.113.5/32"])
    for inside in ("10.0.0.0", "10.255.255.255", "192.168.1.77", "203.0.113.5"):
        assert inside in cidrs, inside
    for outside in ("9.255.255.255", "11.0.0.0", "192.168.2.1", "203.0.113.4", "203.0.113.6"):
        assert outside not in cidrs, outside


def test_cidr_set_merges_overlapping_and_adjacent_networks():
    cidrs = CidrSet(["10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/24", "10.0.1.0/24"])
    assert len(cidrs) == 1  # /25 + /25 = /24, /24 kề /24 → một khoảng duy nhất 10.0.0.0–10.0.1.255
    assert "10.0.1.200" in cidrs and "10.0.2.0" not in cidrs


def test_cidr_set_ignores_ipv6_and_junk_input_without_raising():
    cidrs = CidrSet(["10.0.0.0/8", "2001:db8::/32"])
    assert "2001:db8::1" not in cidrs and "khong-phai-ip" not in cidrs and "" not in cidrs
    assert len(CidrSet()) == 0 and "1.1.1.1" not in CidrSet()
    assert CidrSet(["192.168.1.5/24"]).__contains__("192.168.1.200")  # bit máy chủ được chuẩn hoá như update_threat_feeds


# ------------------------------------------------------------------------------------------------ ThreatIntel


def write_feeds(folder, tor="1.1.1.1\n2.2.2.2\n", datacenter="10.0.0.0/8\n", vpn="172.16.0.0/12\n"):
    (folder / TOR_FILE).write_text(tor, encoding="utf-8")
    (folder / DATACENTER_FILE).write_text(datacenter, encoding="utf-8")
    (folder / VPN_FILE).write_text(vpn, encoding="utf-8")


def test_threat_intel_loads_the_three_lists_and_classifies_addresses(tmp_path):
    write_feeds(tmp_path, tor="# chú thích\n1.1.1.1\n\n2001:db8::1\n")
    (tmp_path / "sources.json").write_text(json.dumps([{"fetched_at": "2026-09-20T14:19:30+00:00"}, {"fetched_at": "2026-09-21T01:00:00+00:00"}]), encoding="utf-8")
    intel = ThreatIntel.load(tmp_path)
    assert intel.loaded == {"tor": True, "datacenter": True, "vpn": True}
    assert intel.is_tor("1.1.1.1") and intel.is_tor("2001:db8::1") and not intel.is_tor("3.3.3.3")
    assert intel.in_datacenter("10.4.5.6") and not intel.in_datacenter("11.0.0.1")
    assert intel.in_vpn("172.20.0.1") and not intel.in_vpn("172.32.0.1")
    assert intel.fetched_at.isoformat() == "2026-09-20T14:19:30+00:00"  # bản CŨ NHẤT: tuổi của danh sách là tuổi của nguồn cũ nhất
    assert intel.status()["entries"] == {"tor": 2, "datacenter": 1, "vpn": 1}


def test_missing_lists_stay_empty_and_are_reported_as_not_loaded(tmp_path):
    (tmp_path / TOR_FILE).write_text("1.1.1.1\n", encoding="utf-8")
    intel = ThreatIntel.load(tmp_path)
    assert intel.loaded == {"tor": True, "datacenter": False, "vpn": False}
    assert intel.is_tor("1.1.1.1") and not intel.in_datacenter("10.0.0.1") and not intel.in_vpn("172.16.0.1")
    empty = ThreatIntel.load(tmp_path / "khong-ton-tai")
    assert empty.loaded == {"tor": False, "datacenter": False, "vpn": False} and empty.fetched_at is None


def test_broken_sources_file_does_not_stop_loading(tmp_path):
    write_feeds(tmp_path)
    (tmp_path / "sources.json").write_text("{không phải json", encoding="utf-8")
    assert ThreatIntel.load(tmp_path).fetched_at is None
    (tmp_path / "sources.json").write_text(json.dumps([{"fetched_at": "hôm qua"}]), encoding="utf-8")
    assert ThreatIntel.load(tmp_path).fetched_at is None


@pytest.mark.skipif(not (DEFAULT_DIR / TOR_FILE).is_file() or not (DEFAULT_DIR / DATACENTER_FILE).is_file(), reason="chưa tải danh sách công khai (python -m scripts.update_threat_feeds)")
def test_real_downloaded_lists_are_usable_and_fast_to_query():
    intel = ThreatIntel.load()
    assert all(intel.loaded.values()) and len(intel.tor) > 500 and len(intel.datacenter) > 1000
    first_tor = next(iter(intel.tor))
    assert intel.is_tor(first_tor) and not intel.is_tor("192.0.2.1")
    first_network = (DEFAULT_DIR / DATACENTER_FILE).read_text(encoding="utf-8").splitlines()[0].split("/")[0]
    assert intel.in_datacenter(first_network)


# ------------------------------------------------------------------------------------------------ Blocklist


def test_blocklist_matches_ip_cidr_asn_and_username():
    block = Blocklist()
    block.add("ip", "1.2.3.4", "IP đã dò mật khẩu")
    block.add("cidr", "10.9.0.0/16", "dải proxy")
    block.add("asn", "AS64512", "nhà mạng chỉ chứa botnet")
    block.add("username", "  ADMIN  ", "tài khoản bị nhắm")
    assert block.match(attempt(ip="1.2.3.4")).reason == "IP đã dò mật khẩu"
    assert block.match(attempt(ip="10.9.200.1")).kind == "cidr"
    assert block.match(attempt(ip="8.8.8.8", asn=64512)).kind == "asn"
    assert block.match(attempt(ip="8.8.8.8", username="Admin")).kind == "username"  # không phân biệt hoa thường
    assert block.match(attempt(ip="8.8.8.8", asn=64513)) is None
    assert block.match(attempt(ip="khong-phai-ip")) is None  # IP hỏng không làm sập, chỉ có thể khớp theo ASN/tên


def test_blocklist_entries_expire_by_event_time_not_wall_clock():
    block = Blocklist()
    block.add("ip", "1.2.3.4", "tạm chặn 1 giờ", ttl=3600, now=1000.0)
    assert block.match(attempt(ts=1000.0 + 3599)) is not None
    assert block.match(attempt(ts=1000.0 + 3600)) is None  # đúng hạn thì hết hiệu lực
    assert len(block.entries(ts=1500.0)) == 1 and block.entries(ts=9999.0) == []
    with pytest.raises(ValueError):
        block.add("ip", "5.6.7.8", ttl=60)  # đặt hạn cần biết `now`


def test_blocklist_remove_and_input_validation():
    block = Blocklist()
    block.add("ip", "2001:0db8:0000:0000:0000:0000:0000:0001")
    assert block.match(attempt(ip="2001:db8::1")) is not None  # IPv6 được chuẩn hoá
    assert block.remove("ip", "2001:db8::1") is True and block.remove("ip", "2001:db8::1") is False
    for kind, value in (("ip", "999.1.1.1"), ("cidr", "khong-phai-cidr"), ("asn", "AS-abc"), ("email", "a@b.c")):
        with pytest.raises(ValueError):
            block.add(kind, value)


def test_blocklist_prefers_the_exact_ip_over_a_network():
    block = Blocklist()
    block.add("cidr", "1.2.3.0/24", "dải")
    block.add("ip", "1.2.3.4", "đúng IP")
    assert block.match(attempt(ip="1.2.3.4")).reason == "đúng IP"
    assert block.match(attempt(ip="1.2.3.9")).reason == "dải"
