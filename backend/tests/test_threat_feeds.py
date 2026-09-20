"""MR1 — script tải danh sách threat-intel: kiểm tra định dạng, ghi nguyên tử, giữ file cũ khi lỗi."""

import pytest

from scripts import update_threat_feeds as feeds

_IP_FEED = feeds.Feed("ips.txt", "test", "https://example.test/ips", "ip")
_CIDR_FEED = feeds.Feed("cidrs.txt", "test", "https://example.test/cidrs", "cidr")


def test_parse_ip_lines_skips_comments_blanks_and_reports_invalid():
    text = "1.2.3.4\n\n# ghi chú\n  5.6.7.8  \nkhong-phai-ip\n2001:db8::1\n"
    valid, invalid = feeds.parse_feed_text(text, "ip")
    assert valid == ["1.2.3.4", "5.6.7.8", "2001:db8::1"]
    assert invalid == 1


def test_parse_cidr_lines_normalises_host_bits():
    valid, invalid = feeds.parse_feed_text("10.0.0.0/8\n192.168.1.5/24\n999.1.1.1/8\n", "cidr")
    assert valid == ["10.0.0.0/8", "192.168.1.0/24"]
    assert invalid == 1


def test_update_feed_writes_file_and_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "_download", lambda url: "1.1.1.1\n2.2.2.2\n")
    info = feeds.update_feed(_IP_FEED, feed_dir=str(tmp_path))
    assert info["entries"] == 2 and info["invalid_lines"] == 0
    assert (tmp_path / "ips.txt").read_text(encoding="utf-8") == "1.1.1.1\n2.2.2.2\n"
    assert not (tmp_path / "ips.txt.tmp").exists()


def test_empty_download_keeps_previous_file(tmp_path, monkeypatch):
    (tmp_path / "cidrs.txt").write_text("10.0.0.0/8\n", encoding="utf-8")
    monkeypatch.setattr(feeds, "_download", lambda url: "# chỉ có chú thích\n\n")
    with pytest.raises(ValueError):
        feeds.update_feed(_CIDR_FEED, feed_dir=str(tmp_path))
    assert (tmp_path / "cidrs.txt").read_text(encoding="utf-8") == "10.0.0.0/8\n"


def test_download_rejects_non_https():
    with pytest.raises(ValueError):
        feeds._download("http://example.test/list.txt")
